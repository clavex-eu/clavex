// Package walletsigning resolves operator-authorised wallet signing keys.
package walletsigning

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TransitProfile is operator configuration, never accepted from tenant input.
// TokenEnv names an environment variable; tokens are never stored in tenant rows.
type TransitProfile struct {
	CAFile    string    `json:"ca_file,omitempty"`
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	OrgID     uuid.UUID `json:"org_id"`
	Address   string    `json:"address"`
	TokenEnv  string    `json:"token_env"`
	Namespace string    `json:"namespace,omitempty"`
	Mount     string    `json:"mount"`
	Key       string    `json:"key"`
	Version   int       `json:"version"`
}

type Registry struct {
	profiles map[string]TransitProfile
	err      error
}
type Choice struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Version int    `json:"version"`
}

var segment = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// LoadRegistry loads a bounded, operator-owned JSON array. Invalid configuration
// fails closed: no profile is available and resolution returns an error.
func LoadRegistry(path string) *Registry {
	r := &Registry{profiles: map[string]TransitProfile{}}
	if path == "" {
		return r
	}
	f, err := os.Open(path)
	if err != nil {
		r.err = errors.New("wallet Vault profile file unavailable")
		return r
	}
	defer f.Close()
	var profiles []TransitProfile
	dec := json.NewDecoder(io.LimitReader(f, 256*1024+1))
	dec.DisallowUnknownFields()
	if dec.Decode(&profiles) != nil {
		r.err = errors.New("invalid wallet Vault profile file")
		return r
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		r.err = errors.New("invalid trailing wallet Vault configuration")
		return r
	}
	for _, p := range profiles {
		u, e := url.Parse(p.Address)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !segment.MatchString(p.ID) || !segment.MatchString(p.Mount) || !segment.MatchString(p.Key) || !segment.MatchString(p.TokenEnv) || p.Version < 1 || p.OrgID == uuid.Nil || r.profiles[p.ID].ID != "" {
			r.err = errors.New("invalid wallet Vault profile")
			r.profiles = nil
			return r
		}
		r.profiles[p.ID] = p
	}
	return r
}

func (r *Registry) Choices(org uuid.UUID) []Choice {
	out := []Choice{}
	if r == nil || r.err != nil {
		return out
	}
	for _, p := range r.profiles {
		if p.OrgID == org {
			out = append(out, Choice{p.ID, p.Label, p.Version})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *Registry) Resolve(org uuid.UUID, id string, public crypto.PublicKey) (crypto.Signer, error) {
	if r == nil || r.err != nil {
		return nil, errors.New("wallet Vault configuration unavailable")
	}
	p, ok := r.profiles[id]
	if !ok || p.OrgID != org {
		return nil, errors.New("wallet Vault profile unavailable for this organisation")
	}
	token := os.Getenv(p.TokenEnv)
	if token == "" {
		return nil, errors.New("wallet Vault credentials unavailable")
	}
	pub, ok := public.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("wallet Vault signer requires P-256")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	if p.CAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		raw, err := os.ReadFile(p.CAFile)
		if err != nil || len(raw) > 256*1024 || !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("wallet Vault TLS CA unavailable")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	signer := &transitSigner{profile: p, token: token, public: pub, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	defer transport.CloseIdleConnections()
	if err := signer.validateKey(); err != nil {
		return nil, err
	}
	return signer, nil
}

type transitSigner struct {
	profile TransitProfile
	token   string
	public  *ecdsa.PublicKey
	client  *http.Client
}

func (s *transitSigner) Public() crypto.PublicKey { return s.public }
func (s *transitSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("wallet Transit requires a SHA-256 digest")
	}
	//nolint:misspell // Vault API parameter uses the American spelling.
	body, _ := json.Marshal(map[string]any{"input": base64.StdEncoding.EncodeToString(digest), "prehashed": true, "hash_algorithm": "sha2-256", "marshaling_algorithm": "asn1", "key_version": s.profile.Version})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint := strings.TrimRight(s.profile.Address, "/") + "/v1/" + s.profile.Mount + "/sign/" + s.profile.Key
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid wallet Vault endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", s.token)
	if s.profile.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.profile.Namespace)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.New("wallet Vault signing unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("wallet Vault signing failed")
	}
	var result struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&result) != nil {
		return nil, errors.New("invalid wallet Vault response")
	}
	prefix := fmt.Sprintf("vault:v%s:", strconv.Itoa(s.profile.Version))
	if !strings.HasPrefix(result.Data.Signature, prefix) {
		return nil, errors.New("wallet Vault key version mismatch")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(result.Data.Signature, prefix))
	if err != nil || !ecdsa.VerifyASN1(s.public, digest, sig) {
		return nil, errors.New("wallet Vault signature does not match certificate")
	}
	return sig, nil
}

// validateKey confirms the pinned public key and version, and refuses exportable
// or derived keys. No private material is read or exported from Vault.
func (s *transitSigner) validateKey() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint := strings.TrimRight(s.profile.Address, "/") + "/v1/" + s.profile.Mount + "/keys/" + s.profile.Key
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("invalid wallet Vault endpoint")
	}
	req.Header.Set("X-Vault-Token", s.token)
	if s.profile.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.profile.Namespace)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.New("wallet Vault key unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("wallet Vault key read failed")
	}
	var result struct {
		Data struct {
			Type            string `json:"type"`
			Exportable      *bool  `json:"exportable"`
			PlaintextBackup *bool  `json:"allow_plaintext_backup"`
			Derived         *bool  `json:"derived"`
			Keys            map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&result) != nil {
		return errors.New("invalid wallet Vault key response")
	}
	d := result.Data
	if d.Type != "ecdsa-p256" || d.Exportable == nil || *d.Exportable || d.PlaintextBackup == nil || *d.PlaintextBackup || d.Derived == nil || *d.Derived {
		return errors.New("wallet Vault requires a non-exportable, non-derived P-256 signing key")
	}
	block, _ := pem.Decode([]byte(d.Keys[strconv.Itoa(s.profile.Version)].PublicKey))
	if block == nil {
		return errors.New("wallet Vault key version unavailable")
	}
	raw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("invalid wallet Vault public key")
	}
	pub, ok := raw.(*ecdsa.PublicKey)
	if !ok || !s.public.Equal(pub) {
		return errors.New("wallet Vault public key does not match certificate")
	}
	return nil
}

// Err reports only a sanitised configuration error for administration status.
func (r *Registry) Err() error {
	if r == nil {
		return nil
	}
	return r.err
}
