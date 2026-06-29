package oidc

// VaultSigner implements the Signer interface by delegating all signing
// operations to HashiCorp Vault Transit.  The RSA private key never leaves
// Vault; the Clavex process only holds the public key.
//
// Vault Transit requirements:
//   - A Transit secret engine mounted at /transit (or a custom path)
//   - A key named by VaultConfig.TransitKey of type "rsa-2048" or "rsa-4096"
//   - Key capability: sign
//
// Configuration (set via env or config file):
//   CLAVEX_AUTH_VAULT_ADDRESS      e.g. https://vault.corp:8200
//   CLAVEX_AUTH_VAULT_TOKEN        Vault token (or VAULT_TOKEN env var)
//   CLAVEX_AUTH_VAULT_TRANSIT_KEY  Transit key name (default: clavex-signing)
//   CLAVEX_AUTH_VAULT_NAMESPACE    Vault Enterprise namespace (optional)
//   CLAVEX_AUTH_VAULT_TRANSIT_PATH Mount path (default: transit)

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

// VaultConfig holds the Vault Transit connection parameters.
type VaultConfig struct {
	Address      string // e.g. "https://vault.corp:8200"
	Token        string // Vault token; falls back to VAULT_TOKEN env var
	Namespace    string // Vault Enterprise namespace (optional)
	TransitKey   string // Transit key name (default: "clavex-signing")
	TransitMount string // Transit mount path (default: "transit")
}

func (c *VaultConfig) keyName() string {
	if c.TransitKey == "" {
		return "clavex-signing"
	}
	return c.TransitKey
}

func (c *VaultConfig) mountPath() string {
	if c.TransitMount == "" {
		return "transit"
	}
	return strings.Trim(c.TransitMount, "/")
}

// VaultSigner signs JWTs via HashiCorp Vault Transit.
type VaultSigner struct {
	cfg    VaultConfig
	client *http.Client

	mu        sync.RWMutex
	publicKey *rsa.PublicKey
	kid       string
	jwks      []byte
}

// NewVaultSigner creates a VaultSigner and loads the current public key from
// Vault so that JWKS can be served immediately.
func NewVaultSigner(ctx context.Context, cfg VaultConfig) (*VaultSigner, error) {
	s := &VaultSigner{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
	if err := s.loadPublicKey(ctx); err != nil {
		return nil, fmt.Errorf("vault signer: load public key: %w", err)
	}
	return s, nil
}

// ── Signer interface ──────────────────────────────────────────────────────────

// PrivateKey returns nil — the private key never leaves Vault.
// Callers that require an *rsa.PrivateKey (e.g. SAML, SSF event signing) are
// incompatible with the vault backend and will receive nil.  Use CryptoSigner()
// for all JWT signing paths.
func (s *VaultSigner) PrivateKey() *rsa.PrivateKey { return nil }

func (s *VaultSigner) PublicKey() *rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publicKey
}

func (s *VaultSigner) KID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kid
}

func (s *VaultSigner) JWKS() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwks
}

func (s *VaultSigner) Algorithm() jwa.SignatureAlgorithm { return jwa.PS256 }

// CryptoSigner returns a crypto.Signer whose Sign() method calls Vault Transit.
func (s *VaultSigner) CryptoSigner() crypto.Signer { return &vaultCryptoSigner{parent: s} }

// Rotate is a no-op for Vault — key rotation is performed in Vault directly.
// After rotating in Vault, restart (or call loadPublicKey) to pick up the new public key.
func (s *VaultSigner) Rotate() error {
	return s.loadPublicKey(context.Background())
}

// ── Vault API helpers ─────────────────────────────────────────────────────────

// loadPublicKey fetches the current public key from Vault Transit.
func (s *VaultSigner) loadPublicKey(ctx context.Context) error {
	url := fmt.Sprintf("%s/v1/%s/keys/%s",
		strings.TrimRight(s.cfg.Address, "/"), s.cfg.mountPath(), s.cfg.keyName())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	s.addVaultHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault keys API returned %d: %s", resp.StatusCode, body)
	}

	// Vault key response: data.keys.<version>.public_key (PEM)
	var result struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse vault keys response: %w", err)
	}

	// Use the highest version.
	var pemKey string
	for _, v := range result.Data.Keys {
		pemKey = v.PublicKey
	}
	if pemKey == "" {
		return fmt.Errorf("vault: no public key found in keys response")
	}

	pub, err := parseRSAPublicKeyPEM(pemKey)
	if err != nil {
		return fmt.Errorf("vault: parse public key: %w", err)
	}
	kid := computeKID(pub)
	jwksJSON, err := buildJWKS(pub, kid)
	if err != nil {
		return fmt.Errorf("vault: build JWKS: %w", err)
	}

	s.mu.Lock()
	s.publicKey = pub
	s.kid = kid
	s.jwks = jwksJSON
	s.mu.Unlock()
	return nil
}

// signDigest calls the Vault Transit sign endpoint with a pre-hashed digest
// and returns the raw RSA-PSS signature bytes.
func (s *VaultSigner) signDigest(ctx context.Context, digest []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/%s/sign/%s",
		strings.TrimRight(s.cfg.Address, "/"), s.cfg.mountPath(), s.cfg.keyName())

	payload, _ := json.Marshal(map[string]any{
		"input":              base64.StdEncoding.EncodeToString(digest),
		"hash_algorithm":     "none",   // digest is already hashed by the caller
		"prehashed":          true,
		"signature_algorithm": "pss",
		"marshalling_algorithm": "jws", // DER-encoded, not the "vault:v1:" prefix format
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	s.addVaultHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault sign returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse vault sign response: %w", err)
	}

	// Vault with marshalling_algorithm=jws returns raw base64url-encoded DER signature.
	sig, err := base64.RawURLEncoding.DecodeString(result.Data.Signature)
	if err != nil {
		// Fallback: try standard base64
		sig, err = base64.StdEncoding.DecodeString(result.Data.Signature)
		if err != nil {
			return nil, fmt.Errorf("decode vault signature: %w", err)
		}
	}
	return sig, nil
}

func (s *VaultSigner) addVaultHeaders(req *http.Request) {
	req.Header.Set("X-Vault-Token", s.cfg.Token)
	if s.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.cfg.Namespace)
	}
}

// ── vaultCryptoSigner ─────────────────────────────────────────────────────────

// vaultCryptoSigner wraps VaultSigner to implement crypto.Signer.
// The jwx library will call Sign() when producing a PS256 JWT.
type vaultCryptoSigner struct {
	parent *VaultSigner
}

func (v *vaultCryptoSigner) Public() crypto.PublicKey {
	return v.parent.PublicKey()
}

// Sign delegates to Vault Transit.  The `digest` is SHA-256(signingInput) as
// computed by the jwx library before calling this method.
func (v *vaultCryptoSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return v.parent.signDigest(context.Background(), digest)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseRSAPublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return pub, nil
}

// Ensure *VaultSigner satisfies Signer at compile time.
var _ Signer = (*VaultSigner)(nil)
