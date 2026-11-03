package oid4w

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Call only after authenticating the referenced token and its issuer. Explicit
// status delegation never substitutes for that authentication.
func CheckDelegatedStatus(ctx context.Context, scope string, settings map[string]interface{}, format, issuer, kind string, raw json.RawMessage, required bool) error {
	if len(raw) == 0 {
		if required {
			return ErrStatusInvalid
		}
		return nil
	}
	ref, err := ParseStatusClaim(raw)
	if err != nil {
		return ErrStatusInvalid
	}
	sources, err := StatusSources(settings)
	if err != nil {
		return ErrStatusUnavailable
	}
	for _, source := range sources {
		if source.Format != format || source.CredentialIssuer != issuer || source.CredentialType != kind {
			continue
		}
		for _, uri := range source.ListURIs {
			if uri == ref.StatusList.URI {
				return StatusResolverFor(ctx).Check(ctx, scope, source, ref)
			}
		}
	}
	return ErrStatusUnavailable
}

// A status signer is explicitly delegated by tenant policy for an already
// verified credential issuer/type and exact list URIs. It cannot establish
// credential issuer trust by itself; no jku/x5u/JWKS discovery occurs.
type StatusSource struct {
	RequireIssuerClaim bool            `json:"require_issuer_claim,omitempty"`
	RequireExpiration  bool            `json:"require_expiration,omitempty"`
	Format             string          `json:"format"`
	CredentialIssuer   string          `json:"credential_issuer"`
	CredentialType     string          `json:"credential_type"`
	StatusIssuer       string          `json:"status_issuer"`
	ListURIs           []string        `json:"list_uris"`
	JWKS               json.RawMessage `json:"jwks"`
	MaxAgeSeconds      int             `json:"max_age_seconds,omitempty"`
	CacheSeconds       *int            `json:"cache_seconds,omitempty"`
}

func StatusURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw {
		return nil, ErrUnknownStatus
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.RawQuery != "" {
		return nil, ErrUnknownStatus
	}
	return u, nil
}

func (s StatusSource) keys() ([]jwk.Key, error) {
	set, err := jwk.Parse(s.JWKS)
	if err != nil || set.Len() == 0 || set.Len() > 20 {
		return nil, fmt.Errorf("invalid status signer JWKS")
	}
	var keys []jwk.Key
	seen := map[string]bool{}
	for i := 0; i < set.Len(); i++ {
		key, _ := set.Key(i)
		private, err := jwk.IsPrivateKey(key)
		if err != nil || private || (key.KeyType() != jwa.RSA && key.KeyType() != jwa.EC) {
			return nil, fmt.Errorf("status signer keys must be public RSA/P-256 keys")
		}
		var raw crypto.PublicKey
		if err := key.Raw(&raw); err != nil {
			return nil, err
		}
		switch k := raw.(type) {
		case *rsa.PublicKey:
			if k.N.BitLen() < 2048 {
				return nil, fmt.Errorf("weak status RSA key")
			}
		case *ecdsa.PublicKey:
			if k.Curve != elliptic.P256() {
				return nil, fmt.Errorf("unsupported status EC curve")
			}
		default:
			return nil, fmt.Errorf("unsupported status signer")
		}
		if key.KeyID() != "" && seen[key.KeyID()] {
			return nil, fmt.Errorf("duplicate status signer kid")
		}
		seen[key.KeyID()] = true
		keys = append(keys, key)
	}
	return keys, nil
}

func (s StatusSource) Validate() error {
	switch s.Format {
	case "dc+sd-jwt", "mso_mdoc", "key-attestation+jwt", "wallet-attestation+jwt":
	default:
		return fmt.Errorf("unsupported status source format")
	}
	if s.CredentialIssuer == "" || len(s.CredentialIssuer) > 1024 || s.CredentialType == "" || len(s.CredentialType) > 512 || s.StatusIssuer == "" || len(s.StatusIssuer) > 1024 || len(s.ListURIs) == 0 || len(s.ListURIs) > 100 {
		return fmt.Errorf("invalid status source selector")
	}
	if s.MaxAgeSeconds < 0 || s.MaxAgeSeconds > 86400 || s.CacheSeconds != nil && (*s.CacheSeconds < 0 || *s.CacheSeconds > 300) {
		return fmt.Errorf("invalid status freshness policy")
	}
	seen := map[string]bool{}
	for _, uri := range s.ListURIs {
		if _, err := StatusURL(uri); err != nil || seen[uri] {
			return fmt.Errorf("invalid or duplicate allowed status URI")
		}
		seen[uri] = true
	}
	_, err := s.keys()
	return err
}

func StatusSources(settings map[string]interface{}) ([]StatusSource, error) {
	value, ok := settings["wallet_status_sources"]
	if !ok {
		return nil, nil
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 1024*1024 {
		return nil, fmt.Errorf("oversized status source policy")
	}
	var sources []StatusSource
	if err := json.Unmarshal(raw, &sources); err != nil || len(sources) > 100 {
		return nil, fmt.Errorf("invalid status sources")
	}
	seen := map[string]bool{}
	for _, source := range sources {
		if err := source.Validate(); err != nil {
			return nil, err
		}
		for _, uri := range source.ListURIs {
			selector, _ := json.Marshal([]string{source.Format, source.CredentialIssuer, source.CredentialType, uri})
			if seen[string(selector)] {
				return nil, fmt.Errorf("ambiguous status source delegation")
			}
			seen[string(selector)] = true
		}
	}
	return sources, nil
}
