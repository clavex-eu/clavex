// Package oidc implements the OpenID Connect / OAuth2 protocol logic.
// It is intentionally decoupled from HTTP: handlers in internal/handler/oidc.go
// call into this package.
package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// prevKey holds a retired RSA public key kept in the JWKS after rotation so
// that tokens signed with the old key can still be verified.
type prevKey struct {
	pub *rsa.PublicKey
	kid string
}

// rsaKeyEntry is used internally to build multi-key JWKS JSON.
type rsaKeyEntry struct {
	pub *rsa.PublicKey
	kid string
}

// KeySet holds the RSA signing key and the derived public JWK.
// It is safe for concurrent use after initialisation.
type KeySet struct {
	mu           sync.RWMutex
	privateKey   *rsa.PrivateKey
	kid          string     // stable key ID = hex(SHA-256(DER(public key)))[:16]
	jwks         []byte     // pre-serialised JWKS JSON (current + previous keys)
	previousKeys []prevKey  // retired keys kept in JWKS for verification overlap
}

// LoadKeySet reads the RSA private key PEM file at path and returns a KeySet.
// Returns an error if the file cannot be read or does not contain a valid
// RSA private key.
func LoadKeySet(path string) (*KeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing key: no PEM block found in %s", path)
	}

	var priv *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY": // PKCS#1
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY": // PKCS#8
		key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, fmt.Errorf("parse PKCS8 key: %w", e)
		}
		var ok bool
		priv, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key must be RSA, got %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse RSA key: %w", err)
	}
	if bits := priv.N.BitLen(); bits < 2048 {
		return nil, fmt.Errorf("RSA key too short (%d bits); minimum 2048", bits)
	}

	kid := computeKID(&priv.PublicKey)

	jwksJSON, err := buildJWKS(&priv.PublicKey, kid)
	if err != nil {
		return nil, fmt.Errorf("build JWKS: %w", err)
	}

	return &KeySet{
		privateKey: priv,
		kid:        kid,
		jwks:       jwksJSON,
	}, nil
}

// Rotate generates a new RSA-2048 signing key, archives the current key so it
// remains in the JWKS for token verification, and starts using the new key for
// signing.  At most two previous keys are retained.  The operation is atomic
// and safe for concurrent callers.
func (ks *KeySet) Rotate() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rotate signing key: %w", err)
	}
	newKID := computeKID(&priv.PublicKey)

	// Pre-build JWKS before taking the write lock to minimise lock duration.
	ks.mu.RLock()
	prev := append([]prevKey(nil), ks.previousKeys...)
	prev = append(prev, prevKey{pub: &ks.privateKey.PublicKey, kid: ks.kid})
	ks.mu.RUnlock()

	if len(prev) > 2 {
		prev = prev[len(prev)-2:]
	}

	entries := []rsaKeyEntry{{pub: &priv.PublicKey, kid: newKID}}
	for _, p := range prev {
		entries = append(entries, rsaKeyEntry(p))
	}
	newJWKS := marshalJWKS(entries)

	ks.mu.Lock()
	ks.privateKey = priv
	ks.kid = newKID
	ks.previousKeys = prev
	ks.jwks = newJWKS
	ks.mu.Unlock()
	return nil
}

// PrivateKey returns the RSA private key for signing tokens.
func (ks *KeySet) PrivateKey() *rsa.PrivateKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.privateKey
}

// KID returns the key identifier included in JWT headers.
func (ks *KeySet) KID() string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.kid
}

// JWKS returns the pre-serialised JSON Web Key Set (public key only).
func (ks *KeySet) JWKS() []byte {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.jwks
}

// PublicKey returns the RSA public key for token verification.
func (ks *KeySet) PublicKey() *rsa.PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return &ks.privateKey.PublicKey
}

// Algorithm returns the JWA signing algorithm (PS256 — RSASSA-PSS with SHA-256).
// PS256 uses the same RSA key as RS256 but with PSS padding, satisfying FAPI2
// which requires PS256, ES256, or EdDSA (FAPI2-SP-ID2-5.4-1).
func (ks *KeySet) Algorithm() jwa.SignatureAlgorithm {
	return jwa.PS256
}

// CryptoSigner returns the active private key as a crypto.Signer.
// *rsa.PrivateKey already implements crypto.Signer, so this is a zero-cost wrapper.
func (ks *KeySet) CryptoSigner() crypto.Signer {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.privateKey
}

// computeKID derives a stable key ID from the public key DER encoding.
func computeKID(pub *rsa.PublicKey) string {
	der := x509.MarshalPKCS1PublicKey(pub)
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8]) // 8 bytes → 11 base64url chars
}

// buildJWKS serialises the RSA public key as a JWKS JSON document.
// The 'alg' field is intentionally omitted: the server may sign ID tokens with
// PS256 (default) or RS256/ES256 when a client registered with a specific
// id_token_signed_response_alg.  RFC 7517 makes 'alg' optional; if present it
// narrows the key to a single algorithm, causing ValidateIdTokenSignature to
// fail for any non-matching alg.  Omitting it lets the conformance suite (and
// any verifier) use the key with any compatible RSA algorithm.
func buildJWKS(pub *rsa.PublicKey, kid string) ([]byte, error) {
	// Use lestrrat for validation only.
	key, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, err
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, err
	}
	_ = set // validation done; use manual serialisation below

	return marshalJWKS([]rsaKeyEntry{{pub: pub, kid: kid}}), nil
}

// marshalJWKS produces a minimal, spec-compliant JWKS JSON body for one or
// more RSA public keys.  'alg' is deliberately excluded — see buildJWKS for
// the rationale.
func marshalJWKS(keys []rsaKeyEntry) []byte {
	enc := func(i *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(i.Bytes())
	}

	var sb strings.Builder
	sb.WriteString(`{"keys":[`)
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		e := big.NewInt(int64(k.pub.E))
		fmt.Fprintf(&sb, `{"kty":"RSA","use":"sig","kid":%q,"n":%q,"e":%q}`,
			k.kid, enc(k.pub.N), enc(e))
	}
	sb.WriteString(`]}`)
	return []byte(sb.String())
}
