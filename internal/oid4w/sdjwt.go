// Package oid4w implements OpenID for Verifiable Credential Issuance (OID4VCI)
// and OpenID for Verifiable Presentations (OID4VP) as specified by the OpenID Foundation.
//
// Credential format: SD-JWT-VC (draft-ietf-oauth-selective-disclosure-jwt + sd-jwt-vc extension)
// Specs:
//   - SD-JWT-VC: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc
//   - OID4VCI Final: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
//   - OID4VP:  https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
package oid4w

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const sdAlg = "sha-256"

// Disclosure represents a single selectively-disclosable claim.
// Format per spec: base64url( JSON( [ salt, claim_name, claim_value ] ) )
type Disclosure struct {
	Salt  string `json:"-"`
	Name  string `json:"-"`
	Value any    `json:"-"`
	// Raw is the base64url-encoded disclosure string included after "~" in the SD-JWT.
	Raw string `json:"-"`
	// Hash is base64url( SHA-256( Raw ) ) — placed in the _sd array of the issuer JWT.
	Hash string `json:"-"`
}

// NewDisclosure creates a new disclosure for a named claim with a random salt.
func NewDisclosure(name string, value any) (*Disclosure, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	saltB64 := base64.RawURLEncoding.EncodeToString(salt)

	arr := []any{saltB64, name, value}
	b, err := json.Marshal(arr)
	if err != nil {
		return nil, fmt.Errorf("marshal disclosure: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(b)

	h := sha256.Sum256([]byte(raw))
	hash := base64.RawURLEncoding.EncodeToString(h[:])

	return &Disclosure{
		Salt:  saltB64,
		Name:  name,
		Value: value,
		Raw:   raw,
		Hash:  hash,
	}, nil
}

// SDJWTParams holds the parameters for issuing an SD-JWT-VC.
type SDJWTParams struct {
	// Issuer is the "iss" claim — typically the org's OIDC issuer URL.
	Issuer string
	// Subject is the "sub" claim — user ID or DID.
	Subject string
	// VCT is the Verifiable Credential Type URI (e.g. "https://example.com/credentials/identity/v1").
	VCT string
	// DisclosableClaims become individual disclosures in the SD-JWT.
	// The holder can choose to reveal or conceal each claim.
	DisclosableClaims map[string]any
	// PlainClaims are included verbatim in the issuer JWT (not selectively disclosable).
	PlainClaims map[string]any
	// TTL controls the "exp" claim.
	TTL time.Duration
	// Signer is the crypto.Signer (RSA/EC private key) used to sign the issuer JWT.
	// Obtain via oidc.Signer.CryptoSigner(). Must not be nil.
	Signer crypto.Signer
	// Alg is the JWS algorithm for signing. Defaults to PS256 (OID4VCI Final recommendation).
	// Use jwa.PS256 for HAIP 1.0 compliance.
	Alg jwa.SignatureAlgorithm
	// KID is the "kid" JWS header value, matching the issuer's public JWKS.
	KID string
	// FormatTyp is the JWS "typ" header value.
	// Defaults to "dc+sd-jwt" per SD-JWT-VC Final §3.2.1 (SDJWTVC-3.2.1).
	// Older deployments may use "vc+sd-jwt" if required.
	FormatTyp string
	// X5C is the issuer's certificate chain embedded in the JWS "x5c" header
	// (RFC 7515 §4.1.6). Required by HAIP-6.1.1: the SD-JWT VC MUST contain
	// an x5c entry in the JWS protected header.
	// Build with selfSignedX5C (credential.go) or supply a real chain in prod.
	// When nil, the x5c header is omitted (backward-compatible with existing flows).
	X5C *cert.Chain
	// HolderKey is the wallet's public key extracted from the proof JWT "jwk" header.
	// When non-nil, it is included as the "cnf.jwk" claim (SD-JWT §4.1.2 / SDJWT-4.1.2)
	// to bind the credential to the wallet's key pair (key binding).
	// Private key material is always stripped before embedding.
	HolderKey jwk.Key
}

// IssueSDJWT issues an SD-JWT-VC and returns the full serialised token
// ("issuer-jwt~disc1~disc2~") plus the individual disclosures for audit.
func IssueSDJWT(p SDJWTParams) (string, []Disclosure, error) {
	// Defaults.
	alg := p.Alg
	if alg == "" {
		alg = jwa.PS256 // OID4VCI Final recommendation; HAIP 1.0 mandatory
	}
	typ := p.FormatTyp
	if typ == "" {
		typ = "dc+sd-jwt" // SD-JWT-VC Final §3.2.1 (SDJWTVC-3.2.1)
	}
	// Truncate to hour boundary — RFC 9901 §10.1 linkability prevention.
	now := time.Now().UTC().Truncate(time.Hour)
	expiry := now.Add(p.TTL)

	disclosures := make([]Disclosure, 0, len(p.DisclosableClaims))
	sdHashes := make([]string, 0, len(p.DisclosableClaims))

	for name, value := range p.DisclosableClaims {
		d, err := NewDisclosure(name, value)
		if err != nil {
			return "", nil, fmt.Errorf("create disclosure for %q: %w", name, err)
		}
		disclosures = append(disclosures, *d)
		sdHashes = append(sdHashes, d.Hash)
	}

	builder := jwt.NewBuilder().
		Issuer(p.Issuer).
		Subject(p.Subject).
		IssuedAt(now).
		Expiration(expiry).
		Claim("vct", p.VCT).
		Claim("_sd_alg", sdAlg).
		Claim("_sd", sdHashes)

	for k, v := range p.PlainClaims {
		builder = builder.Claim(k, v)
	}

	// cnf.jwk — key binding per SD-JWT §4.1.2 (SDJWT-4.1.2).
	// Embed the wallet's public key so verifiers can bind the credential to the
	// holder's key pair.  Private material ("d") is stripped before embedding.
	if p.HolderKey != nil {
		pubKey, pkErr := p.HolderKey.PublicKey()
		if pkErr != nil {
			return "", nil, fmt.Errorf("extract holder public key for cnf: %w", pkErr)
		}
		pubJSON, pkErr := json.Marshal(pubKey)
		if pkErr != nil {
			return "", nil, fmt.Errorf("marshal holder public key for cnf: %w", pkErr)
		}
		var pubMap map[string]any
		if pkErr = json.Unmarshal(pubJSON, &pubMap); pkErr != nil {
			return "", nil, fmt.Errorf("unmarshal holder public key for cnf: %w", pkErr)
		}
		builder = builder.Claim("cnf", map[string]any{"jwk": pubMap})
	}

	tok, err := builder.Build()
	if err != nil {
		return "", nil, fmt.Errorf("build sd-jwt payload: %w", err)
	}

	// Add kid, typ (and optionally x5c) to the JWS protected header.
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, p.KID); err != nil {
		return "", nil, fmt.Errorf("set kid header: %w", err)
	}
	if err := headers.Set("typ", typ); err != nil {
		return "", nil, fmt.Errorf("set typ header: %w", err)
	}
	// x5c: HAIP-6.1.1 requires the issuer certificate chain in the JWS header.
	// When X5C is nil (non-HAIP flows) the header is simply omitted.
	if p.X5C != nil && p.X5C.Len() > 0 {
		if err := headers.Set(jws.X509CertChainKey, p.X5C); err != nil {
			return "", nil, fmt.Errorf("set x5c header: %w", err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, p.Signer, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", nil, fmt.Errorf("sign sd-jwt: %w", err)
	}

	// Serialise: <issuer-jwt>~<disc1>~<disc2>~
	// The trailing "~" with no kb-jwt indicates no holder-binding is required.
	parts := make([]string, 0, 1+len(disclosures)+1)
	parts = append(parts, string(signed))
	for _, d := range disclosures {
		parts = append(parts, d.Raw)
	}
	parts = append(parts, "") // trailing empty segment → trailing ~

	return strings.Join(parts, "~"), disclosures, nil
}

// ParseSDJWT splits a compact SD-JWT into its components.
// Returns the issuer JWT string, raw disclosure strings, and the optional kb-JWT.
func ParseSDJWT(token string) (issuerJWT string, disclosureRaws []string, kbJWT string, err error) {
	parts := strings.Split(token, "~")
	if len(parts) == 0 || parts[0] == "" {
		return "", nil, "", fmt.Errorf("invalid sd-jwt: missing issuer jwt")
	}
	issuerJWT = parts[0]
	rest := parts[1:]

	// The last element is either "" (no kb-jwt) or a compact JWT (kb-jwt).
	if len(rest) > 0 {
		last := rest[len(rest)-1]
		if last != "" && strings.Count(last, ".") == 2 {
			kbJWT = last
			rest = rest[:len(rest)-1]
		}
	}

	for _, d := range rest {
		if d != "" {
			disclosureRaws = append(disclosureRaws, d)
		}
	}
	return issuerJWT, disclosureRaws, kbJWT, nil
}

// DecodeDisclosure decodes a raw base64url disclosure and returns its components.
func DecodeDisclosure(raw string) (salt, name string, value any, err error) {
	b, e := base64.RawURLEncoding.DecodeString(raw)
	if e != nil {
		return "", "", nil, fmt.Errorf("base64url decode: %w", e)
	}
	var arr [3]json.RawMessage
	if e := json.Unmarshal(b, &arr); e != nil {
		// Try as []json.RawMessage in case of extra fields (shouldn't happen per spec)
		return "", "", nil, fmt.Errorf("unmarshal disclosure array: %w", e)
	}
	if e := json.Unmarshal(arr[0], &salt); e != nil {
		return "", "", nil, fmt.Errorf("decode salt: %w", e)
	}
	if e := json.Unmarshal(arr[1], &name); e != nil {
		return "", "", nil, fmt.Errorf("decode name: %w", e)
	}
	if e := json.Unmarshal(arr[2], &value); e != nil {
		return "", "", nil, fmt.Errorf("decode value: %w", e)
	}
	return salt, name, value, nil
}

// VerifyAndExtractClaims parses and verifies an SD-JWT issuer JWT with the given public
// key, matches all disclosureRaws against the _sd array, and returns the
// full set of disclosed claims (JWT registered claims + all matched disclosures).
//
// An error is returned if the signature is invalid or any disclosure hash is not
// found in the issuer JWT's _sd array.
func VerifyAndExtractClaims(issuerJWT string, disclosureRaws []string, pubKey crypto.PublicKey) (map[string]any, error) {
	// Try PS256 first (OID4VCI Final preferred), fall back to RS256.
	var tok jwt.Token
	var err error
	for _, alg := range []jwa.SignatureAlgorithm{jwa.PS256, jwa.RS256, jwa.ES256} {
		tok, err = jwt.Parse([]byte(issuerJWT),
			jwt.WithKey(alg, pubKey),
			jwt.WithValidate(true),
		)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("verify issuer jwt: %w", err)
	}

	// Build a set of expected _sd hashes from the JWT.
	sdSet := map[string]struct{}{}
	if raw, ok := tok.Get("_sd"); ok {
		switch v := raw.(type) {
		case []any:
			for _, h := range v {
				if s, ok := h.(string); ok {
					sdSet[s] = struct{}{}
				}
			}
		case []string:
			for _, h := range v {
				sdSet[h] = struct{}{}
			}
		}
	}

	// Start with all plaintext JWT claims.
	claims, err := jwtToMap(tok)
	if err != nil {
		return nil, fmt.Errorf("extract jwt claims: %w", err)
	}
	// Remove internal SD-JWT claims from the output.
	delete(claims, "_sd")
	delete(claims, "_sd_alg")

	// Match each disclosure against the _sd array.
	for _, raw := range disclosureRaws {
		h := sha256.Sum256([]byte(raw))
		hash := base64.RawURLEncoding.EncodeToString(h[:])
		if _, ok := sdSet[hash]; !ok {
			return nil, fmt.Errorf("disclosure hash %q not found in _sd array", hash)
		}
		_, name, value, err := DecodeDisclosure(raw)
		if err != nil {
			return nil, fmt.Errorf("decode disclosure: %w", err)
		}
		claims[name] = value
	}

	return claims, nil
}

// extractSDJWTClaimsNoSigCheck decodes the SD-JWT payload and matches all
// disclosures WITHOUT verifying the issuer's signature. Use this when the
// issuer's public key is not available (e.g. during direct_post handling for
// DCQL sessions where the issuer is an external party).
func extractSDJWTClaimsNoSigCheck(issuerJWT string, disclosureRaws []string) (map[string]any, error) {
	payloadBytes, err := decodeJWTPayload(issuerJWT)
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal jwt payload: %w", err)
	}

	sdSet := map[string]struct{}{}
	if sdRaw, ok := payload["_sd"]; ok {
		if sdArr, ok := sdRaw.([]interface{}); ok {
			for _, h := range sdArr {
				if s, ok := h.(string); ok {
					sdSet[s] = struct{}{}
				}
			}
		}
	}

	claims := make(map[string]any)
	for k, v := range payload {
		if k == "_sd" || k == "_sd_alg" {
			continue
		}
		claims[k] = v
	}

	for _, raw := range disclosureRaws {
		h := sha256.Sum256([]byte(raw))
		hash := base64.RawURLEncoding.EncodeToString(h[:])
		if _, ok := sdSet[hash]; !ok {
			return nil, fmt.Errorf("disclosure hash %q not found in _sd array", hash)
		}
		_, name, value, err := DecodeDisclosure(raw)
		if err != nil {
			return nil, fmt.Errorf("decode disclosure: %w", err)
		}
		claims[name] = value
	}

	return claims, nil
}

// HashToken returns the hex-encoded SHA-256 of the full token string.
// Used to store a non-reversible reference in the issued_credentials audit table.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

// jwtToMap serialises a jwt.Token to a plain map via JSON round-trip.
func jwtToMap(tok jwt.Token) (map[string]any, error) {
	b, err := json.Marshal(tok)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// ClaimsFromContext retrieves the VP claims stored by the OID4VP handler in the
// Echo request context after successful presentation verification.
func ClaimsFromContext(ctx context.Context) (map[string]any, bool) {
	v := ctx.Value(vpClaimsKey{})
	if v == nil {
		return nil, false
	}
	m, ok := v.(map[string]any)
	return m, ok
}

type vpClaimsKey struct{}
