package oidc

// DPoP (Demonstrating Proof of Possession) — RFC 9449.
//
// DPoP binds an access token to a client-held asymmetric key pair.
// The client generates a DPoP proof JWS on every request; the server
// verifies the proof and embeds a JWK Thumbprint ("jkt") in the access
// token's "cnf" claim.  A stolen token is useless without the private key.
//
// Server-side responsibilities implemented here:
//   1. Parse the DPoP proof from the "DPoP" HTTP header.
//   2. Verify it is a valid JWS (alg != none, typ = dpop+jwt).
//   3. Check htm/htu match the current request method/URL.
//   4. Validate iat / jti (anti-replay via a short-lived nonce store).
//   5. Compute the JWK Thumbprint for the "cnf" claim.
//
// Token issuance:
//   IssueAccessToken accepts an optional *DPoPKey; when present it adds
//   cnf.jkt to the JWT payload and sets token_type = "DPoP".
//
// Token verification:
//   The resource-server middleware should call VerifyDPoPProof for every
//   request carrying a "DPoP" header, using the jkt extracted from the
//   access-token cnf claim.

import (
	"context"
	"crypto"
	_ "crypto/sha256" // register SHA-256
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
)

// DPoPProofMaxAge is how long a DPoP proof is considered fresh.
// RFC 9449 §11.1 recommends no more than a few minutes.
const DPoPProofMaxAge = 5 * time.Minute

// DPoPKey carries the parsed public key and its thumbprint from a DPoP proof.
type DPoPKey struct {
	// JKT is the JWK SHA-256 Thumbprint (base64url-encoded), used as cnf.jkt.
	JKT string
	// JTI is the jti claim from the DPoP proof — used for replay detection.
	JTI string
	// PublicKey is the raw jwk.Key from the DPoP proof header.
	PublicKey jwk.Key
	// Alg is the signature algorithm used in the DPoP proof (e.g. "PS256", "ES256").
	Alg string
	// ATH is the ath claim from the DPoP proof; empty if not present.
	// Resource servers MUST verify this matches the bound access token hash (RFC 9449 §4.2).
	ATH string
}

// dpopJTIPrefix is the Redis key prefix for DPoP jti anti-replay entries.
const dpopJTIPrefix = "dpop:jti:"

// CheckJTI performs a Redis SETNX-style check to prevent DPoP proof replay.
// Returns an error if the jti has already been seen within its 5-minute window.
// Must be called after ParseDPoPProof for every token-endpoint request carrying a DPoP header.
func CheckJTI(ctx context.Context, jti string, rdb redis.UniversalClient) error {
	key := dpopJTIPrefix + jti
	// SET key 1 EX 300 NX — atomically sets with TTL only if the key does not exist.
	set, err := rdb.SetNX(ctx, key, 1, DPoPProofMaxAge).Result()
	if err != nil {
		// Redis unavailable — fail open to avoid blocking legitimate requests,
		// but log the error; callers can decide to fail closed.
		return fmt.Errorf("%w: jti store unavailable: %v", ErrDPoP, err)
	}
	if !set {
		// Key already existed — this jti was already used.
		return fmt.Errorf("%w: dpop proof replay detected (jti=%s)", ErrDPoP, jti)
	}
	return nil
}

// ErrDPoP is the sentinel error for DPoP validation failures.
var ErrDPoP = errors.New("use_dpop_nonce")

// ParseDPoPProof parses a DPoP proof JWS from the Authorization header value.
//
//   - proofJWT: the raw value of the "DPoP" HTTP header.
//   - htm:      expected HTTP method (e.g. "POST"), case-insensitive.
//   - htu:      expected HTTP URL (scheme + host + path, no query / fragment).
//
// On success it returns the DPoPKey that should be bound to the access token.
// If the proof is missing pass an empty string; the function returns (nil, nil)
// signalling that the request is plain Bearer — callers decide whether to
// enforce DPoP.
func ParseDPoPProof(proofJWT, htm, htu string) (*DPoPKey, error) {
	if proofJWT == "" {
		return nil, nil
	}

	// ── Parse JWS headers (unverified, to extract jwk) ───────────────────
	msg, err := jws.Parse([]byte(proofJWT))
	if err != nil {
		return nil, fmt.Errorf("%w: malformed dpop proof: %v", ErrDPoP, err)
	}
	if len(msg.Signatures()) == 0 {
		return nil, fmt.Errorf("%w: dpop proof has no signatures", ErrDPoP)
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()

	// typ MUST be "dpop+jwt" (RFC 9449 §4.2)
	if !strings.EqualFold(hdr.Type(), "dpop+jwt") {
		return nil, fmt.Errorf("%w: typ must be dpop+jwt, got %q", ErrDPoP, hdr.Type())
	}

	// alg must be PS-family or EC-family (RFC 9449 §4.1; FAPI2-SP-FINAL §5.4).
	alg := hdr.Algorithm()
	if err := rejectForbiddenDPoPAlg(alg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDPoP, err)
	}

	// The DPoP header MUST carry the public key ("jwk" header).
	rawJWK := hdr.JWK()
	if rawJWK == nil {
		return nil, fmt.Errorf("%w: jwk header is required in dpop proof", ErrDPoP)
	}

	// The jwk header must be a public key (no "d" parameter).
	if _, ok := rawJWK.(jwk.RSAPrivateKey); ok {
		return nil, fmt.Errorf("%w: jwk header must not be a private key", ErrDPoP)
	}
	if _, ok := rawJWK.(jwk.ECDSAPrivateKey); ok {
		return nil, fmt.Errorf("%w: jwk header must not be a private key", ErrDPoP)
	}

	// ── Verify signature against the embedded public key ─────────────────
	verified, err := jws.Verify([]byte(proofJWT), jws.WithKey(alg, rawJWK))
	if err != nil {
		return nil, fmt.Errorf("%w: dpop proof signature invalid: %v", ErrDPoP, err)
	}

	// ── Parse JWT claims ──────────────────────────────────────────────────
	tok, err := jwt.ParseInsecure(verified)
	if err != nil {
		return nil, fmt.Errorf("%w: dpop proof payload: %v", ErrDPoP, err)
	}

	// jti — REQUIRED, must be unique (callers should replay-check it)
	if tok.JwtID() == "" {
		return nil, fmt.Errorf("%w: jti is required", ErrDPoP)
	}

	// iat — REQUIRED and fresh
	iat := tok.IssuedAt()
	if iat.IsZero() {
		return nil, fmt.Errorf("%w: iat is required", ErrDPoP)
	}
	age := time.Since(iat)
	if age < 0 {
		age = -age
	}
	if age > DPoPProofMaxAge {
		return nil, fmt.Errorf("%w: dpop proof too old (%s)", ErrDPoP, age)
	}

	// htm — REQUIRED, must match the request method
	htmClaim, _ := tok.Get("htm")
	if !strings.EqualFold(fmt.Sprint(htmClaim), htm) {
		return nil, fmt.Errorf("%w: htm mismatch: proof=%q request=%q", ErrDPoP, htmClaim, htm)
	}

	// htu — REQUIRED, must match the request URL (no query/fragment)
	// RFC 9449 §4.3 item 9: when comparing htu, strip query and fragment from
	// the proof's htu value so that proofs with extra components still match.
	// RFC 3986 §6.2.3: normalise default ports (https:443, http:80) to their
	// absent form so that "https://host:443/path" equals "https://host/path".
	htuClaim, _ := tok.Get("htu")
	proofHTU := fmt.Sprint(htuClaim)
	if u, parseErr := url.Parse(proofHTU); parseErr == nil {
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.RawQuery = ""
		u.Fragment = ""
		// Strip default port for the scheme (RFC 3986 §6.2.3).
		if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
			u.Host = u.Hostname()
		}
		proofHTU = u.String()
	}
	if proofHTU != htu {
		return nil, fmt.Errorf("%w: htu mismatch: proof=%q request=%q", ErrDPoP, htuClaim, htu)
	}

	// ── Compute JWK Thumbprint (RFC 7638) ─────────────────────────────────
	jkt, err := thumbprint(rawJWK)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot compute jwk thumbprint: %v", ErrDPoP, err)
	}

	// ath claim — resource servers MUST verify this matches the access token
	// hash (RFC 9449 §4.2, §7.2); store it so callers can check it.
	athClaim, _ := tok.Get("ath")
	ath := ""
	if athClaim != nil {
		ath = fmt.Sprint(athClaim)
	}

	return &DPoPKey{JKT: jkt, JTI: tok.JwtID(), PublicKey: rawJWK, Alg: alg.String(), ATH: ath}, nil
}

// VerifyDPoPProof validates a DPoP proof against an already-bound access token.
// Use this at the resource server to verify that the caller holds the private
// key bound to the access token.
//
//   - proofJWT:    raw DPoP header value
//   - htm / htu:  current request method and URL
//   - boundJKT:   the jkt extracted from the access token's cnf.jkt claim
func VerifyDPoPProof(proofJWT, htm, htu, boundJKT string) error {
	key, err := ParseDPoPProof(proofJWT, htm, htu)
	if err != nil {
		return err
	}
	if key == nil {
		return fmt.Errorf("%w: dpop proof required for this token", ErrDPoP)
	}
	if key.JKT != boundJKT {
		return fmt.Errorf("%w: jkt mismatch: proof=%q token=%q", ErrDPoP, key.JKT, boundJKT)
	}
	return nil
}

// IssueNonce generates a fresh opaque DPoP server nonce (RFC 9449 §8).
// Callers should store it short-lived (e.g. in Redis with a 60 s TTL) and
// include it in the WWW-Authenticate / DPoP-Nonce response header.
func IssueNonce() string {
	return uuid.NewString()
}

// JKTFromCNF extracts the jkt value from a parsed access-token's cnf claim.
// Returns ("", false) if no cnf/jkt is present (plain Bearer token).
func JKTFromCNF(tok jwt.Token) (string, bool) {
	cnfRaw, ok := tok.Get("cnf")
	if !ok {
		return "", false
	}
	cnfMap, ok := cnfRaw.(map[string]interface{})
	if !ok {
		return "", false
	}
	jkt, ok := cnfMap["jkt"].(string)
	return jkt, ok && jkt != ""
}

// thumbprint computes the RFC 7638 JWK Thumbprint for a public key.
func thumbprint(key jwk.Key) (string, error) {
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// rejectForbiddenDPoPAlg returns an error if alg is not allowed in a DPoP proof.
//
// RFC 9449 §4.1 requires an asymmetric algorithm and specifically discourages
// RS256. FAPI2 Security Profile Final §5.4 (via FAPI2MSG_SIGNING_ALGS) further
// restricts DPoP proofs to PS-family (RSA-PSS) and EC-family algorithms:
//
//	allowed: PS256, PS384, PS512, ES256, ES384, ES512, EdDSA
//	rejected: none, HS*, RS256, RS384, RS512 (RSA PKCS1v15)
func rejectForbiddenDPoPAlg(alg jwa.SignatureAlgorithm) error {
	switch alg {
	case jwa.PS256, jwa.PS384, jwa.PS512,
		jwa.ES256, jwa.ES384, jwa.ES512,
		jwa.EdDSA:
		return nil
	case jwa.RS256, jwa.RS384, jwa.RS512:
		return fmt.Errorf("RSA PKCS1v15 alg %q is not permitted for DPoP (FAPI2-SP-FINAL §5.4; use PS256 or an EC algorithm)", alg)
	default:
		return fmt.Errorf("alg %q is not permitted for DPoP", alg)
	}
}
