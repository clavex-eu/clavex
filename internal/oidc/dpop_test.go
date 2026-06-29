package oidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func generateECDPoP(t *testing.T) (*ecdsa.PrivateKey, jwk.Key) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.FromRaw(priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func generateRSADPoP(t *testing.T) (*rsa.PrivateKey, jwk.Key) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.FromRaw(priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// makeDPoPProof creates a minimal valid DPoP proof JWS.
func makeDPoPProof(t *testing.T, alg jwa.SignatureAlgorithm, priv interface{}, pub jwk.Key,
	htm, htu string, iat time.Time) string {
	t.Helper()

	tok, err := jwt.NewBuilder().
		JwtID(uuid.NewString()).
		Claim("htm", htm).
		Claim("htu", htu).
		IssuedAt(iat).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.TypeKey, "dpop+jwt")
	// jws.JWKKey is the constant for the "jwk" protected header field.
	// We must pass a jwk.Key (not a raw map) so that dpop.go's hdr.JWK() works.
	if err := hdrs.Set(jws.JWKKey, pub); err != nil {
		t.Fatalf("set jwk header: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// ── ParseDPoPProof ────────────────────────────────────────────────────────────

func TestParseDPoPProof_EmptyReturnsNil(t *testing.T) {
	result, err := oidc.ParseDPoPProof("", "POST", "https://example.com/token")
	if err != nil || result != nil {
		t.Fatalf("expected nil,nil for empty proof; got %v, %v", result, err)
	}
}

func TestParseDPoPProof_ValidEC(t *testing.T) {
	priv, pub := generateECDPoP(t)
	proof := makeDPoPProof(t, jwa.ES256, priv, pub, "POST", "https://example.com/token", time.Now())

	dpop, err := oidc.ParseDPoPProof(proof, "POST", "https://example.com/token")
	if err != nil {
		t.Fatalf("ParseDPoPProof: %v", err)
	}
	if dpop == nil {
		t.Fatal("expected DPoPKey, got nil")
	}
	if dpop.JKT == "" {
		t.Fatal("expected non-empty JKT")
	}
}

func TestParseDPoPProof_RS256Rejected(t *testing.T) {
	// FAPI2-SP-FINAL §5.4 and RFC 9449 §4.1: RSA PKCS1v15 (RS256) is not
	// permitted in DPoP proofs; only PS-family and EC-family are allowed.
	priv, pub := generateRSADPoP(t)
	proof := makeDPoPProof(t, jwa.RS256, priv, pub, "GET", "https://example.com/userinfo", time.Now())

	_, err := oidc.ParseDPoPProof(proof, "GET", "https://example.com/userinfo")
	if err == nil {
		t.Fatal("expected RS256 DPoP proof to be rejected, but ParseDPoPProof succeeded")
	}
}

func TestParseDPoPProof_HtmMismatch(t *testing.T) {
	priv, pub := generateECDPoP(t)
	proof := makeDPoPProof(t, jwa.ES256, priv, pub, "POST", "https://example.com/token", time.Now())

	_, err := oidc.ParseDPoPProof(proof, "GET", "https://example.com/token")
	if err == nil {
		t.Fatal("expected error on htm mismatch")
	}
}

func TestParseDPoPProof_HtuMismatch(t *testing.T) {
	priv, pub := generateECDPoP(t)
	proof := makeDPoPProof(t, jwa.ES256, priv, pub, "POST", "https://example.com/token", time.Now())

	_, err := oidc.ParseDPoPProof(proof, "POST", "https://other.com/token")
	if err == nil {
		t.Fatal("expected error on htu mismatch")
	}
}

// TestParseDPoPProof_HtuDefaultPortNormalized verifies that a DPoP proof
// whose htu contains an explicit default port (https:443 / http:80) is accepted
// when the server's htu omits the port — RFC 3986 §6.2.3.
func TestParseDPoPProof_HtuDefaultPortNormalized(t *testing.T) {
	priv, pub := generateECDPoP(t)

	// Proof htu has explicit :443; server expects the port-free form.
	proof := makeDPoPProof(t, jwa.ES256, priv, pub, "POST",
		"https://example.com:443/token", time.Now())

	dpop, err := oidc.ParseDPoPProof(proof, "POST", "https://example.com/token")
	if err != nil {
		t.Fatalf("expected :443 to be normalised away, got error: %v", err)
	}
	if dpop == nil {
		t.Fatal("expected non-nil DPoPKey")
	}
}

func TestParseDPoPProof_Expired(t *testing.T) {
	priv, pub := generateECDPoP(t)
	oldIat := time.Now().Add(-10 * time.Minute)
	proof := makeDPoPProof(t, jwa.ES256, priv, pub, "POST", "https://example.com/token", oldIat)

	_, err := oidc.ParseDPoPProof(proof, "POST", "https://example.com/token")
	if err == nil {
		t.Fatal("expected error for expired iat")
	}
}

func TestParseDPoPProof_NotYetValid(t *testing.T) {
	priv, pub := generateECDPoP(t)
	futureIat := time.Now().Add(10 * time.Minute)
	proof := makeDPoPProof(t, jwa.ES256, priv, pub, "POST", "https://example.com/token", futureIat)

	_, err := oidc.ParseDPoPProof(proof, "POST", "https://example.com/token")
	if err == nil {
		t.Fatal("expected error for future iat")
	}
}

// ── Reject symmetric / none alg ───────────────────────────────────────────────

func TestParseDPoPProof_HMACRejected(t *testing.T) {
	// Build a proof manually with alg=HS256 (no jwk header needed for HMAC,
	// but the validation should reject it before checking the signature).
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	tok, _ := jwt.NewBuilder().
		JwtID(uuid.NewString()).
		Claim("htm", "POST").
		Claim("htu", "https://example.com/token").
		IssuedAt(time.Now()).
		Build()

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.TypeKey, "dpop+jwt")

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, secret, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Skip("could not sign HMAC proof:", err)
	}

	_, err = oidc.ParseDPoPProof(string(signed), "POST", "https://example.com/token")
	if err == nil {
		t.Fatal("expected HMAC alg to be rejected")
	}
}

// ── VerifyDPoPProof ────────────────────────────────────────────────────────────

func TestVerifyDPoPProof_MatchingJKT(t *testing.T) {
	priv, pub := generateECDPoP(t)
	proof := makeDPoPProof(t, jwa.ES256, priv, pub, "POST", "https://example.com/token", time.Now())

	dpop, err := oidc.ParseDPoPProof(proof, "POST", "https://example.com/token")
	if err != nil || dpop == nil {
		t.Fatalf("setup: %v", err)
	}

	err = oidc.VerifyDPoPProof(proof, "POST", "https://example.com/token", dpop.JKT)
	if err != nil {
		t.Fatalf("VerifyDPoPProof: %v", err)
	}
}

func TestVerifyDPoPProof_WrongJKT(t *testing.T) {
	priv, pub := generateECDPoP(t)
	proof := makeDPoPProof(t, jwa.ES256, priv, pub, "POST", "https://example.com/token", time.Now())

	err := oidc.VerifyDPoPProof(proof, "POST", "https://example.com/token", "wrongJKT")
	if err == nil {
		t.Fatal("expected error on wrong JKT")
	}
}

// ── JKT thumbprint format ─────────────────────────────────────────────────────

func TestDPoPKey_JKTIsBase64URL(t *testing.T) {
	priv, pub := generateECDPoP(t)
	proof := makeDPoPProof(t, jwa.ES256, priv, pub, "POST", "https://example.com/token", time.Now())

	dpop, err := oidc.ParseDPoPProof(proof, "POST", "https://example.com/token")
	if err != nil {
		t.Fatalf("ParseDPoPProof: %v", err)
	}
	if dpop == nil {
		t.Fatal("expected non-nil DPoPKey")
	}
	// Raw URL (no padding) base64 decode must succeed.
	_, err = base64.RawURLEncoding.DecodeString(dpop.JKT)
	if err != nil {
		t.Fatalf("JKT is not valid base64url: %v", err)
	}
}

// ── JKTFromCNF ────────────────────────────────────────────────────────────────

func TestJKTFromCNF_Present(t *testing.T) {
	tok, _ := jwt.NewBuilder().
		Claim("cnf", map[string]interface{}{"jkt": "abc123"}).
		Build()

	jkt, ok := oidc.JKTFromCNF(tok)
	if !ok || jkt != "abc123" {
		t.Fatalf("expected jkt=abc123, got %q ok=%v", jkt, ok)
	}
}

func TestJKTFromCNF_Missing(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	_, ok := oidc.JKTFromCNF(tok)
	if ok {
		t.Fatal("expected ok=false when cnf claim absent")
	}
}

// ── ThumbprintFromCNF ─────────────────────────────────────────────────────────

func TestThumbprintFromCNF_Present(t *testing.T) {
	tok, _ := jwt.NewBuilder().
		Claim("cnf", map[string]interface{}{"x5t#S256": "abc123"}).
		Build()

	thumb, ok := oidc.ThumbprintFromCNF(tok)
	if !ok || thumb != "abc123" {
		t.Fatalf("expected thumb=abc123, got %q ok=%v", thumb, ok)
	}
}

func TestThumbprintFromCNF_Missing(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	_, ok := oidc.ThumbprintFromCNF(tok)
	if ok {
		t.Fatal("expected ok=false when cnf claim absent")
	}
}

func TestThumbprintFromCNF_JKTOnlyNoCert(t *testing.T) {
	// token with cnf.jkt but no cnf.x5t#S256 must return false
	tok, _ := jwt.NewBuilder().
		Claim("cnf", map[string]interface{}{"jkt": "dpopkey"}).
		Build()

	_, ok := oidc.ThumbprintFromCNF(tok)
	if ok {
		t.Fatal("expected ok=false when only jkt is present, no x5t#S256")
	}
}

// ── IssueNonce ────────────────────────────────────────────────────────────────

func TestIssueNonce_UniqueAndNonEmpty(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		n := oidc.IssueNonce()
		if n == "" {
			t.Fatal("nonce is empty")
		}
		if seen[n] {
			t.Fatal("duplicate nonce")
		}
		seen[n] = true
		// Must be valid URL-safe chars (base64url or hex).
		for _, c := range n {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/", c) {
				t.Fatalf("nonce contains unexpected character: %q", c)
			}
		}
	}
}
