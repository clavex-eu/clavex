package oid4w

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func testPubKey(p SDJWTParams) crypto.PublicKey {
	return p.Signer.Public()
}

func baseParams(t *testing.T) SDJWTParams {
	t.Helper()
	k := newTestKey(t)
	return SDJWTParams{
		Issuer:  "https://clavex.example.com/test-org",
		Subject: "user-uuid-1",
		VCT:     "https://example.com/credentials/identity/v1",
		DisclosableClaims: map[string]any{
			"email":      "alice@example.com",
			"first_name": "Alice",
			"last_name":  "Smith",
		},
		PlainClaims: map[string]any{
			"org_id": "org-uuid-1",
		},
		TTL:    time.Hour,
		Signer: k,
		Alg:    jwa.RS256,
		KID:    "test-kid",
	}
}

// ── NewDisclosure ─────────────────────────────────────────────────────────────

func TestNewDisclosure_Structure(t *testing.T) {
	d, err := NewDisclosure("email", "alice@example.com")
	require.NoError(t, err)

	assert.NotEmpty(t, d.Salt)
	assert.Equal(t, "email", d.Name)
	assert.Equal(t, "alice@example.com", d.Value)
	assert.NotEmpty(t, d.Raw)
	assert.NotEmpty(t, d.Hash)
}

func TestNewDisclosure_UniquePerCall(t *testing.T) {
	d1, err1 := NewDisclosure("email", "alice@example.com")
	d2, err2 := NewDisclosure("email", "alice@example.com")
	require.NoError(t, err1)
	require.NoError(t, err2)

	// Different salts → different Raw and Hash even for identical inputs
	assert.NotEqual(t, d1.Salt, d2.Salt)
	assert.NotEqual(t, d1.Raw, d2.Raw)
	assert.NotEqual(t, d1.Hash, d2.Hash)
}

func TestNewDisclosure_RawIsBase64URLNoPadding(t *testing.T) {
	d, err := NewDisclosure("foo", "bar")
	require.NoError(t, err)
	assert.NotContains(t, d.Raw, "=")
	assert.NotContains(t, d.Raw, "+")
	assert.NotContains(t, d.Raw, "/")
}

// ── DecodeDisclosure ──────────────────────────────────────────────────────────

func TestDecodeDisclosure_RoundTrip(t *testing.T) {
	d, err := NewDisclosure("given_name", "Bob")
	require.NoError(t, err)

	salt, name, value, decErr := DecodeDisclosure(d.Raw)
	require.NoError(t, decErr)

	assert.Equal(t, d.Salt, salt)
	assert.Equal(t, "given_name", name)
	assert.Equal(t, "Bob", value)
}

func TestDecodeDisclosure_InvalidBase64(t *testing.T) {
	_, _, _, err := DecodeDisclosure("not-valid-base64!!!")
	assert.Error(t, err)
}

func TestDecodeDisclosure_TooFewElements(t *testing.T) {
	// Valid base64url but JSON array with only 2 elements (missing value)
	import64 := "WyJzYWx0IiwibmFtZSJd" // base64url(["salt","name"])
	_, _, _, err := DecodeDisclosure(import64)
	assert.Error(t, err)
}

// ── IssueSDJWT ────────────────────────────────────────────────────────────────

func TestIssueSDJWT_ReturnsCompactToken(t *testing.T) {
	p := baseParams(t)
	token, disclosures, err := IssueSDJWT(p)
	require.NoError(t, err)

	// Format: issuer-jwt~disc1~disc2~...~
	assert.Contains(t, token, "~")
	assert.NotEmpty(t, disclosures)
}

func TestIssueSDJWT_OneDisclosurePerClaim(t *testing.T) {
	p := baseParams(t)
	_, disclosures, err := IssueSDJWT(p)
	require.NoError(t, err)
	assert.Len(t, disclosures, len(p.DisclosableClaims))
}

func TestIssueSDJWT_TokenContainsAllDisclosures(t *testing.T) {
	p := baseParams(t)
	token, disclosures, err := IssueSDJWT(p)
	require.NoError(t, err)

	// Each disclosure Raw must appear in the token string.
	for _, d := range disclosures {
		assert.Contains(t, token, d.Raw, "disclosure %q missing from token", d.Name)
	}
}

func TestIssueSDJWT_IssuerJWTHasThreeParts(t *testing.T) {
	p := baseParams(t)
	token, _, err := IssueSDJWT(p)
	require.NoError(t, err)

	// The issuer JWT is the portion before the first "~"
	issuerJWT := strings.SplitN(token, "~", 2)[0]
	parts := strings.Split(issuerJWT, ".")
	assert.Len(t, parts, 3, "issuer JWT must be a compact JWS")
}

// ── VerifyAndExtractClaims ────────────────────────────────────────────────────

func TestVerifyAndExtractClaims_FullRoundTrip(t *testing.T) {
	p := baseParams(t)
	token, disclosures, err := IssueSDJWT(p)
	require.NoError(t, err)

	issuerJWT := strings.SplitN(token, "~", 2)[0]
	raws := make([]string, len(disclosures))
	for i, d := range disclosures {
		raws[i] = d.Raw
	}

	claims, verifyErr := VerifyAndExtractClaims(issuerJWT, raws, testPubKey(p))
	require.NoError(t, verifyErr)

	// All disclosable claims must be present after full reveal
	assert.Equal(t, "alice@example.com", claims["email"])
	assert.Equal(t, "Alice", claims["first_name"])
	assert.Equal(t, "Smith", claims["last_name"])

	// Plain claims must also be present
	assert.Equal(t, "org-uuid-1", claims["org_id"])
}

func TestVerifyAndExtractClaims_SelectiveReveal(t *testing.T) {
	p := baseParams(t)
	token, disclosures, err := IssueSDJWT(p)
	require.NoError(t, err)

	issuerJWT := strings.SplitN(token, "~", 2)[0]

	// Reveal only the email disclosure
	var emailRaw string
	for _, d := range disclosures {
		if d.Name == "email" {
			emailRaw = d.Raw
			break
		}
	}
	require.NotEmpty(t, emailRaw)

	claims, verifyErr := VerifyAndExtractClaims(issuerJWT, []string{emailRaw}, testPubKey(p))
	require.NoError(t, verifyErr)

	assert.Equal(t, "alice@example.com", claims["email"])
	// Unrevealed claims must NOT appear
	assert.NotContains(t, claims, "first_name")
	assert.NotContains(t, claims, "last_name")
}

func TestVerifyAndExtractClaims_NoDisclosures(t *testing.T) {
	p := baseParams(t)
	token, _, err := IssueSDJWT(p)
	require.NoError(t, err)

	issuerJWT := strings.SplitN(token, "~", 2)[0]

	// Present no disclosures — only plain claims should be visible
	claims, verifyErr := VerifyAndExtractClaims(issuerJWT, nil, testPubKey(p))
	require.NoError(t, verifyErr)
	assert.Equal(t, "org-uuid-1", claims["org_id"])
	assert.NotContains(t, claims, "email")
}

func TestVerifyAndExtractClaims_WrongKey(t *testing.T) {
	p := baseParams(t)
	token, disclosures, err := IssueSDJWT(p)
	require.NoError(t, err)

	issuerJWT := strings.SplitN(token, "~", 2)[0]
	raws := make([]string, len(disclosures))
	for i, d := range disclosures {
		raws[i] = d.Raw
	}

	wrongKey := newTestKey(t)
	_, verifyErr := VerifyAndExtractClaims(issuerJWT, raws, &wrongKey.PublicKey) //nolint:gosec
	assert.Error(t, verifyErr, "verification with wrong key must fail")
}

func TestVerifyAndExtractClaims_TamperedDisclosure(t *testing.T) {
	p := baseParams(t)
	token, disclosures, err := IssueSDJWT(p)
	require.NoError(t, err)

	issuerJWT := strings.SplitN(token, "~", 2)[0]

	// Tamper: change the last character of the first disclosure
	tampered := disclosures[0].Raw
	if tampered[len(tampered)-1] == 'a' {
		tampered = tampered[:len(tampered)-1] + "b"
	} else {
		tampered = tampered[:len(tampered)-1] + "a"
	}

	_, verifyErr := VerifyAndExtractClaims(issuerJWT, []string{tampered}, testPubKey(p))
	assert.Error(t, verifyErr, "tampered disclosure must be rejected")
}

// ── HashToken ─────────────────────────────────────────────────────────────────

func TestHashToken_Deterministic(t *testing.T) {
	h1 := HashToken("some-sd-jwt-token")
	h2 := HashToken("some-sd-jwt-token")
	assert.Equal(t, h1, h2)
}

func TestHashToken_IsHex(t *testing.T) {
	h := HashToken("x")
	for _, ch := range h {
		assert.True(t, (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'),
			"expected hex character, got %q", ch)
	}
}
