package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestKeySet generates a fresh 2048-bit RSA KeySet for tests.
func newTestKeySet(t *testing.T) *KeySet {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := computeKID(&priv.PublicKey)
	jwksJSON, err := buildJWKS(&priv.PublicKey, kid)
	require.NoError(t, err)
	return &KeySet{privateKey: priv, kid: kid, jwks: jwksJSON}
}

// newTestTokenConfig returns a TokenConfig wired to a fresh in-memory key.
func newTestTokenConfig(t *testing.T) *TokenConfig {
	t.Helper()
	return &TokenConfig{
		Keys:            newTestKeySet(t),
		Issuer:          "https://clavex.example.com/test-org",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		IDTokenTTL:      time.Hour,
	}
}

// ── IssueAccessToken ─────────────────────────────────────────────────────────

func TestIssueAccessToken_UserGrant(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := &UserClaims{
		UserID: "user-uuid-1",
		OrgID:  "org-uuid-1",
		Email:  "alice@example.com",
		Roles:  []string{"admin"},
		Groups: []string{"eng"},
	}

	signed, jti, err := tc.IssueAccessToken("client-id", "openid profile", uc, nil, nil)

	require.NoError(t, err)
	assert.NotEmpty(t, signed)
	assert.NotEmpty(t, jti)

	// JWT has three base64url parts
	parts := strings.Split(signed, ".")
	require.Len(t, parts, 3, "expected compact JWT")

	// Verify the token round-trips correctly
	tok, gotJTI, _, verifyErr := tc.VerifyAccessToken(signed)
	require.NoError(t, verifyErr)
	assert.Equal(t, jti, gotJTI)
	assert.Equal(t, "user-uuid-1", tok.Subject())
	assert.Equal(t, tc.Issuer, tok.Issuer())
}

func TestIssueAccessToken_ClientCredentials(t *testing.T) {
	tc := newTestTokenConfig(t)

	signed, _, err := tc.IssueAccessToken("m2m-client", "read:logs", nil, nil, nil)

	require.NoError(t, err)
	tok, _, _, verifyErr := tc.VerifyAccessToken(signed)
	require.NoError(t, verifyErr)
	// sub should be the client_id for M2M grants
	assert.Equal(t, "m2m-client", tok.Subject())
}

// ── IssueIDToken ─────────────────────────────────────────────────────────────

func TestIssueIDToken_ContainsRequiredClaims(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := UserClaims{
		UserID:        "user-uuid-2",
		OrgID:         "org-uuid-1",
		Email:         "bob@example.com",
		FirstName:     "Bob",
		LastName:      "Builder",
		EmailVerified: true,
		AuthTime:      time.Now().Unix(),
		AtHash:        "abc123atHash",
	}

	signed, err := tc.IssueIDToken("web-client", "nonce-xyz", uc)

	require.NoError(t, err)
	assert.NotEmpty(t, signed)
}

func TestIssueIDToken_NoncePropagated(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := UserClaims{UserID: "u1", OrgID: "o1", Email: "e@e.com"}

	signed, err := tc.IssueIDToken("client", "my-nonce", uc)

	require.NoError(t, err)
	require.NotEmpty(t, signed)

	// Decode the payload (middle segment) to verify the nonce claim is present.
	parts := strings.Split(signed, ".")
	require.Len(t, parts, 3)
	payload, decErr := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, decErr)
	assert.Contains(t, string(payload), `"my-nonce"`)
}

func TestIssueIDToken_EmptyNonce(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := UserClaims{UserID: "u1", OrgID: "o1", Email: "e@e.com"}

	_, err := tc.IssueIDToken("client", "", uc)
	require.NoError(t, err)
}

// ── ComputeAtHash ─────────────────────────────────────────────────────────────

func TestComputeAtHash_Deterministic(t *testing.T) {
	token := "some.access.token"
	h1 := ComputeAtHash(token)
	h2 := ComputeAtHash(token)
	assert.Equal(t, h1, h2)
}

func TestComputeAtHash_DifferentTokensDifferentHash(t *testing.T) {
	assert.NotEqual(t, ComputeAtHash("token-a"), ComputeAtHash("token-b"))
}

func TestComputeAtHash_IsBase64URLNoPadding(t *testing.T) {
	h := ComputeAtHash("any-token")
	assert.NotContains(t, h, "=", "at_hash must not contain padding")
	assert.NotContains(t, h, "+")
	assert.NotContains(t, h, "/")
}

// ── VerifyPKCE ───────────────────────────────────────────────────────────────

func TestVerifyPKCE_ValidS256(t *testing.T) {
	// Generate a real S256 challenge/verifier pair
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := hashString(verifier) // S256 = BASE64URL(SHA-256(verifier))

	err := VerifyPKCE(challenge, verifier)
	assert.NoError(t, err)
}

func TestVerifyPKCE_Mismatch(t *testing.T) {
	challenge := hashString("correct-verifier")
	err := VerifyPKCE(challenge, "wrong-verifier")
	assert.ErrorContains(t, err, "code_verifier does not match")
}

func TestVerifyPKCE_EmptyVerifierWhenChallengeSet(t *testing.T) {
	challenge := hashString("some-verifier")
	err := VerifyPKCE(challenge, "")
	assert.ErrorContains(t, err, "code_verifier is required")
}

func TestVerifyPKCE_NoChallenge(t *testing.T) {
	// No PKCE → always passes (confidential clients without PKCE)
	err := VerifyPKCE("", "")
	assert.NoError(t, err)

	err = VerifyPKCE("", "any-verifier")
	assert.NoError(t, err)
}

// ── VerifyAccessToken ─────────────────────────────────────────────────────────

func TestVerifyAccessToken_WrongKey(t *testing.T) {
	tc := newTestTokenConfig(t)
	signed, _, err := tc.IssueAccessToken("client", "openid", nil, nil, nil)
	require.NoError(t, err)

	// Build a second config with a different key
	tc2 := newTestTokenConfig(t)
	_, _, _, verifyErr := tc2.VerifyAccessToken(signed)
	assert.Error(t, verifyErr)
}

func TestVerifyAccessToken_Expired(t *testing.T) {
	tc := &TokenConfig{
		Keys:           newTestKeySet(t),
		Issuer:         "https://clavex.example.com/test-org",
		AccessTokenTTL: -time.Second, // already expired
		IDTokenTTL:     time.Hour,
	}

	signed, _, err := tc.IssueAccessToken("client", "openid", nil, nil, nil)
	require.NoError(t, err)

	_, _, _, verifyErr := tc.VerifyAccessToken(signed)
	assert.Error(t, verifyErr, "expired token must not verify")
}

// ── Claims parameter (OIDC Core §5.5) ────────────────────────────────────────

func TestIssueAccessToken_ReqClaimsCarried(t *testing.T) {
	tc := newTestTokenConfig(t)
	rawClaims := `{"userinfo":{"email":null,"phone_number":{"essential":true}}}`
	uc := &UserClaims{
		UserID:    "user-uuid-3",
		OrgID:     "org-uuid-1",
		Email:     "test@example.com",
		ReqClaims: rawClaims,
	}

	signed, _, err := tc.IssueAccessToken("client-id", "openid", uc, nil, nil)
	require.NoError(t, err)

	tok, _, _, verifyErr := tc.VerifyAccessToken(signed)
	require.NoError(t, verifyErr)

	// req_claims must be present and round-trip exactly.
	got, ok := tok.Get("req_claims")
	require.True(t, ok, "req_claims claim missing from access token")
	assert.Equal(t, rawClaims, got)
}

func TestIssueAccessToken_NoReqClaimsWhenEmpty(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := &UserClaims{UserID: "u1", OrgID: "o1", Email: "e@e.com", ReqClaims: ""}

	signed, _, err := tc.IssueAccessToken("client-id", "openid", uc, nil, nil)
	require.NoError(t, err)

	tok, _, _, verifyErr := tc.VerifyAccessToken(signed)
	require.NoError(t, verifyErr)

	_, ok := tok.Get("req_claims")
	assert.False(t, ok, "req_claims should be absent when ReqClaims is empty")
}

func TestIssueAccessToken_ReqClaimsOmittedForClientCredentials(t *testing.T) {
	tc := newTestTokenConfig(t)

	// M2M / client_credentials: user is nil, no req_claims expected.
	signed, _, err := tc.IssueAccessToken("m2m-client", "read:data", nil, nil, nil)
	require.NoError(t, err)

	tok, _, _, verifyErr := tc.VerifyAccessToken(signed)
	require.NoError(t, verifyErr)
	_, ok := tok.Get("req_claims")
	assert.False(t, ok, "req_claims must not appear in M2M tokens")
}

// ── ACR (Authentication Context Class Reference) ─────────────────────────────

func TestIssueIDToken_AcrIncludedWhenRequested(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := UserClaims{
		UserID: "user-uuid-4",
		OrgID:  "org-uuid-1",
		Email:  "a@example.com",
		Acr:    "0", // resolveAcr("eidas1") → "0"
	}

	signed, err := tc.IssueIDToken("client", "", uc)
	require.NoError(t, err)

	parts := strings.Split(signed, ".")
	require.Len(t, parts, 3)
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	assert.Contains(t, string(payload), `"acr":"0"`)
}

func TestIssueIDToken_AcrOmittedWhenNotRequested(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := UserClaims{
		UserID: "user-uuid-5",
		OrgID:  "org-uuid-1",
		Email:  "b@example.com",
		Acr:    "", // acr_values not requested → acr omitted
	}

	signed, err := tc.IssueIDToken("client", "", uc)
	require.NoError(t, err)

	parts := strings.Split(signed, ".")
	require.Len(t, parts, 3)
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	assert.NotContains(t, string(payload), `"acr"`)
}
