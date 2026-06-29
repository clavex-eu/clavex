package cie

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── GetEndpoints ──────────────────────────────────────────────────────────────

func TestGetEndpoints_Production(t *testing.T) {
	eps := GetEndpoints("production")
	assert.Contains(t, eps.AuthorizationURL, "idserver.servizicie.interno.gov.it")
	assert.NotContains(t, eps.AuthorizationURL, "preproduzione")
}

func TestGetEndpoints_Preproduction(t *testing.T) {
	eps := GetEndpoints("preproduction")
	assert.Contains(t, eps.AuthorizationURL, "preproduzione")
}

func TestGetEndpoints_UnknownFallsToPreproduction(t *testing.T) {
	eps := GetEndpoints("unknown-env")
	assert.Contains(t, eps.AuthorizationURL, "preproduzione")
}

func TestGetEndpoints_AllURLsAreHTTPS(t *testing.T) {
	for _, env := range []string{"production", "preproduction"} {
		eps := GetEndpoints(env)
		for _, u := range []string{eps.AuthorizationURL, eps.TokenURL, eps.UserinfoURL, eps.JWKSURL} {
			assert.True(t, strings.HasPrefix(u, "https://"), "URL %q should use HTTPS", u)
		}
	}
}

// ── StripTINITPrefix ──────────────────────────────────────────────────────────

func TestStripTINITPrefix_StripsPrefix(t *testing.T) {
	assert.Equal(t, "RSSMRA80A01H501Z", StripTINITPrefix("TINIT-RSSMRA80A01H501Z"))
}

func TestStripTINITPrefix_NoPrefix(t *testing.T) {
	assert.Equal(t, "RSSMRA80A01H501Z", StripTINITPrefix("RSSMRA80A01H501Z"))
}

func TestStripTINITPrefix_EmptyString(t *testing.T) {
	assert.Equal(t, "", StripTINITPrefix(""))
}

func TestStripTINITPrefix_ShortString(t *testing.T) {
	assert.Equal(t, "ABC", StripTINITPrefix("ABC"))
}

// ── BuildPKCEPair ─────────────────────────────────────────────────────────────

func TestBuildPKCEPair_Deterministic(t *testing.T) {
	c1 := BuildPKCEPair("my-verifier")
	c2 := BuildPKCEPair("my-verifier")
	assert.Equal(t, c1, c2)
}

func TestBuildPKCEPair_DifferentVerifiersDifferentChallenges(t *testing.T) {
	c1 := BuildPKCEPair("verifier-aaa")
	c2 := BuildPKCEPair("verifier-bbb")
	assert.NotEqual(t, c1, c2)
}

func TestBuildPKCEPair_IsBase64URLNoPadding(t *testing.T) {
	c := BuildPKCEPair("some-verifier")
	assert.NotContains(t, c, "=", "PKCE challenge must be unpadded base64url")
	assert.NotContains(t, c, "+")
	assert.NotContains(t, c, "/")
}

// ── BuildAuthzURL ─────────────────────────────────────────────────────────────

func TestBuildAuthzURL_ReturnsValidURL(t *testing.T) {
	authzURL, codeChallenge := BuildAuthzURL(
		"preproduction",
		"my-client-id",
		"https://app.example.com/callback",
		"state-123",
		"nonce-456",
		"my-verifier",
	)

	u, err := url.Parse(authzURL)
	require.NoError(t, err)

	q := u.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "my-client-id", q.Get("client_id"))
	assert.Equal(t, "https://app.example.com/callback", q.Get("redirect_uri"))
	assert.Equal(t, "state-123", q.Get("state"))
	assert.Equal(t, "nonce-456", q.Get("nonce"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, codeChallenge, q.Get("code_challenge"))
	assert.NotEmpty(t, codeChallenge)
}

func TestBuildAuthzURL_CodeChallengeMatchesBuildPKCEPair(t *testing.T) {
	verifier := "test-code-verifier"
	_, codeChallenge := BuildAuthzURL("preproduction", "cid", "https://x.com/cb", "s", "n", verifier)
	expected := BuildPKCEPair(verifier)
	assert.Equal(t, expected, codeChallenge)
}

func TestBuildAuthzURL_DefaultScopesIncluded(t *testing.T) {
	authzURL, _ := BuildAuthzURL("preproduction", "cid", "https://x.com/cb", "s", "n", "v")
	assert.Contains(t, authzURL, "openid")
	assert.Contains(t, authzURL, "profile")
}

func TestBuildAuthzURL_AdditionalScopesAppended(t *testing.T) {
	authzURL, _ := BuildAuthzURL("preproduction", "cid", "https://x.com/cb", "s", "n", "v", "email", "fiscal_code")
	u, _ := url.Parse(authzURL)
	scope := u.Query().Get("scope")
	assert.Contains(t, scope, "email")
	assert.Contains(t, scope, "fiscal_code")
}

// ── ExtractFiscalNumber ───────────────────────────────────────────────────────

func TestExtractFiscalNumber_WithTINITPrefix(t *testing.T) {
	claims := map[string]interface{}{
		"fiscal_number": "TINIT-RSSMRA80A01H501Z",
	}
	assert.Equal(t, "RSSMRA80A01H501Z", ExtractFiscalNumber(claims))
}

func TestExtractFiscalNumber_WithoutPrefix(t *testing.T) {
	claims := map[string]interface{}{
		"fiscal_number": "RSSMRA80A01H501Z",
	}
	assert.Equal(t, "RSSMRA80A01H501Z", ExtractFiscalNumber(claims))
}

func TestExtractFiscalNumber_MissingClaim(t *testing.T) {
	assert.Equal(t, "", ExtractFiscalNumber(map[string]interface{}{}))
}

// ── ExtractEmail ──────────────────────────────────────────────────────────────

func TestExtractEmail_ReturnsEmailIfPresent(t *testing.T) {
	claims := map[string]interface{}{"email": "alice@example.com"}
	email, synthetic := ExtractEmail(claims, "CF123")
	assert.Equal(t, "alice@example.com", email)
	assert.True(t, synthetic, "email present in claims → synthetic=true (real)")
}

func TestExtractEmail_SyntheticFromFiscalNumber(t *testing.T) {
	claims := map[string]interface{}{}
	email, synthetic := ExtractEmail(claims, "RSSMRA80A01H501Z")
	assert.Equal(t, "RSSMRA80A01H501Z@cie.internal", email)
	assert.False(t, synthetic)
}

func TestExtractEmail_EmptyIfNoClaims(t *testing.T) {
	email, synthetic := ExtractEmail(map[string]interface{}{}, "")
	assert.Equal(t, "", email)
	assert.False(t, synthetic)
}

// ── ParseUserInfo ─────────────────────────────────────────────────────────────

func TestParseUserInfo_FullClaims(t *testing.T) {
	claims := map[string]interface{}{
		"fiscal_number": "TINIT-RSSMRA80A01H501Z",
		"given_name":    "Mario",
		"family_name":   "Rossi",
		"birthdate":     "1980-01-01",
		"gender":        "M",
		"email":         "mario.rossi@example.com",
	}

	info := ParseUserInfo(claims)

	assert.Equal(t, "RSSMRA80A01H501Z", info.FiscalNumber)
	assert.Equal(t, "Mario", info.FirstName)
	assert.Equal(t, "Rossi", info.LastName)
	assert.Equal(t, "1980-01-01", info.DateOfBirth)
	assert.Equal(t, "M", info.Gender)
	assert.Equal(t, "mario.rossi@example.com", info.Email)
	assert.False(t, info.EmailSynthetic, "real email should not be marked synthetic")
}

func TestParseUserInfo_MissingEmail_UsesSynthetic(t *testing.T) {
	claims := map[string]interface{}{
		"fiscal_number": "TINIT-RSSMRA80A01H501Z",
		"given_name":    "Mario",
		"family_name":   "Rossi",
	}

	info := ParseUserInfo(claims)
	assert.Equal(t, "RSSMRA80A01H501Z@cie.internal", info.Email)
	assert.True(t, info.EmailSynthetic)
}

func TestParseUserInfo_EmptyClaims_NoPanic(t *testing.T) {
	info := ParseUserInfo(map[string]interface{}{})
	assert.NotNil(t, info)
	assert.Empty(t, info.FiscalNumber)
	assert.Empty(t, info.Email)
}
