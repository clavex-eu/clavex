package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Fake ClientLookup ────────────────────────────────────────────────────────

type fakeClientLookup struct {
	client *models.OIDCClient
	err    error
}

func (f *fakeClientLookup) GetByClientID(_ context.Context, _ string) (*models.OIDCClient, error) {
	return f.client, f.err
}

// ── Helpers ──────────────────────────────────────────────────────────────────

var testOrgID = uuid.New()

func confidentialClient(redirectURIs ...string) *models.OIDCClient {
	secret := "hashed-secret"
	return &models.OIDCClient{
		OrgID:            testOrgID,
		IsActive:         true,
		ClientSecretHash: &secret,
		RedirectURIs:     redirectURIs,
	}
}

func publicClient(redirectURIs ...string) *models.OIDCClient {
	return &models.OIDCClient{
		OrgID:                   testOrgID,
		IsActive:                true,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            redirectURIs,
	}
}

func callValidate(clients ClientLookup, extraParams map[string]string) (*AuthorizeRequest, *AuthorizeError) {
	params := map[string]string{
		"client_id":     "test-client",
		"redirect_uri":  "https://app.example.com/callback",
		"response_type": "code",
		"scope":         "openid",
		"state":         "state-xyz",
	}
	for k, v := range extraParams {
		params[k] = v
	}
	return ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), clients, false)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestValidateAuthorizeRequest_MissingClientID(t *testing.T) {
	lkp := &fakeClientLookup{client: confidentialClient("https://app.example.com/callback")}
	_, authErr := ValidateAuthorizeRequest(context.Background(), map[string]string{}, "org", testOrgID.String(), lkp, false)
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_request", authErr.Code)
}

func TestValidateAuthorizeRequest_UnknownClient(t *testing.T) {
	lkp := &fakeClientLookup{err: errors.New("not found")}
	_, authErr := callValidate(lkp, nil)
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_request", authErr.Code)
}

func TestValidateAuthorizeRequest_InactiveClient(t *testing.T) {
	c := confidentialClient("https://app.example.com/callback")
	c.IsActive = false
	_, authErr := callValidate(&fakeClientLookup{client: c}, nil)
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_request", authErr.Code)
}

func TestValidateAuthorizeRequest_WrongOrg(t *testing.T) {
	c := confidentialClient("https://app.example.com/callback")
	c.OrgID = uuid.New() // different org
	_, authErr := callValidate(&fakeClientLookup{client: c}, nil)
	require.NotNil(t, authErr)
	assert.Equal(t, "unauthorized_client", authErr.Code)
}

func TestValidateAuthorizeRequest_BadRedirectURI(t *testing.T) {
	lkp := &fakeClientLookup{client: confidentialClient("https://other.example.com/callback")}
	_, authErr := callValidate(lkp, nil)
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_request", authErr.Code)
}

func TestValidateAuthorizeRequest_UnsupportedResponseType(t *testing.T) {
	lkp := &fakeClientLookup{client: confidentialClient("https://app.example.com/callback")}
	_, authErr := callValidate(lkp, map[string]string{"response_type": "token"})
	require.NotNil(t, authErr)
	assert.Equal(t, "unsupported_response_type", authErr.Code)
}

func TestValidateAuthorizeRequest_MissingOpenIDScope(t *testing.T) {
	lkp := &fakeClientLookup{client: confidentialClient("https://app.example.com/callback")}
	_, authErr := callValidate(lkp, map[string]string{"scope": "email"})
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_scope", authErr.Code)
}

func TestValidateAuthorizeRequest_PKCERequired_PublicClient(t *testing.T) {
	lkp := &fakeClientLookup{client: publicClient("https://app.example.com/callback")}
	// no code_challenge → must fail for public clients
	_, authErr := callValidate(lkp, nil)
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_request", authErr.Code)
	assert.Contains(t, authErr.Description, "PKCE")
}

func TestValidateAuthorizeRequest_PKCEPlainRejected(t *testing.T) {
	lkp := &fakeClientLookup{client: publicClient("https://app.example.com/callback")}
	_, authErr := callValidate(lkp, map[string]string{
		"code_challenge":        "somechallenge",
		"code_challenge_method": "plain",
	})
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_request", authErr.Code)
	assert.Contains(t, authErr.Description, "S256")
}

func TestValidateAuthorizeRequest_Success_ConfidentialClient(t *testing.T) {
	lkp := &fakeClientLookup{client: confidentialClient("https://app.example.com/callback")}
	req, authErr := callValidate(lkp, nil)
	require.Nil(t, authErr)
	require.NotNil(t, req)
	assert.Equal(t, "test-client", req.ClientID)
	assert.Equal(t, "https://app.example.com/callback", req.RedirectURI)
	assert.Equal(t, "state-xyz", req.State)
	assert.Equal(t, "openid", req.Scope)
	assert.False(t, req.IsPublicClient)
}

func TestValidateAuthorizeRequest_Success_PublicClientWithPKCE(t *testing.T) {
	lkp := &fakeClientLookup{client: publicClient("https://app.example.com/callback")}
	req, authErr := callValidate(lkp, map[string]string{
		"code_challenge":        hashString("my-code-verifier"),
		"code_challenge_method": "S256",
		"nonce":                 "nonce-abc",
	})
	require.Nil(t, authErr)
	require.NotNil(t, req)
	assert.True(t, req.IsPublicClient)
	assert.Equal(t, hashString("my-code-verifier"), req.PKCEChallenge)
	assert.Equal(t, "S256", req.PKCEMethod)
	assert.Equal(t, "nonce-abc", req.Nonce)
}

// TestValidateAuthorizeRequest_EmptyScope verifies that a request without a scope
// parameter is accepted as a plain OAuth2/VCI flow (scope stays empty; no
// auto-default to "openid").  An id_token will not be issued for empty-scope
// exchanges, which is the correct behaviour per OIDC Core §3.1.2.1.
func TestValidateAuthorizeRequest_EmptyScope(t *testing.T) {
	lkp := &fakeClientLookup{client: confidentialClient("https://app.example.com/callback")}
	params := map[string]string{
		"client_id":     "test-client",
		"redirect_uri":  "https://app.example.com/callback",
		"response_type": "code",
		// no scope → plain OAuth2/VCI flow; scope stays empty
	}
	req, authErr := ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), lkp, false)
	require.Nil(t, authErr)
	assert.Equal(t, "", req.Scope)
}

// TestValidateAuthorizeRequest_OID4VCI_NoOpenIDScope verifies that when
// authorization_details is present (OID4VCI flow), openid scope is not
// required and the request is accepted with an empty scope.
func TestValidateAuthorizeRequest_OID4VCI_NoOpenIDScope(t *testing.T) {
	lkp := &fakeClientLookup{client: confidentialClient("https://app.example.com/callback")}

	// authorization_details present, no scope → must succeed (OID4VCI openid=false).
	params := map[string]string{
		"client_id":             "test-client",
		"redirect_uri":          "https://app.example.com/callback",
		"response_type":         "code",
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
		"authorization_details": `[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential"}]`,
	}
	req, authErr := ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), lkp, false)
	require.Nil(t, authErr)
	// Scope must NOT be silently defaulted to "openid".
	assert.NotContains(t, req.Scope, "openid")

	// authorization_details + openid scope → still accepted (OID4VCI openid=openid_connect).
	params["scope"] = "openid"
	req2, authErr2 := ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), lkp, false)
	require.Nil(t, authErr2)
	assert.Equal(t, "openid", req2.Scope)
}


func TestValidateAuthorizeRequest_FAPI2_RequiresPAR(t *testing.T) {
	c := confidentialClient("https://app.example.com/callback")
	c.RequestObjectSigningAlg = "PS256"
	lkp := &fakeClientLookup{client: c}

	// Without a request object → must be rejected (FAPI 2.0 §5.2.2).
	_, authErr := callValidate(lkp, nil)
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_request", authErr.Code)
	assert.NotEmpty(t, authErr.RedirectURI) // redirectable error

	// With requestObjectProcessed=true (PAR or JAR) → accepted.
	params := map[string]string{
		"client_id":             "test-client",
		"redirect_uri":          "https://app.example.com/callback",
		"response_type":         "code",
		"scope":                 "openid",
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
	}
	req, authErr2 := ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), lkp, true)
	require.Nil(t, authErr2)
	require.NotNil(t, req)
}

func TestValidateAuthorizeRequest_RejectsSubInRequestObject(t *testing.T) {
	c := confidentialClient("https://app.example.com/callback")
	lkp := &fakeClientLookup{client: c}

	// A request object carrying a sub claim must be rejected as
	// invalid_request_object, redirected back to the client (OIDF §12.1.1.1).
	params := map[string]string{
		"client_id":             "test-client",
		"redirect_uri":          "https://app.example.com/callback",
		"response_type":         "code",
		"scope":                 "openid",
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
		"sub":                   "test-client",
	}
	_, authErr := ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), lkp, true)
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_request_object", authErr.Code)
	assert.NotEmpty(t, authErr.RedirectURI) // redirectable error

	// Same params without requestObjectProcessed → sub is ignored (not a
	// request object), request is accepted.
	_, authErr2 := ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), lkp, false)
	require.Nil(t, authErr2)
}

func TestValidateAuthorizeRequest_SurfacesFederationJARPolicyError(t *testing.T) {
	c := confidentialClient("https://app.example.com/callback")
	lkp := &fakeClientLookup{client: c}

	// A federation request-object policy violation recorded by ParseJAR (here a
	// missing jti) must surface as a redirectable invalid_request_object error.
	params := map[string]string{
		"client_id":             "test-client",
		"redirect_uri":          "https://app.example.com/callback",
		"response_type":         "code",
		"scope":                 "openid",
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
		JARPolicyErrorKey:       "invalid_request_object",
		JARPolicyDescKey:        "request object is missing the required \"jti\" claim",
	}
	_, authErr := ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), lkp, true)
	require.NotNil(t, authErr)
	assert.Equal(t, "invalid_request_object", authErr.Code)
	assert.NotEmpty(t, authErr.RedirectURI) // redirectable

	// Without requestObjectProcessed the reserved key is ignored.
	_, authErr2 := ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), lkp, false)
	require.Nil(t, authErr2)
}

func TestValidateAuthorizeRequest_RequirePAR_Flag(t *testing.T) {
	// require_par=true without request_object_signing_alg (FAPI 2.0 §5.2.2-1).
	// Plain authorization request (no PAR, no JAR) must be rejected.
	c := confidentialClient("https://app.example.com/callback")
	c.RequirePAR = true
	// RequestObjectSigningAlg deliberately left empty to exercise the
	// require_par path independently.
	lkp := &fakeClientLookup{client: c}

	_, authErr := callValidate(lkp, nil)
	require.NotNil(t, authErr, "expected invalid_request when require_par=true and no PAR used")
	assert.Equal(t, "invalid_request", authErr.Code)

	// requestObjectProcessed=true (PAR used) → accepted.
	params := map[string]string{
		"client_id":             "test-client",
		"redirect_uri":          "https://app.example.com/callback",
		"response_type":         "code",
		"scope":                 "openid",
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
	}
	req, authErr2 := ValidateAuthorizeRequest(context.Background(), params, "test-org", testOrgID.String(), lkp, true)
	require.Nil(t, authErr2)
	require.NotNil(t, req)
}

func TestValidateAuthorizeRequest_HybridRejectedWhenNotRegistered(t *testing.T) {
	// A client registered with only response_types=["code"] must reject code id_token.
	c := confidentialClient("https://app.example.com/callback")
	c.ResponseTypes = []string{"code"}
	lkp := &fakeClientLookup{client: c}

	_, authErr := callValidate(lkp, map[string]string{"response_type": "code id_token"})
	require.NotNil(t, authErr)
	assert.Equal(t, "unsupported_response_type", authErr.Code)

	// The same client can use response_type=code just fine.
	req, authErr2 := callValidate(lkp, nil)
	require.Nil(t, authErr2)
	require.NotNil(t, req)
}

// ── resolveAcr ───────────────────────────────────────────────────────────────

func TestResolveAcr_EmptyReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", resolveAcr(""))
}

func TestResolveAcr_WhitespaceOnlyReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", resolveAcr("   "))
}

func TestSanitizeErrorDescription(t *testing.T) {
	// § (non-ASCII), double quotes and backslash are outside the RFC 6749
	// §4.1.2.1 charset and must be replaced with spaces; allowed punctuation and
	// parentheses are preserved.
	in := "missing \"jti\" claim (OpenID Federation §12.1.1.1)\\"
	out := SanitizeErrorDescription(in)
	for _, r := range out {
		ok := r == 0x09 || r == 0x0A || r == 0x0D ||
			(r >= 0x20 && r <= 0x21) || (r >= 0x23 && r <= 0x5B) || (r >= 0x5D && r <= 0x7E)
		require.Truef(t, ok, "char %q (0x%x) is outside the allowed set", r, r)
	}
	assert.NotContains(t, out, "\"")
	assert.NotContains(t, out, "§")
	assert.NotContains(t, out, "\\")
	assert.Contains(t, out, "12.1.1.1")
}

func TestResolveAcr_AnyValueReturnsZero(t *testing.T) {
	// Any non-empty acr_values → server satisfies with level "0" (password auth).
	assert.Equal(t, "0", resolveAcr("0"))
	assert.Equal(t, "0", resolveAcr("urn:mace:incommon:iap:bronze"))
	assert.Equal(t, "0", resolveAcr("eidas1 eidas2"))
}

