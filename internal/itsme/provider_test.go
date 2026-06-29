package itsme

import (
	"net/url"
	"strings"
	"testing"
)

// ── GetEndpoints ──────────────────────────────────────────────────────────────

func TestGetEndpoints_Sandbox(t *testing.T) {
	eps := GetEndpoints("sandbox")
	if !strings.Contains(eps.AuthorizationURL, "e2e") {
		t.Errorf("sandbox AuthorizationURL should contain e2e, got %q", eps.AuthorizationURL)
	}
	if !strings.Contains(eps.TokenURL, "e2e") {
		t.Errorf("sandbox TokenURL should contain e2e, got %q", eps.TokenURL)
	}
}

func TestGetEndpoints_Production(t *testing.T) {
	eps := GetEndpoints("production")
	if strings.Contains(eps.AuthorizationURL, "e2e") {
		t.Errorf("production AuthorizationURL should not contain e2e, got %q", eps.AuthorizationURL)
	}
	if !strings.Contains(eps.AuthorizationURL, "prd.itsme.services") {
		t.Errorf("production AuthorizationURL should contain prd.itsme.services, got %q", eps.AuthorizationURL)
	}
}

func TestGetEndpoints_UnknownFallsBackToSandbox(t *testing.T) {
	eps := GetEndpoints("nope")
	sandbox := GetEndpoints("sandbox")
	if eps.TokenURL != sandbox.TokenURL {
		t.Errorf("unknown env should fall back to sandbox, got %q", eps.TokenURL)
	}
}

// ── EnvFromTokenURL ───────────────────────────────────────────────────────────

func TestEnvFromTokenURL_Sandbox(t *testing.T) {
	sandboxURL := "https://idp.e2e.itsme.services/v2/token"
	if got := EnvFromTokenURL(sandboxURL); got != "sandbox" {
		t.Errorf("EnvFromTokenURL(%q) = %q, want sandbox", sandboxURL, got)
	}
}

func TestEnvFromTokenURL_Production(t *testing.T) {
	prodURL := "https://idp.prd.itsme.services/v2/token"
	if got := EnvFromTokenURL(prodURL); got != "production" {
		t.Errorf("EnvFromTokenURL(%q) = %q, want production", prodURL, got)
	}
}

// ── BuildPKCEPair ─────────────────────────────────────────────────────────────

func TestBuildPKCEPair_KnownVector(t *testing.T) {
	// RFC 7636 §B test vector — same hash logic as FranceConnect.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := BuildPKCEPair(verifier); got != want {
		t.Errorf("BuildPKCEPair: got %q, want %q", got, want)
	}
}

func TestBuildPKCEPair_NoEqualPadding(t *testing.T) {
	challenge := BuildPKCEPair("some-verifier")
	if strings.Contains(challenge, "=") {
		t.Errorf("PKCE challenge must not contain padding '=', got %q", challenge)
	}
}

// ── LoA constants ─────────────────────────────────────────────────────────────

func TestLoAConstants(t *testing.T) {
	if LoA2 == "" || LoA3 == "" {
		t.Error("LoA constants must not be empty")
	}
	if LoA2 == LoA3 {
		t.Error("LoA2 and LoA3 must be distinct")
	}
	// itsme uses eIDAS URIs for assurance levels.
	if !strings.Contains(LoA2, "eidas") {
		t.Errorf("LoA2 should be an eIDAS URI, got %q", LoA2)
	}
	if !strings.Contains(LoA3, "eidas") {
		t.Errorf("LoA3 should be an eIDAS URI, got %q", LoA3)
	}
}

// ── BuildAuthzURL ─────────────────────────────────────────────────────────────

func TestBuildAuthzURL_RequiredParams(t *testing.T) {
	authzURL, challenge := BuildAuthzURL(
		"sandbox",
		"my-client-id",
		"https://example.com/callback",
		"state123",
		"nonce456",
		"verifier789",
		"MY_SERVICE_CODE",
		LoA2,
	)

	parsed, err := url.Parse(authzURL)
	if err != nil {
		t.Fatalf("unparseable URL: %v", err)
	}
	q := parsed.Query()

	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "my-client-id",
		"redirect_uri":          "https://example.com/callback",
		"state":                 "state123",
		"nonce":                 "nonce456",
		"service_code":          "MY_SERVICE_CODE",
		"acr_values":            LoA2,
		"code_challenge_method": "S256",
		"code_challenge":        challenge,
	}
	for param, want := range checks {
		if got := q.Get(param); got != want {
			t.Errorf("param %q: got %q, want %q", param, got, want)
		}
	}
}

func TestBuildAuthzURL_ServiceCodeRequired(t *testing.T) {
	// service_code must be present even if empty string is passed;
	// itsme will reject the request, but we make sure it's always set.
	authzURL, _ := BuildAuthzURL("sandbox", "cid", "https://cb", "s", "n", "v", "MYCODE", LoA2)
	parsed, _ := url.Parse(authzURL)
	if got := parsed.Query().Get("service_code"); got != "MYCODE" {
		t.Errorf("service_code: got %q, want MYCODE", got)
	}
}

func TestBuildAuthzURL_DefaultAcrLoA2(t *testing.T) {
	authzURL, _ := BuildAuthzURL("sandbox", "cid", "https://cb", "s", "n", "v", "CODE", "")
	parsed, _ := url.Parse(authzURL)
	if got := parsed.Query().Get("acr_values"); got != LoA2 {
		t.Errorf("empty acr should default to LoA2, got %q", got)
	}
}

func TestBuildAuthzURL_SandboxHost(t *testing.T) {
	authzURL, _ := BuildAuthzURL("sandbox", "c", "https://cb", "s", "n", "v", "CODE", LoA2)
	if !strings.Contains(authzURL, "e2e.itsme.services") {
		t.Errorf("sandbox URL should contain e2e.itsme.services, got %q", authzURL)
	}
}

func TestBuildAuthzURL_ProductionHost(t *testing.T) {
	authzURL, _ := BuildAuthzURL("production", "c", "https://cb", "s", "n", "v", "CODE", LoA3)
	if strings.Contains(authzURL, "e2e") {
		t.Errorf("production URL should not contain e2e, got %q", authzURL)
	}
	if !strings.Contains(authzURL, "prd.itsme.services") {
		t.Errorf("production URL should contain prd.itsme.services, got %q", authzURL)
	}
}

func TestBuildAuthzURL_AdditionalScopes(t *testing.T) {
	authzURL, _ := BuildAuthzURL("sandbox", "cid", "https://cb", "s", "n", "v", "CODE", LoA2, "address", "phone")
	parsed, _ := url.Parse(authzURL)
	scope := parsed.Query().Get("scope")
	if !strings.Contains(scope, "address") {
		t.Errorf("additional scope 'address' not in %q", scope)
	}
	if !strings.Contains(scope, "phone") {
		t.Errorf("additional scope 'phone' not in %q", scope)
	}
}

// ── ParseUserInfo ─────────────────────────────────────────────────────────────

func TestParseUserInfo_AllFields(t *testing.T) {
	claims := map[string]interface{}{
		"sub":          "urn:be:itsme:sub:abc123",
		"email":        "jan@example.be",
		"given_name":   "Jan",
		"family_name":  "De Smedt",
		"birthdate":    "1985-06-20",
		"phone_number": "+32470123456",
	}
	u := ParseUserInfo(claims)
	if u.Sub != "urn:be:itsme:sub:abc123" {
		t.Errorf("Sub: got %q", u.Sub)
	}
	if u.Email != "jan@example.be" {
		t.Errorf("Email: got %q", u.Email)
	}
	if u.FirstName != "Jan" {
		t.Errorf("FirstName: got %q", u.FirstName)
	}
	if u.LastName != "De Smedt" {
		t.Errorf("LastName: got %q", u.LastName)
	}
	if u.Birthdate != "1985-06-20" {
		t.Errorf("Birthdate: got %q", u.Birthdate)
	}
	if u.PhoneNumber != "+32470123456" {
		t.Errorf("PhoneNumber: got %q", u.PhoneNumber)
	}
}

func TestParseUserInfo_PseudonymousSub(t *testing.T) {
	// itsme sub is per-service pseudonymous — must survive round-trip through ParseUserInfo.
	pseudo := "urn:be:itsme:abc:00000000-dead-beef-0000-000000000000"
	claims := map[string]interface{}{"sub": pseudo, "email": "x@x.be"}
	u := ParseUserInfo(claims)
	if u.Sub != pseudo {
		t.Errorf("pseudonymous sub not preserved: got %q, want %q", u.Sub, pseudo)
	}
}

func TestParseUserInfo_MissingEmail(t *testing.T) {
	// itsme email scope is optional.
	claims := map[string]interface{}{
		"sub":        "urn:be:itsme:sub:nomail",
		"given_name": "Marc",
	}
	u := ParseUserInfo(claims)
	if u.Sub == "" {
		t.Error("Sub must be set")
	}
	if u.Email != "" {
		t.Errorf("Email should be empty when absent, got %q", u.Email)
	}
}

func TestParseUserInfo_WrongTypes(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   123,   // number, not string
		"email": false, // bool, not string
	}
	u := ParseUserInfo(claims)
	if u.Sub != "" {
		t.Errorf("numeric sub should yield empty string, got %q", u.Sub)
	}
	if u.Email != "" {
		t.Errorf("bool email should yield empty string, got %q", u.Email)
	}
}
