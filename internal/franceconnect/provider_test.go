package franceconnect

import (
	"net/url"
	"strings"
	"testing"
)

// ── GetEndpoints ──────────────────────────────────────────────────────────────

func TestGetEndpoints_Sandbox(t *testing.T) {
	eps := GetEndpoints("sandbox")
	if !strings.Contains(eps.AuthorizationURL, "integ01") {
		t.Errorf("sandbox AuthorizationURL should contain integ01, got %q", eps.AuthorizationURL)
	}
	if !strings.Contains(eps.TokenURL, "integ01") {
		t.Errorf("sandbox TokenURL should contain integ01, got %q", eps.TokenURL)
	}
}

func TestGetEndpoints_Production(t *testing.T) {
	eps := GetEndpoints("production")
	if strings.Contains(eps.AuthorizationURL, "integ01") {
		t.Errorf("production AuthorizationURL should not contain integ01, got %q", eps.AuthorizationURL)
	}
	if !strings.Contains(eps.AuthorizationURL, "franceconnect.gouv.fr") {
		t.Errorf("production AuthorizationURL should contain franceconnect.gouv.fr, got %q", eps.AuthorizationURL)
	}
}

func TestGetEndpoints_UnknownFallsBackToSandbox(t *testing.T) {
	eps := GetEndpoints("unknown-env")
	sandbox := GetEndpoints("sandbox")
	if eps.AuthorizationURL != sandbox.AuthorizationURL {
		t.Errorf("unknown env should fall back to sandbox, got %q", eps.AuthorizationURL)
	}
}

// ── EnvFromTokenURL ───────────────────────────────────────────────────────────

func TestEnvFromTokenURL_Sandbox(t *testing.T) {
	sandboxURL := "https://fcp.integ01.dev-franceconnect.fr/api/v2/token"
	if got := EnvFromTokenURL(sandboxURL); got != "sandbox" {
		t.Errorf("EnvFromTokenURL(%q) = %q, want sandbox", sandboxURL, got)
	}
}

func TestEnvFromTokenURL_Production(t *testing.T) {
	prodURL := "https://app.franceconnect.gouv.fr/api/v2/token"
	if got := EnvFromTokenURL(prodURL); got != "production" {
		t.Errorf("EnvFromTokenURL(%q) = %q, want production", prodURL, got)
	}
}

// ── BuildPKCEPair ─────────────────────────────────────────────────────────────

func TestBuildPKCEPair_Deterministic(t *testing.T) {
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	c1 := BuildPKCEPair(v)
	c2 := BuildPKCEPair(v)
	if c1 != c2 {
		t.Errorf("BuildPKCEPair not deterministic: %q vs %q", c1, c2)
	}
}

func TestBuildPKCEPair_NoEqualPadding(t *testing.T) {
	// S256 challenge must use raw base64url (no '=' padding per RFC 7636 §4.2).
	challenge := BuildPKCEPair("anything")
	if strings.Contains(challenge, "=") {
		t.Errorf("PKCE challenge must not contain padding '=', got %q", challenge)
	}
	if strings.Contains(challenge, "+") || strings.Contains(challenge, "/") {
		t.Errorf("PKCE challenge must use URL-safe alphabet, got %q", challenge)
	}
}

func TestBuildPKCEPair_KnownVector(t *testing.T) {
	// RFC 7636 §B appendix test vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := BuildPKCEPair(verifier); got != want {
		t.Errorf("BuildPKCEPair RFC vector: got %q, want %q", got, want)
	}
}

// ── SynthesiseEmail ───────────────────────────────────────────────────────────

func TestSynthesiseEmail_Deterministic(t *testing.T) {
	sub := "abc123-pseudo-sub"
	e1 := SynthesiseEmail(sub)
	e2 := SynthesiseEmail(sub)
	if e1 != e2 {
		t.Errorf("SynthesiseEmail not deterministic: %q vs %q", e1, e2)
	}
}

func TestSynthesiseEmail_NoPII(t *testing.T) {
	sub := "abc123-pseudo-sub"
	email := SynthesiseEmail(sub)
	if !strings.HasSuffix(email, "@fc.clavex.invalid") {
		t.Errorf("synthesised email should end with @fc.clavex.invalid, got %q", email)
	}
	if strings.Contains(email, sub) {
		t.Errorf("synthesised email must not contain raw sub, got %q", email)
	}
}

func TestSynthesiseEmail_DifferentSubsDifferentEmails(t *testing.T) {
	e1 := SynthesiseEmail("sub-alice")
	e2 := SynthesiseEmail("sub-bob")
	if e1 == e2 {
		t.Errorf("different subs produced same email: %q", e1)
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
		"eidas1",
	)

	parsed, err := url.Parse(authzURL)
	if err != nil {
		t.Fatalf("BuildAuthzURL returned unparseable URL: %v", err)
	}
	q := parsed.Query()

	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "my-client-id",
		"redirect_uri":          "https://example.com/callback",
		"state":                 "state123",
		"nonce":                 "nonce456",
		"acr_values":            "eidas1",
		"code_challenge_method": "S256",
		"code_challenge":        challenge,
	}
	for param, want := range checks {
		if got := q.Get(param); got != want {
			t.Errorf("param %q: got %q, want %q", param, got, want)
		}
	}

	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope must contain 'openid', got %q", q.Get("scope"))
	}
}

func TestBuildAuthzURL_DefaultAcrValues(t *testing.T) {
	authzURL, _ := BuildAuthzURL("sandbox", "cid", "https://cb", "s", "n", "v", "")
	parsed, _ := url.Parse(authzURL)
	if got := parsed.Query().Get("acr_values"); got != "eidas1" {
		t.Errorf("empty acrValues should default to eidas1, got %q", got)
	}
}

func TestBuildAuthzURL_AdditionalScopes(t *testing.T) {
	authzURL, _ := BuildAuthzURL("sandbox", "cid", "https://cb", "s", "n", "v", "eidas1", "phone", "address")
	parsed, _ := url.Parse(authzURL)
	scope := parsed.Query().Get("scope")
	if !strings.Contains(scope, "phone") {
		t.Errorf("additional scope 'phone' not found in %q", scope)
	}
	if !strings.Contains(scope, "address") {
		t.Errorf("additional scope 'address' not found in %q", scope)
	}
}

func TestBuildAuthzURL_SandboxHost(t *testing.T) {
	authzURL, _ := BuildAuthzURL("sandbox", "c", "https://cb", "s", "n", "v", "eidas1")
	if !strings.Contains(authzURL, "integ01") {
		t.Errorf("sandbox URL should route to integ01 host, got %q", authzURL)
	}
}

func TestBuildAuthzURL_ProductionHost(t *testing.T) {
	authzURL, _ := BuildAuthzURL("production", "c", "https://cb", "s", "n", "v", "eidas2")
	if strings.Contains(authzURL, "integ01") {
		t.Errorf("production URL should not contain integ01, got %q", authzURL)
	}
	if !strings.Contains(authzURL, "franceconnect.gouv.fr") {
		t.Errorf("production URL should contain franceconnect.gouv.fr, got %q", authzURL)
	}
}

// ── ParseUserInfo ─────────────────────────────────────────────────────────────

func TestParseUserInfo_AllFields(t *testing.T) {
	claims := map[string]interface{}{
		"sub":         "urn:fr:fc:sub:abc123",
		"email":       "alice@example.fr",
		"given_name":  "Alice",
		"family_name": "Martin",
		"birthdate":   "1990-01-15",
		"gender":      "female",
	}
	u := ParseUserInfo(claims)
	if u.Sub != "urn:fr:fc:sub:abc123" {
		t.Errorf("Sub: got %q", u.Sub)
	}
	if u.Email != "alice@example.fr" {
		t.Errorf("Email: got %q", u.Email)
	}
	if u.FirstName != "Alice" {
		t.Errorf("FirstName: got %q", u.FirstName)
	}
	if u.LastName != "Martin" {
		t.Errorf("LastName: got %q", u.LastName)
	}
	if u.Birthdate != "1990-01-15" {
		t.Errorf("Birthdate: got %q", u.Birthdate)
	}
	if u.Gender != "female" {
		t.Errorf("Gender: got %q", u.Gender)
	}
}

func TestParseUserInfo_EmptyEmailOnNoConsent(t *testing.T) {
	// FC users that don't consent to email scope will have no "email" claim.
	claims := map[string]interface{}{
		"sub":         "urn:fr:fc:sub:xyz789",
		"given_name":  "Bob",
		"family_name": "Dupont",
	}
	u := ParseUserInfo(claims)
	if u.Sub == "" {
		t.Error("Sub must be set even without email")
	}
	if u.Email != "" {
		t.Errorf("Email should be empty when not in claims, got %q", u.Email)
	}
}

func TestParseUserInfo_NonStringFieldsIgnored(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   42, // wrong type
		"email": true,
	}
	u := ParseUserInfo(claims)
	if u.Sub != "" {
		t.Errorf("non-string sub should yield empty string, got %q", u.Sub)
	}
	if u.Email != "" {
		t.Errorf("non-string email should yield empty string, got %q", u.Email)
	}
}
