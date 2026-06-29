package bundid

import (
	"net/url"
	"strings"
	"testing"
)

// ── GetEndpoints ──────────────────────────────────────────────────────────────

func TestGetEndpoints_Production(t *testing.T) {
	eps := GetEndpoints("production")
	if !strings.Contains(eps.AuthorizationURL, "id.bund.de") {
		t.Errorf("production AuthorizationURL should contain id.bund.de, got %q", eps.AuthorizationURL)
	}
	if strings.Contains(eps.AuthorizationURL, "int.") {
		t.Errorf("production AuthorizationURL should not contain int., got %q", eps.AuthorizationURL)
	}
}

func TestGetEndpoints_Integration(t *testing.T) {
	eps := GetEndpoints("integration")
	if !strings.Contains(eps.AuthorizationURL, "int.id.bund.de") {
		t.Errorf("integration AuthorizationURL should contain int.id.bund.de, got %q", eps.AuthorizationURL)
	}
}

func TestGetEndpoints_UnknownFallsBackToIntegration(t *testing.T) {
	eps := GetEndpoints("unknown")
	want := GetEndpoints("integration")
	if eps.AuthorizationURL != want.AuthorizationURL {
		t.Errorf("unknown env should fall back to integration, got %q", eps.AuthorizationURL)
	}
}

// ── BuildAuthzURL ─────────────────────────────────────────────────────────────

func TestBuildAuthzURL_RequiredParams(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	authzURL := BuildAuthzURL("integration", "client-de", "https://rp.example.de/cb", "st1", "nc1", verifier, "")

	parsed, err := url.Parse(authzURL)
	if err != nil {
		t.Fatalf("BuildAuthzURL returned unparseable URL: %v", err)
	}
	q := parsed.Query()

	want := map[string]string{
		"response_type":         "code",
		"client_id":             "client-de",
		"redirect_uri":          "https://rp.example.de/cb",
		"state":                 "st1",
		"nonce":                 "nc1",
		"code_challenge_method": "S256",
		"code_challenge":        BuildPKCEPair(verifier),
	}
	for param, wantVal := range want {
		if got := q.Get(param); got != wantVal {
			t.Errorf("param %q: got %q, want %q", param, got, wantVal)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope must contain 'openid', got %q", q.Get("scope"))
	}
}

func TestBuildAuthzURL_AcrValuesLoAHigh(t *testing.T) {
	authzURL := BuildAuthzURL("integration", "c", "https://cb", "s", "n", "v", LoAHigh)
	parsed, _ := url.Parse(authzURL)
	if got := parsed.Query().Get("acr_values"); got != LoAHigh {
		t.Errorf("acr_values: got %q, want %q", got, LoAHigh)
	}
}

func TestBuildAuthzURL_EmptyAcrValuesOmitted(t *testing.T) {
	authzURL := BuildAuthzURL("integration", "c", "https://cb", "s", "n", "v", "")
	parsed, _ := url.Parse(authzURL)
	if got := parsed.Query().Get("acr_values"); got != "" {
		t.Errorf("empty acrValues should be omitted, got %q", got)
	}
}

func TestBuildAuthzURL_ProductionHost(t *testing.T) {
	authzURL := BuildAuthzURL("production", "c", "https://cb", "s", "n", "v", "")
	if strings.Contains(authzURL, "int.") {
		t.Errorf("production URL should not contain int., got %q", authzURL)
	}
	if !strings.Contains(authzURL, "id.bund.de") {
		t.Errorf("production URL should contain id.bund.de, got %q", authzURL)
	}
}

// ── ParseUserInfo ─────────────────────────────────────────────────────────────

func TestParseUserInfo_AllFields(t *testing.T) {
	claims := map[string]interface{}{
		"sub":            "de-sub-abc123",
		"email":          "max@example.de",
		"given_name":     "Max",
		"family_name":    "Mustermann",
		"birthdate":      "1985-03-22",
		"place_of_birth": "Berlin",
	}
	u := ParseUserInfo(claims)
	if u.Sub != "de-sub-abc123" {
		t.Errorf("Sub: got %q", u.Sub)
	}
	if u.Email != "max@example.de" || u.EmailSynthetic {
		t.Errorf("Email: got %q synthetic=%v", u.Email, u.EmailSynthetic)
	}
	if u.FirstName != "Max" {
		t.Errorf("FirstName: got %q", u.FirstName)
	}
	if u.LastName != "Mustermann" {
		t.Errorf("LastName: got %q", u.LastName)
	}
	if u.Birthdate != "1985-03-22" {
		t.Errorf("Birthdate: got %q", u.Birthdate)
	}
	if u.PlaceOfBirth != "Berlin" {
		t.Errorf("PlaceOfBirth: got %q", u.PlaceOfBirth)
	}
}

func TestParseUserInfo_SyntheticEmailWhenNoEmail(t *testing.T) {
	claims := map[string]interface{}{"sub": "de-sub-xyz"}
	u := ParseUserInfo(claims)
	if !u.EmailSynthetic {
		t.Error("EmailSynthetic should be true when no email in claims")
	}
	if !strings.HasSuffix(u.Email, "@bundid.internal") {
		t.Errorf("synthetic email should end with @bundid.internal, got %q", u.Email)
	}
	// sub may be used directly as local-part; that is acceptable as long as it ends in @bundid.internal
}

func TestParseUserInfo_EmptyClaimsNoSub(t *testing.T) {
	u := ParseUserInfo(map[string]interface{}{})
	if u.Email != "" {
		t.Errorf("empty claims with no sub: expected empty email, got %q", u.Email)
	}
	if u.EmailSynthetic {
		t.Error("EmailSynthetic should be false when no sub either")
	}
}
