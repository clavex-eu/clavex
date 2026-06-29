package clave

import (
	"net/url"
	"strings"
	"testing"
)

// ── GetEndpoints ──────────────────────────────────────────────────────────────

func TestGetEndpoints_Production(t *testing.T) {
	eps := GetEndpoints("production")
	if !strings.Contains(eps.AuthorizationURL, "clave.gob.es") {
		t.Errorf("production AuthorizationURL should contain clave.gob.es, got %q", eps.AuthorizationURL)
	}
	if strings.Contains(eps.AuthorizationURL, "preprod") {
		t.Errorf("production AuthorizationURL should not contain preprod, got %q", eps.AuthorizationURL)
	}
}

func TestGetEndpoints_Preproduction(t *testing.T) {
	eps := GetEndpoints("preproduction")
	if !strings.Contains(eps.AuthorizationURL, "preprod") {
		t.Errorf("preproduction AuthorizationURL should contain preprod, got %q", eps.AuthorizationURL)
	}
}

func TestGetEndpoints_UnknownFallsBackToPreproduction(t *testing.T) {
	eps := GetEndpoints("unknown")
	want := GetEndpoints("preproduction")
	if eps.AuthorizationURL != want.AuthorizationURL {
		t.Errorf("unknown env should fall back to preproduction, got %q", eps.AuthorizationURL)
	}
}

// ── BuildAuthzURL ─────────────────────────────────────────────────────────────

func TestBuildAuthzURL_RequiredParams(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	authzURL := BuildAuthzURL("preproduction", "client-es", "https://rp.example.es/cb", "st1", "nc1", verifier, "")

	parsed, err := url.Parse(authzURL)
	if err != nil {
		t.Fatalf("BuildAuthzURL returned unparseable URL: %v", err)
	}
	q := parsed.Query()

	want := map[string]string{
		"response_type":         "code",
		"client_id":             "client-es",
		"redirect_uri":          "https://rp.example.es/cb",
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

func TestBuildAuthzURL_AcrValuesHighLevel(t *testing.T) {
	authzURL := BuildAuthzURL("preproduction", "c", "https://cb", "s", "n", "v", LevelCertificate)
	parsed, _ := url.Parse(authzURL)
	if got := parsed.Query().Get("acr_values"); got != LevelCertificate {
		t.Errorf("acr_values: got %q, want %q", got, LevelCertificate)
	}
}

func TestBuildAuthzURL_EmptyAcrValuesOmitted(t *testing.T) {
	authzURL := BuildAuthzURL("preproduction", "c", "https://cb", "s", "n", "v", "")
	parsed, _ := url.Parse(authzURL)
	if got := parsed.Query().Get("acr_values"); got != "" {
		t.Errorf("empty acrValues should be omitted, got %q", got)
	}
}

func TestBuildAuthzURL_ProductionHost(t *testing.T) {
	authzURL := BuildAuthzURL("production", "c", "https://cb", "s", "n", "v", "")
	if strings.Contains(authzURL, "preprod") {
		t.Errorf("production URL should not contain preprod, got %q", authzURL)
	}
	if !strings.Contains(authzURL, "clave.gob.es") {
		t.Errorf("production URL should contain clave.gob.es, got %q", authzURL)
	}
}

// ── ParseUserInfo ─────────────────────────────────────────────────────────────

func TestParseUserInfo_AllFields(t *testing.T) {
	claims := map[string]interface{}{
		"sub":             "es-sub-abc123",
		"email":           "ana@example.es",
		"given_name":      "Ana",
		"family_name":     "García",
		"birthdate":       "1992-07-14",
		"document_number": "12345678Z",
	}
	u := ParseUserInfo(claims)
	if u.Sub != "es-sub-abc123" {
		t.Errorf("Sub: got %q", u.Sub)
	}
	if u.Email != "ana@example.es" || u.EmailSynthetic {
		t.Errorf("Email: got %q synthetic=%v", u.Email, u.EmailSynthetic)
	}
	if u.FirstName != "Ana" {
		t.Errorf("FirstName: got %q", u.FirstName)
	}
	if u.LastName != "García" {
		t.Errorf("LastName: got %q", u.LastName)
	}
	if u.Birthdate != "1992-07-14" {
		t.Errorf("Birthdate: got %q", u.Birthdate)
	}
	if u.DocumentNumber != "12345678Z" {
		t.Errorf("DocumentNumber: got %q", u.DocumentNumber)
	}
}

func TestParseUserInfo_SyntheticEmailFromDocumentNumber(t *testing.T) {
	claims := map[string]interface{}{
		"sub":             "es-sub-xyz",
		"document_number": "87654321A",
	}
	u := ParseUserInfo(claims)
	if !u.EmailSynthetic {
		t.Error("EmailSynthetic should be true when no email in claims")
	}
	if !strings.HasSuffix(u.Email, "@clave.internal") {
		t.Errorf("synthetic email should end with @clave.internal, got %q", u.Email)
	}
	if !strings.Contains(u.Email, "87654321A") {
		t.Errorf("synthetic email should use document_number as local part, got %q", u.Email)
	}
}

func TestParseUserInfo_SyntheticEmailFallsBackToSub(t *testing.T) {
	claims := map[string]interface{}{"sub": "es-sub-only"}
	u := ParseUserInfo(claims)
	if !u.EmailSynthetic {
		t.Error("EmailSynthetic should be true when no email or document_number")
	}
	if !strings.HasSuffix(u.Email, "@clave.internal") {
		t.Errorf("fallback email should end with @clave.internal, got %q", u.Email)
	}
}
