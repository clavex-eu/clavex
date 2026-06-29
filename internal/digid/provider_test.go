package digid

import (
	"net/url"
	"strings"
	"testing"
)

// ── GetEndpoints ──────────────────────────────────────────────────────────────

func TestGetEndpoints_Production(t *testing.T) {
	eps := GetEndpoints("production")
	if !strings.Contains(eps.AuthorizationURL, "authenticatie.digid.nl") {
		t.Errorf("production AuthorizationURL should contain authenticatie.digid.nl, got %q", eps.AuthorizationURL)
	}
	if strings.Contains(eps.AuthorizationURL, "acc") {
		t.Errorf("production AuthorizationURL should not contain acc, got %q", eps.AuthorizationURL)
	}
}

func TestGetEndpoints_Acceptance(t *testing.T) {
	eps := GetEndpoints("acceptance")
	if !strings.Contains(eps.AuthorizationURL, "acc.digid.nl") {
		t.Errorf("acceptance AuthorizationURL should contain acc.digid.nl, got %q", eps.AuthorizationURL)
	}
}

func TestGetEndpoints_UnknownFallsBackToAcceptance(t *testing.T) {
	eps := GetEndpoints("unknown")
	want := GetEndpoints("acceptance")
	if eps.AuthorizationURL != want.AuthorizationURL {
		t.Errorf("unknown env should fall back to acceptance, got %q", eps.AuthorizationURL)
	}
}

// ── BuildAuthzURL ─────────────────────────────────────────────────────────────

func TestBuildAuthzURL_RequiredParams(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	authzURL := BuildAuthzURL("acceptance", "client-nl", "https://rp.example.nl/cb", "st1", "nc1", verifier, "")

	parsed, err := url.Parse(authzURL)
	if err != nil {
		t.Fatalf("BuildAuthzURL returned unparseable URL: %v", err)
	}
	q := parsed.Query()

	want := map[string]string{
		"response_type":         "code",
		"client_id":             "client-nl",
		"redirect_uri":          "https://rp.example.nl/cb",
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
	if !strings.Contains(q.Get("scope"), "bsn") {
		t.Errorf("scope must contain 'bsn', got %q", q.Get("scope"))
	}
}

func TestBuildAuthzURL_AcrValuesLoA3(t *testing.T) {
	authzURL := BuildAuthzURL("acceptance", "c", "https://cb", "s", "n", "v", LoA3)
	parsed, _ := url.Parse(authzURL)
	if got := parsed.Query().Get("acr_values"); got != LoA3 {
		t.Errorf("acr_values: got %q, want %q", got, LoA3)
	}
}

func TestBuildAuthzURL_EmptyAcrValuesOmitted(t *testing.T) {
	authzURL := BuildAuthzURL("acceptance", "c", "https://cb", "s", "n", "v", "")
	parsed, _ := url.Parse(authzURL)
	if got := parsed.Query().Get("acr_values"); got != "" {
		t.Errorf("empty acrValues should be omitted, got %q", got)
	}
}

func TestBuildAuthzURL_ProductionHost(t *testing.T) {
	authzURL := BuildAuthzURL("production", "c", "https://cb", "s", "n", "v", "")
	if strings.Contains(authzURL, "acc") {
		t.Errorf("production URL should not contain acc, got %q", authzURL)
	}
	if !strings.Contains(authzURL, "authenticatie.digid.nl") {
		t.Errorf("production URL should contain authenticatie.digid.nl, got %q", authzURL)
	}
}

// ── ParseUserInfo ─────────────────────────────────────────────────────────────

func TestParseUserInfo_AllFields(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "nl-sub-abc123",
		"bsn": "123456789",
		"acr": LoA3,
	}
	u := ParseUserInfo(claims)
	if u.Sub != "nl-sub-abc123" {
		t.Errorf("Sub: got %q", u.Sub)
	}
	if u.BSN != "123456789" {
		t.Errorf("BSN: got %q", u.BSN)
	}
	if u.ACR != LoA3 {
		t.Errorf("ACR: got %q", u.ACR)
	}
	if !u.EmailSynthetic {
		t.Error("EmailSynthetic should always be true for DigiD")
	}
	if !strings.HasSuffix(u.Email, "@digid.internal") {
		t.Errorf("email should end with @digid.internal, got %q", u.Email)
	}
	// Raw BSN must not appear in the synthesised email (privacy).
	if strings.Contains(u.Email, "123456789") {
		t.Errorf("synthesised email must not contain raw BSN, got %q", u.Email)
	}
}

func TestParseUserInfo_NoBSNFallsBackToSub(t *testing.T) {
	claims := map[string]interface{}{"sub": "nl-sub-only"}
	u := ParseUserInfo(claims)
	if !strings.HasSuffix(u.Email, "@digid.internal") {
		t.Errorf("fallback email should end with @digid.internal, got %q", u.Email)
	}
	if !u.EmailSynthetic {
		t.Error("EmailSynthetic should be true")
	}
}

// ── HashBSN ───────────────────────────────────────────────────────────────────

func TestHashBSN_Deterministic(t *testing.T) {
	h1 := HashBSN("123456789")
	h2 := HashBSN("123456789")
	if h1 != h2 {
		t.Errorf("HashBSN not deterministic: %q vs %q", h1, h2)
	}
}

func TestHashBSN_DoesNotContainRawBSN(t *testing.T) {
	bsn := "999888777"
	h := HashBSN(bsn)
	if strings.Contains(h, bsn) {
		t.Errorf("hash must not contain raw BSN, got %q", h)
	}
}

func TestHashBSN_DifferentBSNsDifferentHashes(t *testing.T) {
	h1 := HashBSN("111111110")
	h2 := HashBSN("111111111")
	if h1 == h2 {
		t.Errorf("different BSNs should produce different hashes, both got %q", h1)
	}
}
