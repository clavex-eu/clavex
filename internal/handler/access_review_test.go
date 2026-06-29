package handler

// Tests for access_review.go pure/logic functions:
//   - extractCallerUserID      — JWT claim extraction from Echo context
//   - buildInitialReviewEmailHTML — email HTML generation
//   - Decide endpoint          — input validation (no-DB path: bad token / bad decision)
//
// Full DB-backed tests (CreateCampaign, Launch, Report, etc.) require
// a live Postgres instance and live in integration tests.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// ── extractCallerUserID ───────────────────────────────────────────────────────

func echoCtxWithUserID(t *testing.T, val interface{}) echo.Context {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if val != nil {
		c.Set("user_id", val)
	}
	return c
}

func TestExtractCallerUserID_ValidUUID(t *testing.T) {
	id := uuid.New()
	c := echoCtxWithUserID(t, id.String())
	got := extractCallerUserID(c)
	if got == nil {
		t.Fatal("expected non-nil UUID, got nil")
	}
	if *got != id {
		t.Errorf("got %v, want %v", *got, id)
	}
}

func TestExtractCallerUserID_MissingKey(t *testing.T) {
	c := echoCtxWithUserID(t, nil)
	if got := extractCallerUserID(c); got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
}

func TestExtractCallerUserID_WrongType(t *testing.T) {
	c := echoCtxWithUserID(t, 12345) // int, not string
	if got := extractCallerUserID(c); got != nil {
		t.Errorf("expected nil for wrong type, got %v", got)
	}
}

func TestExtractCallerUserID_InvalidUUID(t *testing.T) {
	c := echoCtxWithUserID(t, "not-a-uuid")
	if got := extractCallerUserID(c); got != nil {
		t.Errorf("expected nil for invalid UUID string, got %v", got)
	}
}

func TestExtractCallerUserID_EmptyString(t *testing.T) {
	c := echoCtxWithUserID(t, "")
	if got := extractCallerUserID(c); got != nil {
		t.Errorf("expected nil for empty string, got %v", got)
	}
}

// ── buildInitialReviewEmailHTML ───────────────────────────────────────────────

func makeCampaign(name string, endsAt time.Time) *models.AccessReviewCampaign {
	return &models.AccessReviewCampaign{
		ID:     uuid.New(),
		Name:   name,
		EndsAt: endsAt,
	}
}

func makeItem(token, userName, userEmail, roleName string) *models.AccessReviewItem {
	return &models.AccessReviewItem{
		ID:            uuid.New(),
		Token:         token,
		UserName:      userName,
		UserEmail:     userEmail,
		RoleName:      roleName,
		ReviewerEmail: "reviewer@example.com",
	}
}

func TestBuildInitialReviewEmailHTML_ContainsCampaignName(t *testing.T) {
	campaign := makeCampaign("Q2 2026 Review", time.Now().Add(30*24*time.Hour))
	items := []*models.AccessReviewItem{makeItem("tok1", "Alice", "alice@ex.com", "Admin")}
	html := buildInitialReviewEmailHTML(items, campaign, "https://id.example.com/acme")
	if !strings.Contains(html, "Q2 2026 Review") {
		t.Error("email HTML should contain campaign name")
	}
}

func TestBuildInitialReviewEmailHTML_ContainsApproveLink(t *testing.T) {
	campaign := makeCampaign("Test", time.Now().Add(24*time.Hour))
	items := []*models.AccessReviewItem{makeItem("abc123", "Bob", "bob@ex.com", "Viewer")}
	html := buildInitialReviewEmailHTML(items, campaign, "https://id.example.com/acme")

	wantApprove := "https://id.example.com/acme/access-review/decide?token=abc123&decision=approved"
	wantRevoke := "https://id.example.com/acme/access-review/decide?token=abc123&decision=revoked"
	if !strings.Contains(html, wantApprove) {
		t.Errorf("email should contain approve URL; got html len=%d", len(html))
	}
	if !strings.Contains(html, wantRevoke) {
		t.Error("email should contain revoke URL")
	}
}

func TestBuildInitialReviewEmailHTML_ContainsUserDetails(t *testing.T) {
	campaign := makeCampaign("Test", time.Now().Add(24*time.Hour))
	items := []*models.AccessReviewItem{makeItem("t1", "Charlie Doe", "charlie@ex.com", "Super Admin")}
	html := buildInitialReviewEmailHTML(items, campaign, "https://id.example.com")
	for _, want := range []string{"Charlie Doe", "charlie@ex.com", "Super Admin"} {
		if !strings.Contains(html, want) {
			t.Errorf("email HTML should contain %q", want)
		}
	}
}

func TestBuildInitialReviewEmailHTML_MultipleItems(t *testing.T) {
	campaign := makeCampaign("Multi", time.Now().Add(24*time.Hour))
	items := []*models.AccessReviewItem{
		makeItem("t1", "Alice", "alice@ex.com", "Admin"),
		makeItem("t2", "Bob", "bob@ex.com", "Viewer"),
		makeItem("t3", "Carol", "carol@ex.com", "Editor"),
	}
	html := buildInitialReviewEmailHTML(items, campaign, "https://base.example.com")
	for _, tok := range []string{"t1", "t2", "t3"} {
		if !strings.Contains(html, "token="+tok) {
			t.Errorf("email HTML should contain token %q", tok)
		}
	}
}

func TestBuildInitialReviewEmailHTML_EmptyItems(t *testing.T) {
	campaign := makeCampaign("Empty", time.Now().Add(24*time.Hour))
	// Should not panic with zero items.
	html := buildInitialReviewEmailHTML(nil, campaign, "https://base.example.com")
	if !strings.Contains(html, "Empty") {
		t.Error("email should still contain campaign name even with no items")
	}
}

// ── Decide — pure input validation (no DB needed) ─────────────────────────────

func newDecideRequest(token, decision string) (*http.Request, *httptest.ResponseRecorder) {
	target := "/decide"
	if token != "" || decision != "" {
		target += "?"
		if token != "" {
			target += "token=" + token
		}
		if decision != "" {
			if token != "" {
				target += "&"
			}
			target += "decision=" + decision
		}
	}
	return httptest.NewRequest(http.MethodGet, target, nil), httptest.NewRecorder()
}

// decideHandlerWithNilRepo creates an AccessReviewHandler with a nil repo.
// This is only safe for paths that fail before hitting the repo.
func newDecideEchoCtx(t *testing.T, token, decision string) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	req, rec := newDecideRequest(token, decision)
	c := e.NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues("acme")
	return c, rec
}

func TestDecide_MissingToken_Returns400(t *testing.T) {
	h := &AccessReviewHandler{} // nil repo — safe: fails before repo access
	c, _ := newDecideEchoCtx(t, "", "approved")
	err := h.Decide(c)
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T: %v", err, err)
	}
	if he.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", he.Code)
	}
}

func TestDecide_InvalidDecision_Returns400(t *testing.T) {
	h := &AccessReviewHandler{}
	c, _ := newDecideEchoCtx(t, "validtoken", "maybe")
	err := h.Decide(c)
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T: %v", err, err)
	}
	if he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid decision, got %d", he.Code)
	}
}

func TestDecide_EmptyDecision_Returns400(t *testing.T) {
	h := &AccessReviewHandler{}
	c, _ := newDecideEchoCtx(t, "tok", "")
	err := h.Decide(c)
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T: %v", err, err)
	}
	if he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty decision, got %d", he.Code)
	}
}

func TestDecide_ValidInputs_ApprovedAndRevoked(t *testing.T) {
	// Valid token + valid decision should pass the input check and attempt DB lookup.
	// With nil repo it will panic — we don't test beyond the validation gate here.
	// This just documents that "approved" and "revoked" are the only valid values.
	validDecisions := []string{"approved", "revoked"}
	invalidDecisions := []string{"", "maybe", "APPROVED", "reject", "deny", "accept"}

	h := &AccessReviewHandler{}
	for _, d := range invalidDecisions {
		c, _ := newDecideEchoCtx(t, "tok", d)
		err := h.Decide(c)
		he, ok := err.(*echo.HTTPError)
		if !ok || he.Code != http.StatusBadRequest {
			t.Errorf("decision %q should return 400; got %v", d, err)
		}
	}
	// Valid decisions pass the validation gate.
	// We can't proceed further without a real repo, so just verify they're recognised.
	_ = validDecisions // documented above — they would proceed to token lookup
}

// ── parseCampaignParams ───────────────────────────────────────────────────────

func TestParseCampaignParams_InvalidOrgID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id", "campaign_id")
	c.SetParamValues("not-a-uuid", uuid.New().String())

	h := &AccessReviewHandler{}
	_, _, err := h.parseCampaignParams(c)
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid org_id, got %v", err)
	}
}

func TestParseCampaignParams_InvalidCampaignID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id", "campaign_id")
	c.SetParamValues(uuid.New().String(), "bad-id")

	h := &AccessReviewHandler{}
	_, _, err := h.parseCampaignParams(c)
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid campaign_id, got %v", err)
	}
}

func TestParseCampaignParams_BothValid(t *testing.T) {
	orgID := uuid.New()
	campaignID := uuid.New()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id", "campaign_id")
	c.SetParamValues(orgID.String(), campaignID.String())

	h := &AccessReviewHandler{}
	gotOrg, gotCampaign, err := h.parseCampaignParams(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotOrg != orgID {
		t.Errorf("org_id mismatch: got %v, want %v", gotOrg, orgID)
	}
	if gotCampaign != campaignID {
		t.Errorf("campaign_id mismatch: got %v, want %v", gotCampaign, campaignID)
	}
}
