package handler

// Unit tests for stream.go pure/logic functions.
//
// Covered:
//   - streamEventMatches — all filter combinations
//   - extractBearerOrQuery — header and query param extraction
//   - parseAdminJWT — valid token, wrong signing method, non-admin token

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internaudit "github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// ── streamEventMatches ───────────────────────────────────────────────────────

func makeEvent(t *testing.T, action, resourceType, status string) *internaudit.Event {
	t.Helper()
	data := map[string]string{
		"action":        action,
		"resource_type": resourceType,
		"status":        status,
	}
	raw, _ := json.Marshal(data)
	return &internaudit.Event{Data: json.RawMessage(raw)}
}

func TestStreamEventMatches_NoFilters(t *testing.T) {
	evt := makeEvent(t, "user.login", "session", "success")
	if !streamEventMatches(evt, "", "", "") {
		t.Error("no filters should always match")
	}
}

func TestStreamEventMatches_ActionMatch(t *testing.T) {
	evt := makeEvent(t, "user.login", "", "")
	if !streamEventMatches(evt, "user.login", "", "") {
		t.Error("exact action match should pass")
	}
	if streamEventMatches(evt, "user.logout", "", "") {
		t.Error("wrong action should not match")
	}
}

func TestStreamEventMatches_ResourceTypeMatch(t *testing.T) {
	evt := makeEvent(t, "", "session", "")
	if !streamEventMatches(evt, "", "session", "") {
		t.Error("resource_type match should pass")
	}
	if streamEventMatches(evt, "", "user", "") {
		t.Error("wrong resource_type should not match")
	}
}

func TestStreamEventMatches_StatusMatch(t *testing.T) {
	evt := makeEvent(t, "", "", "failure")
	if !streamEventMatches(evt, "", "", "failure") {
		t.Error("status match should pass")
	}
	if streamEventMatches(evt, "", "", "success") {
		t.Error("wrong status should not match")
	}
}

func TestStreamEventMatches_AllFilters(t *testing.T) {
	evt := makeEvent(t, "mfa.enrolled", "mfa", "success")
	// all match
	if !streamEventMatches(evt, "mfa.enrolled", "mfa", "success") {
		t.Error("all filters matching should pass")
	}
	// one mismatch
	if streamEventMatches(evt, "mfa.enrolled", "mfa", "failure") {
		t.Error("status mismatch should fail")
	}
}

func TestStreamEventMatches_NilData(t *testing.T) {
	evt := &internaudit.Event{Data: nil}
	// With no data, action filter won't match non-empty filter.
	if streamEventMatches(evt, "user.login", "", "") {
		t.Error("nil data should not match action filter")
	}
	// No filters still pass.
	if !streamEventMatches(evt, "", "", "") {
		t.Error("nil data with no filters should pass")
	}
}

// ── extractBearerOrQuery ─────────────────────────────────────────────────────

func TestExtractBearerOrQuery_Header(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer mytoken")
	c := e.NewContext(req, httptest.NewRecorder())

	got := extractBearerOrQuery(c)
	if got != "mytoken" {
		t.Errorf("got %q, want %q", got, "mytoken")
	}
}

func TestExtractBearerOrQuery_QueryParam(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?token=querytoken", nil)
	c := e.NewContext(req, httptest.NewRecorder())

	got := extractBearerOrQuery(c)
	if got != "querytoken" {
		t.Errorf("got %q, want %q", got, "querytoken")
	}
}

func TestExtractBearerOrQuery_Empty(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := e.NewContext(req, httptest.NewRecorder())

	if got := extractBearerOrQuery(c); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestExtractBearerOrQuery_HeaderTakesPrecedence(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?token=qtoken", nil)
	req.Header.Set("Authorization", "Bearer htoken")
	c := e.NewContext(req, httptest.NewRecorder())

	got := extractBearerOrQuery(c)
	if got != "htoken" {
		t.Errorf("header should take precedence; got %q", got)
	}
}

// ── parseAdminJWT ────────────────────────────────────────────────────────────

const testAdminSecret = "test-secret-32-bytes-long-xxxxx!!"

func makeAdminJWT(t *testing.T, secret string, isAdmin bool, orgID string) string {
	t.Helper()
	claims := middlewareClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		OrgID:   orgID,
		IsAdmin: isAdmin,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

func testStreamHandler() *StreamHandler {
	return &StreamHandler{
		cfg: &config.Config{
			Auth: config.AuthConfig{AdminSecret: testAdminSecret},
		},
	}
}

func TestParseAdminJWT_ValidAdmin(t *testing.T) {
	raw := makeAdminJWT(t, testAdminSecret, true, "org-123")
	h := testStreamHandler()
	claims, err := h.parseAdminJWT(raw)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !claims.IsAdmin {
		t.Error("expected IsAdmin=true")
	}
	if claims.OrgID != "org-123" {
		t.Errorf("got org_id=%q, want org-123", claims.OrgID)
	}
}

func TestParseAdminJWT_NonAdmin(t *testing.T) {
	raw := makeAdminJWT(t, testAdminSecret, false, "org-x")
	h := testStreamHandler()
	_, err := h.parseAdminJWT(raw)
	if err == nil {
		t.Error("expected error for non-admin token")
	}
}

func TestParseAdminJWT_WrongSecret(t *testing.T) {
	raw := makeAdminJWT(t, "wrong-secret-xxxxxxxxxxxxxxxxxxxxxxx", true, "org-x")
	h := testStreamHandler()
	_, err := h.parseAdminJWT(raw)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestParseAdminJWT_MalformedToken(t *testing.T) {
	h := testStreamHandler()
	_, err := h.parseAdminJWT("not.a.jwt")
	if err == nil {
		t.Error("expected error for malformed token")
	}
}

func TestParseAdminJWT_ExpiredToken(t *testing.T) {
	claims := middlewareClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // expired
		},
		IsAdmin: true,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := tok.SignedString([]byte(testAdminSecret))

	h := testStreamHandler()
	_, err := h.parseAdminJWT(signed)
	if err == nil {
		t.Error("expected error for expired token")
	}
}
