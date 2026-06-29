package handler

// Unit tests for ai.go pure/logic functions.
//
// Covered:
//   - extractJSON - strip markdown fences, return trimmed JSON
//   - AIHandler.UpsertAIConfig - key prefix validation (before DB)
//   - AIHandler.SuggestPolicy/SuggestFGAModel/SuggestLifecycleRule - empty description (before DB)
//
// DB-backed tests (GetAIConfig, aiClient) require a live DB and are not
// included here.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// extractJSON

func TestExtractJSON_PlainJSON(t *testing.T) {
	in := `{"foo":"bar"}`
	got := extractJSON(in)
	if got != `{"foo":"bar"}` {
		t.Errorf("got %q, want plain JSON", got)
	}
}

func TestExtractJSON_JSONFence(t *testing.T) {
	in := "```json\n{\"key\":\"value\"}\n```"
	got := extractJSON(in)
	if got != `{"key":"value"}` {
		t.Errorf("got %q, want stripped JSON", got)
	}
}

func TestExtractJSON_GenericFence(t *testing.T) {
	in := "```\n[1,2,3]\n```"
	got := extractJSON(in)
	if got != "[1,2,3]" {
		t.Errorf("got %q, want stripped array", got)
	}
}

func TestExtractJSON_WithPreamble(t *testing.T) {
	in := "Here is the result:\n```json\n{\"a\":1}\n```"
	got := extractJSON(in)
	if got != `{"a":1}` {
		t.Errorf("got %q, want JSON without preamble", got)
	}
}

func TestExtractJSON_WhitespaceOnly(t *testing.T) {
	got := extractJSON("  \n  ")
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestExtractJSON_ValidJSON(t *testing.T) {
	cases := []string{
		`{"rules":[]}`,
		`{"schema_version":"1.1","type_definitions":[]}`,
		`[]`,
		`{"a":{"b":{"c":3}}}`,
	}
	for _, tc := range cases {
		got := extractJSON(tc)
		var v any
		if err := json.Unmarshal([]byte(got), &v); err != nil {
			t.Errorf("extractJSON(%q) returned non-parseable JSON %q: %v", tc, got, err)
		}
	}
}

// AIHandler.UpsertAIConfig - key prefix validation

func TestUpsertAIConfig_InvalidKey(t *testing.T) {
	e := echo.New()
	body := `{"anthropic_api_key":"invalid-key"}`
	req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id")
	c.SetParamValues(uuid.New().String())

	h := &AIHandler{orgs: &repository.OrgRepository{}}
	err := h.UpsertAIConfig(c)
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T", err)
	}
	if he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid key prefix, got %d", he.Code)
	}
}

// AIHandler description validation

func TestSuggestPolicy_EmptyDescription(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"description":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id")
	c.SetParamValues(uuid.New().String())

	h := &AIHandler{orgs: &repository.OrgRepository{}}
	err := h.SuggestPolicy(c)
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T", err)
	}
	if he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty description, got %d", he.Code)
	}
}

func TestSuggestFGAModel_EmptyDescription(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"description":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id")
	c.SetParamValues(uuid.New().String())

	h := &AIHandler{orgs: &repository.OrgRepository{}}
	err := h.SuggestFGAModel(c)
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T", err)
	}
	if he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty description, got %d", he.Code)
	}
}

func TestSuggestLifecycleRule_EmptyDescription(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"description":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_id")
	c.SetParamValues(uuid.New().String())

	h := &AIHandler{orgs: &repository.OrgRepository{}}
	err := h.SuggestLifecycleRule(c)
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T", err)
	}
	if he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty description, got %d", he.Code)
	}
}
