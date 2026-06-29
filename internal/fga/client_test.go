package fga_test

// Tests for the OpenFGA REST client using an httptest server to mock the
// OpenFGA API.  No real OpenFGA instance is required.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/fga"
)

// ── Check ──────────────────────────────────────────────────────────────────────

func TestCheck_allowed(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		mustContainPath(t, r, "/check")
		json.NewEncoder(w).Encode(map[string]bool{"allowed": true})
	})
	c := fga.NewClient(srv.URL, "")
	got, err := c.Check(context.Background(), "store1", "model1", fga.TupleKey{
		User:     "user:alice",
		Relation: "reader",
		Object:   "document:budget",
	})
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if !got {
		t.Error("expected allowed=true")
	}
}

func TestCheck_denied(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
	})
	c := fga.NewClient(srv.URL, "")
	got, err := c.Check(context.Background(), "s", "m", fga.TupleKey{})
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if got {
		t.Error("expected allowed=false")
	}
}

func TestCheck_serverError(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"internal_error"}`, http.StatusInternalServerError)
	})
	c := fga.NewClient(srv.URL, "")
	_, err := c.Check(context.Background(), "s", "m", fga.TupleKey{})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestCheck_sendsBearerToken(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer secret-api-key" {
			t.Errorf("wrong Authorization header: %q", auth)
		}
		json.NewEncoder(w).Encode(map[string]bool{"allowed": true})
	})
	c := fga.NewClient(srv.URL, "secret-api-key")
	if _, err := c.Check(context.Background(), "s", "m", fga.TupleKey{}); err != nil {
		t.Fatalf("Check error: %v", err)
	}
}

func TestCheck_includesModelID(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body["authorization_model_id"] != "model-xyz" {
			t.Errorf("missing authorization_model_id in request body: %v", body)
		}
		json.NewEncoder(w).Encode(map[string]bool{"allowed": true})
	})
	c := fga.NewClient(srv.URL, "")
	c.Check(context.Background(), "s", "model-xyz", fga.TupleKey{})
}

func TestCheck_omitsModelIDWhenEmpty(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["authorization_model_id"]; ok {
			t.Error("authorization_model_id should be absent when modelID is empty")
		}
		json.NewEncoder(w).Encode(map[string]bool{"allowed": false})
	})
	c := fga.NewClient(srv.URL, "")
	c.Check(context.Background(), "s", "", fga.TupleKey{})
}

// ── Write ──────────────────────────────────────────────────────────────────────

func TestWrite_sendsWritesAndDeletes(t *testing.T) {
	var gotBody map[string]any
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		mustContainPath(t, r, "/write")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	})
	c := fga.NewClient(srv.URL, "")
	err := c.Write(context.Background(), "s", "m",
		[]fga.TupleKey{{User: "user:bob", Relation: "writer", Object: "doc:1"}},
		[]fga.TupleKey{{User: "user:eve", Relation: "reader", Object: "doc:2"}},
	)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if gotBody["authorization_model_id"] != "m" {
		t.Errorf("authorization_model_id not sent: %v", gotBody)
	}
	if _, ok := gotBody["writes"]; !ok {
		t.Error("writes field missing")
	}
	if _, ok := gotBody["deletes"]; !ok {
		t.Error("deletes field missing")
	}
}

func TestWrite_noOp(t *testing.T) {
	// When both writes and deletes are nil AND modelID is empty, the body map
	// is empty and the client must return nil without making an HTTP request.
	// Pointing at an unreachable address confirms no request is sent.
	c := fga.NewClient("http://127.0.0.1:1", "")
	if err := c.Write(context.Background(), "s", "", nil, nil); err != nil {
		t.Fatalf("expected no error for no-op Write: %v", err)
	}
}

func TestWrite_serverError(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"write_failed_due_to_invalid_input"}`, http.StatusBadRequest)
	})
	c := fga.NewClient(srv.URL, "")
	err := c.Write(context.Background(), "s", "m",
		[]fga.TupleKey{{User: "user:bad", Relation: "x", Object: "y"}}, nil)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
}

// ── Read ───────────────────────────────────────────────────────────────────────

func TestRead_returnsTuples(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		mustContainPath(t, r, "/read")
		json.NewEncoder(w).Encode(map[string]any{
			"tuples": []map[string]any{
				{"key": map[string]string{
					"user":     "user:alice",
					"relation": "reader",
					"object":   "doc:1",
				}},
			},
			"continuation_token": "tok-next",
		})
	})
	c := fga.NewClient(srv.URL, "")
	tuples, token, err := c.Read(context.Background(), "s", fga.TupleKey{}, 10, "")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if len(tuples) != 1 {
		t.Errorf("expected 1 tuple, got %d", len(tuples))
	}
	if tuples[0].Key.User != "user:alice" {
		t.Errorf("unexpected tuple user: %q", tuples[0].Key.User)
	}
	if token != "tok-next" {
		t.Errorf("expected continuation token %q, got %q", "tok-next", token)
	}
}

func TestRead_emptyResult(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"tuples":             []any{},
			"continuation_token": "",
		})
	})
	c := fga.NewClient(srv.URL, "")
	tuples, token, err := c.Read(context.Background(), "s", fga.TupleKey{}, 0, "")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if len(tuples) != 0 {
		t.Errorf("expected 0 tuples, got %d", len(tuples))
	}
	if token != "" {
		t.Errorf("expected empty token, got %q", token)
	}
}

// ── Ping ───────────────────────────────────────────────────────────────────────

func TestPing_ok(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected path %q; want /healthz", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})
	c := fga.NewClient(srv.URL, "")
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping error: %v", err)
	}
}

func TestPing_serverError(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := fga.NewClient(srv.URL, "")
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected error for 503 response")
	}
}

func TestPing_unreachable(t *testing.T) {
	c := fga.NewClient("http://127.0.0.1:1", "")
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// ── CreateStore ────────────────────────────────────────────────────────────────

func TestCreateStore_returnsID(t *testing.T) {
	srv := cibaFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		mustContainPath(t, r, "/stores")
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "my-store") {
			t.Errorf("store name not in request body: %s", body)
		}
		json.NewEncoder(w).Encode(map[string]string{"id": "store-abc123"})
	})
	c := fga.NewClient(srv.URL, "")
	id, err := c.CreateStore(context.Background(), "my-store")
	if err != nil {
		t.Fatalf("CreateStore error: %v", err)
	}
	if id != "store-abc123" {
		t.Errorf("want id=%q, got %q", "store-abc123", id)
	}
}

// ── TupleKey struct ────────────────────────────────────────────────────────────

func TestTupleKey_JSONFieldNames(t *testing.T) {
	tk := fga.TupleKey{User: "user:x", Relation: "can_read", Object: "doc:y"}
	b, err := json.Marshal(tk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]string
	json.Unmarshal(b, &out)
	for _, key := range []string{"user", "relation", "object"} {
		if _, ok := out[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
}

// ── Template library ───────────────────────────────────────────────────────────

func TestTemplates_allHaveIDs(t *testing.T) {
	for _, tmpl := range fga.All() {
		if tmpl.ID == "" {
			t.Errorf("template %q has empty ID", tmpl.Name)
		}
	}
}

func TestTemplates_modelsAreValidJSON(t *testing.T) {
	for _, tmpl := range fga.All() {
		if !json.Valid(tmpl.Model) {
			t.Errorf("template %q has invalid JSON model", tmpl.ID)
		}
	}
}

func TestTemplates_modelsHaveSchemaVersion(t *testing.T) {
	for _, tmpl := range fga.All() {
		var m map[string]any
		if err := json.Unmarshal(tmpl.Model, &m); err != nil {
			t.Errorf("template %q: unmarshal: %v", tmpl.ID, err)
			continue
		}
		if m["schema_version"] != "1.1" {
			t.Errorf("template %q: want schema_version=1.1, got %v", tmpl.ID, m["schema_version"])
		}
	}
}

func TestTemplates_modelsHaveTypeDefinitions(t *testing.T) {
	for _, tmpl := range fga.All() {
		var m map[string]any
		if err := json.Unmarshal(tmpl.Model, &m); err != nil {
			continue
		}
		td, ok := m["type_definitions"].([]any)
		if !ok || len(td) == 0 {
			t.Errorf("template %q: type_definitions is empty or missing", tmpl.ID)
		}
	}
}

func TestTemplates_get_knownID(t *testing.T) {
	ids := []string{"rbac-simple", "document-sharing", "org-hierarchy", "healthcare", "banking"}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			tmpl, err := fga.Get(id)
			if err != nil {
				t.Fatalf("Get(%q) error: %v", id, err)
			}
			if tmpl.ID != id {
				t.Errorf("ID mismatch: want %q, got %q", id, tmpl.ID)
			}
		})
	}
}

func TestTemplates_get_unknownID(t *testing.T) {
	_, err := fga.Get("nonexistent-template")
	if err == nil {
		t.Fatal("expected error for unknown template ID")
	}
}

func TestTemplates_count(t *testing.T) {
	if n := len(fga.All()); n != 5 {
		t.Errorf("expected 5 templates, got %d", n)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────────

func cibaFakeServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func mustContainPath(t *testing.T, r *http.Request, substring string) {
	t.Helper()
	if !strings.Contains(r.URL.Path, substring) {
		t.Errorf("unexpected path %q (want contains %q)", r.URL.Path, substring)
	}
}
