package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests POST to httptest servers on loopback, which the default SSRF-safe client
// blocks; relax it for the test package.
func init() { SetHTTPClient(safehttp.Client(5*time.Second, true)) }

func TestEnrich_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer test-secret", r.Header.Get("Authorization"))

		var body Payload
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "user-123", body.Sub)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"subscription_plan": "enterprise",
			"tenant_region":     "eu-west",
		})
	}))
	defer srv.Close()

	extra, err := Enrich(context.Background(), srv.URL, "test-secret", Payload{Sub: "user-123"})
	require.NoError(t, err)
	assert.Equal(t, "enterprise", extra["subscription_plan"])
	assert.Equal(t, "eu-west", extra["tenant_region"])
}

func TestEnrich_ReservedClaimsStripped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sub":               "evil-override",
			"iss":               "evil-issuer",
			"subscription_plan": "pro",
		})
	}))
	defer srv.Close()

	extra, err := Enrich(context.Background(), srv.URL, "", Payload{})
	require.NoError(t, err)
	assert.NotContains(t, extra, "sub")
	assert.NotContains(t, extra, "iss")
	assert.Equal(t, "pro", extra["subscription_plan"])
}

func TestEnrich_Non2xx_GracefulFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	extra, err := Enrich(context.Background(), srv.URL, "", Payload{})
	// Error returned but caller should discard it; extra is always a valid map.
	require.Error(t, err)
	assert.NotNil(t, extra)
}

func TestEnrich_Timeout(t *testing.T) {
	// unblock lets us release the server handler so srv.Close() doesn't wait
	// forever on the WaitGroup tracking the still-running handler goroutine.
	unblock := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-unblock:
		}
	}))

	extra, err := Enrich(context.Background(), srv.URL, "", Payload{})

	// Release the handler goroutine, then close the server cleanly.
	close(unblock)
	srv.Close()

	require.Error(t, err)
	assert.NotNil(t, extra)
}

func TestSanitise(t *testing.T) {
	in := map[string]any{
		"sub":               "x",
		"email":             "y",
		"subscription_plan": "enterprise",
		"Scope":             "z", // case-insensitive
	}
	out := sanitise(in)
	assert.NotContains(t, out, "sub")
	assert.NotContains(t, out, "email")
	assert.NotContains(t, out, "Scope")
	assert.Equal(t, "enterprise", out["subscription_plan"])
}

// TestEnrich_EmptySecret verifies that no Authorization header is sent when
// the secret is empty, and that the request still succeeds.
func TestEnrich_EmptySecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"), "no Authorization header when secret is empty")
		json.NewEncoder(w).Encode(map[string]any{"plan": "free"})
	}))
	defer srv.Close()

	extra, err := Enrich(context.Background(), srv.URL, "", Payload{Sub: "u1"})
	require.NoError(t, err)
	assert.Equal(t, "free", extra["plan"])
}

// TestEnrich_NestedObjectsPassedThrough verifies that nested JSON objects returned
// by the hook are included in the result map as-is (they are not flattened or
// rejected — the sanitiser only removes reserved top-level keys).
func TestEnrich_NestedObjectsPassedThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"roles":  []string{"admin", "editor"},
			"tenant": map[string]any{"id": "t1", "region": "eu"},
		})
	}))
	defer srv.Close()

	extra, err := Enrich(context.Background(), srv.URL, "", Payload{})
	require.NoError(t, err)
	// Nested values survive sanitise unchanged.
	require.Contains(t, extra, "roles")
	require.Contains(t, extra, "tenant")
	tenant, ok := extra["tenant"].(map[string]any)
	require.True(t, ok, "tenant should be a map")
	assert.Equal(t, "eu", tenant["region"])
}

// TestEnrich_UTF8Claims verifies that claims containing non-ASCII characters
// (accents, CJK, RTL text) round-trip correctly through the JSON encode/decode.
func TestEnrich_UTF8Claims(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that the request body was received with the correct UTF-8 email.
		var body Payload
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "ünïcödé@example.com", body.Email)

		json.NewEncoder(w).Encode(map[string]any{
			"display_name": "Ångström Üniversity 大学",
			"city":         "Köln",
		})
	}))
	defer srv.Close()

	extra, err := Enrich(context.Background(), srv.URL, "", Payload{
		Sub:   "u-utf8",
		Email: "ünïcödé@example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "Ångström Üniversity 大学", extra["display_name"])
	assert.Equal(t, "Köln", extra["city"])
}

// TestEnrich_Concurrency verifies that the shared httpClient handles concurrent
// calls without data races.  Run with -race to validate.
func TestEnrich_Concurrency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()

	const goroutines = 20
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			_, err := Enrich(context.Background(), srv.URL, "secret", Payload{
				Sub: fmt.Sprintf("user-%d", i),
			})
			errs <- err
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		assert.NoError(t, <-errs)
	}
}
