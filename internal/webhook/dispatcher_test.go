package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Fake HookLister ──────────────────────────────────────────────────────────

type fakeLister struct {
	hooks []*models.Webhook
	err   error
}

func (f *fakeLister) ListActiveByOrgAndEvent(_ context.Context, _ uuid.UUID, _ string) ([]*models.Webhook, error) {
	return f.hooks, f.err
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func newTestDispatcher(lister HookLister, client *http.Client) *Dispatcher {
	return &Dispatcher{
		lister:    lister,
		delivRepo: nil, // no DB in unit tests
		client:    client,
		backoff:   func(time.Duration) {}, // instant in tests
	}
}

func verifySignature(t *testing.T, body []byte, secret, headerValue string) {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	assert.Equal(t, expected, headerValue, "HMAC signature mismatch")
}

// ── Unit tests ───────────────────────────────────────────────────────────────

func TestSign(t *testing.T) {
	secret := "mysecret"
	payload := []byte(`{"event":"user.created"}`)

	got := sign(payload, secret)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	want := hex.EncodeToString(mac.Sum(nil))

	assert.Equal(t, want, got)
	assert.Len(t, got, 64, "should be 32-byte hex")
}

func TestBuildPayload(t *testing.T) {
	type testData struct {
		UserID string `json:"user_id"`
	}
	raw, _, err := buildPayload(EventUserCreated, testData{UserID: "abc"})
	require.NoError(t, err)

	var p Payload
	require.NoError(t, json.Unmarshal(raw, &p))

	assert.Equal(t, EventUserCreated, p.Event)
	assert.NotEmpty(t, p.ID, "delivery ID should be set")
	assert.WithinDuration(t, time.Now().UTC(), p.OccuredAt, 5*time.Second)

	var data testData
	require.NoError(t, json.Unmarshal(p.Data, &data))
	assert.Equal(t, "abc", data.UserID)
}

// ── Integration-style tests (httptest.Server, no real DB/network) ────────────

func TestDispatch_Success(t *testing.T) {
	orgID := uuid.New()
	secret := "test-secret-1234"

	received := make(chan []byte, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Verify headers
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		verifySignature(t, body, secret, r.Header.Get("X-Clavex-Signature"))
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hook := &models.Webhook{
		ID:       uuid.New(),
		OrgID:    orgID,
		URL:      srv.URL,
		Events:   []string{EventUserCreated},
		Secret:   secret,
		IsActive: true,
	}

	d := newTestDispatcher(&fakeLister{hooks: []*models.Webhook{hook}}, srv.Client())
	d.Dispatch(orgID, EventUserCreated, map[string]string{"id": "user-1"})

	select {
	case body := <-received:
		var p Payload
		require.NoError(t, json.Unmarshal(body, &p))
		assert.Equal(t, EventUserCreated, p.Event)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: webhook was not delivered")
	}
}

func TestDispatch_NoHooks(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := newTestDispatcher(&fakeLister{hooks: []*models.Webhook{}}, srv.Client())
	d.Dispatch(uuid.New(), EventUserCreated, map[string]string{"id": "user-1"})

	// Wait briefly to let the goroutine run (it should do nothing).
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(0), calls.Load(), "no HTTP calls expected when no hooks are registered")
}

func TestDispatch_MultipleHooks(t *testing.T) {
	orgID := uuid.New()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hooks := []*models.Webhook{
		{ID: uuid.New(), OrgID: orgID, URL: srv.URL, Secret: "s1", IsActive: true},
		{ID: uuid.New(), OrgID: orgID, URL: srv.URL, Secret: "s2", IsActive: true},
		{ID: uuid.New(), OrgID: orgID, URL: srv.URL, Secret: "s3", IsActive: true},
	}

	d := newTestDispatcher(&fakeLister{hooks: hooks}, srv.Client())
	d.Dispatch(orgID, EventUserCreated, map[string]string{"id": "u1"})

	require.Eventually(t, func() bool {
		return calls.Load() == 3
	}, 3*time.Second, 50*time.Millisecond, "expected 3 deliveries, got %d", calls.Load())
}

func TestDispatch_RetriesOnServerError(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	hook := &models.Webhook{
		ID: uuid.New(), URL: srv.URL, Secret: "sec", IsActive: true,
	}

	d := newTestDispatcher(&fakeLister{hooks: []*models.Webhook{hook}}, srv.Client())
	d.Dispatch(uuid.New(), EventUserCreated, nil)

	// With instant backoff, all 3 attempts should complete quickly.
	require.Eventually(t, func() bool {
		return calls.Load() == int32(maxRetries)
	}, 3*time.Second, 50*time.Millisecond,
		"expected %d attempts, got %d", maxRetries, calls.Load())
}

func TestDispatch_SucceedsOnSecondAttempt(t *testing.T) {
	var calls atomic.Int32
	done := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // first attempt fails
		} else {
			w.WriteHeader(http.StatusOK) // second succeeds
			done <- struct{}{}
		}
	}))
	defer srv.Close()

	hook := &models.Webhook{
		ID: uuid.New(), URL: srv.URL, Secret: "sec", IsActive: true,
	}

	d := newTestDispatcher(&fakeLister{hooks: []*models.Webhook{hook}}, srv.Client())
	d.Dispatch(uuid.New(), EventUserCreated, nil)

	select {
	case <-done:
		assert.Equal(t, int32(2), calls.Load(), "should have taken exactly 2 attempts")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: webhook was never delivered successfully")
	}
}

func TestDispatch_SignaturesAreUniquePerSecret(t *testing.T) {
	payload := []byte(`{"event":"user.created","id":"x"}`)
	sig1 := sign(payload, "secret-A")
	sig2 := sign(payload, "secret-B")
	assert.NotEqual(t, sig1, sig2, "different secrets must produce different signatures")
}
