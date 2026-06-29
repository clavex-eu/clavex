// White-box tests for unexported SSF functions: streamWantsEvent and deliverPush.
// These live in "package ssf" (not ssf_test) to access unexported symbols.
package ssf

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests deliver to httptest servers on loopback, which the default SSRF-safe push
// client blocks; relax it for the test package.
func init() { SetPushHTTPClient(safehttp.Client(5*time.Second, true)) }

// ptr is a local helper to get *string from a literal.
func ptr(s string) *string { return &s }

// ── streamWantsEvent ─────────────────────────────────────────────────────────

func TestStreamWantsEvent_IncludedSingleEvent(t *testing.T) {
	s := &models.SSFStream{EventsRequested: []string{EventSessionRevoked}}
	assert.True(t, streamWantsEvent(s, EventSessionRevoked))
}

func TestStreamWantsEvent_IncludedAmongMultiple(t *testing.T) {
	s := &models.SSFStream{
		EventsRequested: []string{EventSessionRevoked, EventAccountDisabled, EventCredentialChange},
	}
	assert.True(t, streamWantsEvent(s, EventAccountDisabled))
	assert.True(t, streamWantsEvent(s, EventCredentialChange))
}

func TestStreamWantsEvent_NotIncluded(t *testing.T) {
	s := &models.SSFStream{EventsRequested: []string{EventSessionRevoked}}
	assert.False(t, streamWantsEvent(s, EventAccountDisabled))
	assert.False(t, streamWantsEvent(s, EventAccountPurged))
}

func TestStreamWantsEvent_EmptyRequestedList(t *testing.T) {
	s := &models.SSFStream{EventsRequested: []string{}}
	assert.False(t, streamWantsEvent(s, EventSessionRevoked))
}

func TestStreamWantsEvent_AllSupportedEvents(t *testing.T) {
	s := &models.SSFStream{EventsRequested: AllSupportedEvents}
	for _, ev := range AllSupportedEvents {
		assert.True(t, streamWantsEvent(s, ev), "should want %s", ev)
	}
	// An event not in AllSupportedEvents must still be filtered out.
	assert.False(t, streamWantsEvent(s, "https://custom.example.com/unknown-event"))
}

func TestStreamWantsEvent_UnknownEventNotWanted(t *testing.T) {
	s := &models.SSFStream{EventsRequested: []string{EventAccountDisabled}}
	assert.False(t, streamWantsEvent(s, "https://schemas.openid.net/secevent/caep/event-type/nonexistent"))
}

// ── deliverPush ──────────────────────────────────────────────────────────────

func TestDeliverPush_SuccessfulDelivery202(t *testing.T) {
	var receivedMethod, receivedCT, receivedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(http.StatusAccepted) // 202 Accepted — RFC 8935 §3.2
	}))
	defer srv.Close()

	ep := srv.URL
	s := &models.SSFStream{ID: uuid.New(), PushEndpoint: &ep}

	err := deliverPush(context.Background(), s, "header.payload.signature")
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, receivedMethod)
	assert.Equal(t, "application/secevent+jwt", receivedCT)
	assert.Equal(t, "header.payload.signature", receivedBody)
}

func TestDeliverPush_SuccessfulDelivery200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep := srv.URL
	s := &models.SSFStream{ID: uuid.New(), PushEndpoint: &ep}
	require.NoError(t, deliverPush(context.Background(), s, "tok"))
}

func TestDeliverPush_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // receiver rejected the SET
	}))
	defer srv.Close()

	ep := srv.URL
	s := &models.SSFStream{ID: uuid.New(), PushEndpoint: &ep}
	assert.Error(t, deliverPush(context.Background(), s, "tok"))
}

func TestDeliverPush_5xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ep := srv.URL
	s := &models.SSFStream{ID: uuid.New(), PushEndpoint: &ep}
	assert.Error(t, deliverPush(context.Background(), s, "tok"))
}

func TestDeliverPush_NilEndpointIsNoop(t *testing.T) {
	// A stream with no push endpoint (e.g. a poll stream) must not error.
	s := &models.SSFStream{ID: uuid.New(), PushEndpoint: nil}
	require.NoError(t, deliverPush(context.Background(), s, "tok"))
}

func TestDeliverPush_EmptyEndpointIsNoop(t *testing.T) {
	s := &models.SSFStream{ID: uuid.New(), PushEndpoint: ptr("")}
	require.NoError(t, deliverPush(context.Background(), s, "tok"))
}

func TestDeliverPush_CancelledContextReturnsError(t *testing.T) {
	// A server that hangs indefinitely; the cancelled context must unblock.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the request context is cancelled.
		<-r.Context().Done()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	ep := srv.URL
	s := &models.SSFStream{ID: uuid.New(), PushEndpoint: &ep}
	err := deliverPush(ctx, s, "tok")
	assert.Error(t, err, "cancelled context must surface an error")
}
