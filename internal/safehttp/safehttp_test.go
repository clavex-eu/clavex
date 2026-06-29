package safehttp

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBlockedIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "fc00::1", "0.0.0.0", "224.0.0.1"}
	for _, s := range blocked {
		if !blockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "203.0.113.10", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if blockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestClient_BlocksLoopbackByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Default (allowPrivate=false): connecting to the loopback test server is refused.
	if _, err := Client(2*time.Second, false).Get(ts.URL); err == nil {
		t.Error("expected loopback connection to be blocked, got nil error")
	}

	// Opt-out: allowPrivate=true permits it.
	resp, err := Client(2*time.Second, true).Get(ts.URL)
	if err != nil {
		t.Fatalf("allowPrivate=true should permit loopback: %v", err)
	}
	_ = resp.Body.Close()
}
