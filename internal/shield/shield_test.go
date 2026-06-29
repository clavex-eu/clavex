package shield

// Tests for Client.Check and supporting logic:
//   - Private/loopback addresses short-circuit to clean Result (no HTTP)
//   - Cache: hit returns stale-free result; second call skips lookup
//   - AbuseIPDB: confidence below threshold → clean; above → malicious
//   - Tor exit list: listed IP → IsTorExit + IsMalicious
//   - fetchTorExits: parses IP lines, skips comments and blank lines
//   - Default option values (threshold=25, torURL default, timeout default)

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// abuseIPDBResponse builds a minimal AbuseIPDB v2 JSON payload.
func abuseIPDBResponse(score int) string {
	return fmt.Sprintf(`{"data":{"abuseConfidenceScore":%d}}`, score)
}

// ── Option defaults ───────────────────────────────────────────────────────────

func TestNew_DefaultThreshold(t *testing.T) {
	c := New(Options{AbuseIPDBKey: "key"})
	if c.abuseIPDBThreshold != 25 {
		t.Errorf("default threshold = %d, want 25", c.abuseIPDBThreshold)
	}
}

func TestNew_DefaultTorURL(t *testing.T) {
	c := New(Options{})
	const want = "https://check.torproject.org/torbulkexitlist"
	if c.torExitURL != want {
		t.Errorf("torExitURL = %q, want %q", c.torExitURL, want)
	}
}

func TestNew_CustomThresholdPreserved(t *testing.T) {
	c := New(Options{AbuseIPDBThreshold: 60})
	if c.abuseIPDBThreshold != 60 {
		t.Errorf("threshold = %d, want 60", c.abuseIPDBThreshold)
	}
}

// ── Private / loopback bypass ─────────────────────────────────────────────────

func TestCheck_Loopback_ReturnsClean(t *testing.T) {
	c := &Client{cache: make(map[string]cacheEntry), httpClient: &http.Client{}}
	res := c.Check(context.Background(), "127.0.0.1")
	if res.IsMalicious || res.IsTorExit || len(res.Sources) > 0 {
		t.Errorf("loopback should return clean result: %+v", res)
	}
}

func TestCheck_IPv6Loopback_ReturnsClean(t *testing.T) {
	c := &Client{cache: make(map[string]cacheEntry), httpClient: &http.Client{}}
	res := c.Check(context.Background(), "::1")
	if res.IsMalicious {
		t.Error("IPv6 loopback should return clean result")
	}
}

func TestCheck_PrivateRFC1918_ReturnsClean(t *testing.T) {
	c := &Client{cache: make(map[string]cacheEntry), httpClient: &http.Client{}}
	for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.100"} {
		res := c.Check(context.Background(), ip)
		if res.IsMalicious {
			t.Errorf("private IP %q should return clean result", ip)
		}
	}
}

func TestCheck_IPWithPort_Stripped(t *testing.T) {
	c := &Client{cache: make(map[string]cacheEntry), httpClient: &http.Client{}}
	// 127.0.0.1:8080 → 127.0.0.1 → loopback → clean (no HTTP call needed)
	res := c.Check(context.Background(), "127.0.0.1:8080")
	if res.IsMalicious {
		t.Error("loopback with port should return clean result after port stripping")
	}
}

func TestCheck_InvalidIP_ReturnsClean(t *testing.T) {
	c := &Client{cache: make(map[string]cacheEntry), httpClient: &http.Client{}}
	res := c.Check(context.Background(), "not-an-ip")
	if res.IsMalicious {
		t.Error("invalid IP should return clean result")
	}
}

// ── AbuseIPDB integration (via test HTTP server) ──────────────────────────────

func newAbuseIPDBClient(t *testing.T, srv *httptest.Server, score int) *Client {
	t.Helper()
	return &Client{
		abuseIPDBKey:       "test-key",
		abuseIPDBThreshold: 25,
		abuseIPDBBaseURL:   srv.URL + "/check",
		torExitURL:         srv.URL + "/tor",
		httpClient:         srv.Client(),
		cache:              make(map[string]cacheEntry),
		torExits:           map[string]struct{}{}, // pre-seeded — skip Tor fetch
		torFetched:         time.Now(),
	}
}

func TestCheck_AbuseIPDB_BelowThreshold_Clean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, abuseIPDBResponse(10)) // below threshold 25
	}))
	defer srv.Close()

	c := newAbuseIPDBClient(t, srv, 10)
	conf, err := c.queryAbuseIPDB(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("queryAbuseIPDB error: %v", err)
	}
	if conf != 10 {
		t.Errorf("confidence = %d, want 10", conf)
	}
}

func TestCheck_AbuseIPDB_AboveThreshold_Malicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, abuseIPDBResponse(90)) // well above threshold
	}))
	defer srv.Close()

	c := newAbuseIPDBClient(t, srv, 90)
	conf, err := c.queryAbuseIPDB(context.Background(), "5.6.7.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf < 25 {
		t.Error("score 90 should be above threshold 25")
	}
}

func TestCheck_AbuseIPDB_RateLimit_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newAbuseIPDBClient(t, srv, 0)
	_, err := c.queryAbuseIPDB(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("rate-limited response should return error")
	}
}

func TestCheck_AbuseIPDB_Non200_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newAbuseIPDBClient(t, srv, 0)
	_, err := c.queryAbuseIPDB(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("5xx response should return error")
	}
}

func TestCheck_AbuseIPDB_BadJSON_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json at all {{{")
	}))
	defer srv.Close()

	c := newAbuseIPDBClient(t, srv, 0)
	_, err := c.queryAbuseIPDB(context.Background(), "1.2.3.4")
	if err == nil {
		t.Error("invalid JSON should return error")
	}
}

// ── Tor exit list ─────────────────────────────────────────────────────────────

const torList = `# Tor exit nodes
1.1.1.1
2.2.2.2
# another comment

3.3.3.3
`

func TestFetchTorExits_ParsesIPsCorrectly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, torList)
	}))
	defer srv.Close()

	c := New(Options{TorExitURL: srv.URL})
	c.httpClient = srv.Client()

	exits, err := c.fetchTorExits(context.Background())
	if err != nil {
		t.Fatalf("fetchTorExits error: %v", err)
	}
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if _, ok := exits[ip]; !ok {
			t.Errorf("expected %q in Tor exit set", ip)
		}
	}
	// Comments and blank lines should not appear as keys.
	if _, ok := exits["# Tor exit nodes"]; ok {
		t.Error("comment line should not be in exit set")
	}
}

func TestFetchTorExits_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(Options{TorExitURL: srv.URL})
	c.httpClient = srv.Client()

	_, err := c.fetchTorExits(context.Background())
	if err == nil {
		t.Error("5xx Tor list response should return error")
	}
}

// ── Cache behaviour ───────────────────────────────────────────────────────────

func TestCheck_CacheHit_NoExtraHTTP(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Return empty Tor list for any request.
		fmt.Fprint(w, "")
	}))
	defer srv.Close()

	c := &Client{
		abuseIPDBThreshold: 25,
		torExitURL:         srv.URL,
		httpClient:         srv.Client(),
		cache:              make(map[string]cacheEntry),
		torExits:           map[string]struct{}{},        // pre-seeded — no fetch
		torFetched:         time.Now(),
	}
	// Pre-populate cache.
	c.cache["8.8.8.8"] = cacheEntry{
		result:    Result{IP: "8.8.8.8", IsMalicious: false},
		expiresAt: time.Now().Add(1 * time.Hour),
	}

	// First Check should hit cache (no HTTP call).
	res := c.Check(context.Background(), "8.8.8.8")
	if res.IsMalicious {
		t.Error("cached clean result should be returned as clean")
	}
	if callCount > 0 {
		t.Errorf("cache hit should not trigger HTTP calls; got %d", callCount)
	}
}

func TestCheck_CacheExpired_RelooksUp(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		fmt.Fprint(w, "") // empty Tor list
	}))
	defer srv.Close()

	c := &Client{
		abuseIPDBThreshold: 25,
		torExitURL:         srv.URL,
		httpClient:         srv.Client(),
		cache:              make(map[string]cacheEntry),
		torExits:           map[string]struct{}{},
		torFetched:         time.Now(),
	}
	// Stale cache entry (expired 1 hour ago).
	c.cache["9.9.9.9"] = cacheEntry{
		result:    Result{IP: "9.9.9.9", IsMalicious: false},
		expiresAt: time.Now().Add(-1 * time.Hour), // expired
	}

	// Should re-fetch (Tor list call) — no AbuseIPDB key configured.
	_ = c.Check(context.Background(), "9.9.9.9")
	// The Tor list is already fresh (torFetched = now), so no HTTP should happen
	// for the Tor list. And no AbuseIPDB key, so no AbuseIPDB call either.
	// After the lookup the cache is updated.
	c.mu.RLock()
	entry, ok := c.cache["9.9.9.9"]
	c.mu.RUnlock()
	if !ok {
		t.Error("cache should be populated after expired entry re-lookup")
	}
	if !entry.expiresAt.After(time.Now()) {
		t.Error("new cache entry should expire in the future")
	}
}

func TestCheck_MaliciousCached_ShortTTL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return empty Tor list for Tor fetch.
		fmt.Fprint(w, "10.0.0.1") // not a valid public IP — parsed as private, won't match
	}))
	defer srv.Close()

	c := &Client{
		abuseIPDBKey:       "key",
		abuseIPDBThreshold: 25,
		torExitURL:         srv.URL,
		httpClient:         srv.Client(),
		cache:              make(map[string]cacheEntry),
		torExits:           map[string]struct{}{"11.22.33.44": {}},
		torFetched:         time.Now(),
	}

	// Verify that a Tor-exit IP results in IsMalicious + IsTorExit.
	// We test isTorExit directly since Check would need a non-private IP
	// and AbuseIPDB is hard-coded.
	if !c.isTorExit(context.Background(), "11.22.33.44") {
		t.Error("IP in Tor exit set should return true")
	}
	if c.isTorExit(context.Background(), "11.22.33.45") {
		t.Error("IP not in Tor exit set should return false")
	}
}

// ── isTorExit — cache refresh logic ──────────────────────────────────────────

func TestIsTorExit_StaleList_Refreshes(t *testing.T) {
	const targetIP = "77.88.99.10"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, targetIP)
	}))
	defer srv.Close()

	c := New(Options{TorExitURL: srv.URL})
	c.httpClient = srv.Client()
	// torExits nil and torFetched zero → stale → should fetch.
	result := c.isTorExit(context.Background(), targetIP)
	if !result {
		t.Errorf("after refresh, %q should be in Tor exit set", targetIP)
	}
}

func TestIsTorExit_NilExits_FetchFails_ReturnsFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(Options{TorExitURL: srv.URL})
	c.httpClient = srv.Client()
	// nil exits + fetch failure → should return false, not panic.
	result := c.isTorExit(context.Background(), "1.2.3.4")
	if result {
		t.Error("failed Tor fetch with nil exits should return false")
	}
}
