// Package shield provides Clavex Shield threat-intelligence integration.
// It queries external threat feeds (AbuseIPDB) and caches results in-process
// with a configurable TTL so the risk scorer can call it on every login event
// without incurring per-request HTTP latency on cache hits.
//
// Signal weights (added to the risk score when present):
//
//	+20  IP found in AbuseIPDB with confidence ≥ threshold (default 25 %)
//	+20  IP is a known Tor exit node (via the Tor Project's exit-node list)
package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// DefaultCacheTTL is how long a threat-intel lookup result is cached.
// Negative entries (clean IPs) are cached for 6 h; positive (malicious) for 1 h
// so that a newly de-listed IP recovers faster.
const (
	DefaultCleanTTL     = 6 * time.Hour
	DefaultMaliciousTTL = 1 * time.Hour
)

// Result summarises the threat-intel verdict for a single IP.
type Result struct {
	IP            string
	IsMalicious   bool   // true when at least one feed flags the IP
	Confidence    int    // AbuseIPDB confidence score (0-100); 0 when not checked
	IsTorExit     bool
	Sources       []string // which feeds flagged this IP
}

// cacheEntry is a single cached verdict.
type cacheEntry struct {
	result    Result
	expiresAt time.Time
}

// Client is a thread-safe threat-intelligence client.
// Create one via New and share it for the lifetime of the process.
type Client struct {
	abuseIPDBKey        string // empty → AbuseIPDB disabled
	abuseIPDBThreshold  int    // minimum confidence % to treat as malicious
	abuseIPDBBaseURL    string // overridable in tests; defaults to AbuseIPDB v2 endpoint
	torExitURL          string // URL to the Tor exit-node list
	httpClient          *http.Client

	mu    sync.RWMutex
	cache map[string]cacheEntry

	torMu      sync.RWMutex
	torExits   map[string]struct{} // set of Tor exit node IPs
	torFetched time.Time
}

// Options configures a Client.
type Options struct {
	// AbuseIPDBKey is the v2 API key.  Leave empty to disable AbuseIPDB checks.
	AbuseIPDBKey string
	// AbuseIPDBThreshold is the minimum confidence percentage (0-100) to flag an IP
	// as malicious.  Defaults to 25.
	AbuseIPDBThreshold int
	// TorExitURL is the URL of the Tor exit-node list.
	// Defaults to https://check.torproject.org/torbulkexitlist
	TorExitURL string
	// HTTPTimeout overrides the per-request HTTP timeout (default 5 s).
	HTTPTimeout time.Duration
}

// New creates a new Client.
func New(opts Options) *Client {
	if opts.AbuseIPDBThreshold <= 0 {
		opts.AbuseIPDBThreshold = 25
	}
	torURL := opts.TorExitURL
	if torURL == "" {
		torURL = "https://check.torproject.org/torbulkexitlist"
	}
	timeout := opts.HTTPTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		abuseIPDBKey:       opts.AbuseIPDBKey,
		abuseIPDBThreshold: opts.AbuseIPDBThreshold,
		abuseIPDBBaseURL:   "https://api.abuseipdb.com/api/v2/check",
		torExitURL:         torURL,
		httpClient:         &http.Client{Timeout: timeout},
		cache:              make(map[string]cacheEntry),
	}
}

// Check returns a threat-intel verdict for ip.  Results are cached.
// ip should be a plain IPv4 or IPv6 address (no port).
// Private / loopback addresses always return a clean Result immediately.
func (c *Client) Check(ctx context.Context, ip string) Result {
	// Strip port if present.
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}
	parsed := net.ParseIP(host)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return Result{IP: host}
	}

	// Check cache.
	c.mu.RLock()
	entry, ok := c.cache[host]
	c.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.result
	}

	res := c.lookup(ctx, host)

	ttl := DefaultCleanTTL
	if res.IsMalicious {
		ttl = DefaultMaliciousTTL
	}
	c.mu.Lock()
	c.cache[host] = cacheEntry{result: res, expiresAt: time.Now().Add(ttl)}
	c.mu.Unlock()

	return res
}

// lookup performs the actual external queries (no cache interaction).
func (c *Client) lookup(ctx context.Context, ip string) Result {
	res := Result{IP: ip}

	// ── AbuseIPDB ─────────────────────────────────────────────────────────────
	if c.abuseIPDBKey != "" {
		conf, err := c.queryAbuseIPDB(ctx, ip)
		if err != nil {
			log.Warn().Err(err).Str("ip", ip).Msg("shield: AbuseIPDB query failed")
		} else {
			res.Confidence = conf
			if conf >= c.abuseIPDBThreshold {
				res.IsMalicious = true
				res.Sources = append(res.Sources, fmt.Sprintf("abuseipdb:%d%%", conf))
			}
		}
	}

	// ── Tor exit list ─────────────────────────────────────────────────────────
	if c.isTorExit(ctx, ip) {
		res.IsTorExit = true
		res.IsMalicious = true
		res.Sources = append(res.Sources, "tor_exit")
	}

	return res
}

// queryAbuseIPDB calls the AbuseIPDB v2 check endpoint and returns the
// abuseConfidenceScore (0-100).
func (c *Client) queryAbuseIPDB(ctx context.Context, ip string) (int, error) {
	baseURL := c.abuseIPDBBaseURL
	if baseURL == "" {
		baseURL = "https://api.abuseipdb.com/api/v2/check"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return 0, err
	}
	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "30")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", c.abuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return 0, fmt.Errorf("abuseipdb: rate limited")
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("abuseipdb: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return 0, err
	}

	var payload struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, fmt.Errorf("abuseipdb: bad JSON: %w", err)
	}
	return payload.Data.AbuseConfidenceScore, nil
}

// isTorExit returns true if ip is in the Tor exit-node list.
// The list is fetched at most once per hour and cached in-process.
func (c *Client) isTorExit(ctx context.Context, ip string) bool {
	c.torMu.RLock()
	exits := c.torExits
	fetched := c.torFetched
	c.torMu.RUnlock()

	if exits == nil || time.Since(fetched) > time.Hour {
		if fresh, err := c.fetchTorExits(ctx); err != nil {
			log.Warn().Err(err).Msg("shield: Tor exit list fetch failed")
		} else {
			c.torMu.Lock()
			c.torExits = fresh
			c.torFetched = time.Now()
			c.torMu.Unlock()
			exits = fresh
		}
	}
	if exits == nil {
		return false
	}
	_, ok := exits[ip]
	return ok
}

// fetchTorExits downloads the Tor bulk exit list and returns a set of IPs.
func (c *Client) fetchTorExits(ctx context.Context) (map[string]struct{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.torExitURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tor exit list: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{})
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if net.ParseIP(line) != nil {
			out[line] = struct{}{}
		}
	}
	return out, nil
}
