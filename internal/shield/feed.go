// Package shield — FeedClient: distributed community threat feed.
//
// Architecture:
//   - Consumer: downloads a signed feed JSON from the aggregator every 15 min
//     (via RunShieldFeedWorker), verifies the EC P-256 ECDSA signature, and
//     caches the resulting hash→confidence map in memory for O(1) local lookup.
//   - Contributor (opt-in): when Report=true, detected brute-force IPs are
//     HMAC-SHA256 obfuscated and queued for async POST to the aggregator.
//
// Security properties:
//   - HMAC-SHA256(ip, shared_key) prevents precomputed IPv4 rainbow tables.
//   - Threshold quorum (≥5 distinct reporters) in the aggregator resists poisoning.
//   - EC P-256 feed signature prevents MITM feed injection.
//   - Feed contributes +20 to risk score only; it never directly blocks.
package shield

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/rs/zerolog/log"
)

// FeedEntry is one entry in the aggregator's signed feed JSON.
type FeedEntry struct {
	Hash       string  `json:"hash"`        // hex HMAC-SHA256(ip, shared_key)
	AttackType string  `json:"attack_type"` // e.g. "brute_force"
	Confidence float64 `json:"confidence"`  // 0.0-1.0
}

// SignedFeed is the JSON payload served by GET /v1/feed on the aggregator.
type SignedFeed struct {
	Version   int         `json:"version"`
	IssuedAt  time.Time   `json:"issued_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Entries   []FeedEntry `json:"entries"`
	// Signature is a base64url-encoded DER EC P-256 ECDSA signature over
	// SHA-256(canonical_json), where canonical_json is the feed JSON without
	// the signature field (entries sorted ascending by hash).
	Signature string `json:"signature"`
}

type reportItem struct {
	ip         string
	attackType string
	confidence float64
}

// FeedClient is a thread-safe client for the Clavex Shield distributed feed.
// Create with NewFeedClient; share for process lifetime.
type FeedClient struct {
	cfg        config.ThreatFeedConfig
	licenseJWT string
	sigPubKey  *ecdsa.PublicKey // nil → signature verification skipped (dev/test only)
	hmacKey    []byte
	httpClient *http.Client

	// reportCh buffers IPs to report asynchronously; capacity 512.
	reportCh chan reportItem

	mu     sync.RWMutex
	hashes map[string]float64 // HMAC hash → confidence; replaced atomically on Refresh

	// reported deduplicates IPs sent within the last hour.
	reportedMu sync.Mutex
	reported   map[string]time.Time
	lastEvict  time.Time
}

// NewFeedClient creates a FeedClient from the given config.
// Returns an error if SigningPubKey is non-empty but cannot be parsed.
func NewFeedClient(cfg config.ThreatFeedConfig, licenseJWT string) (*FeedClient, error) {
	var sigKey *ecdsa.PublicKey
	if cfg.SigningPubKey != "" {
		k, err := parseECPublicKey(cfg.SigningPubKey)
		if err != nil {
			return nil, fmt.Errorf("shield feed: parse signing_pub_key: %w", err)
		}
		sigKey = k
	}

	hmacKey, err := decodeKey(cfg.SharedKey)
	if err != nil {
		return nil, fmt.Errorf("shield feed: parse shared_key: %w", err)
	}

	return &FeedClient{
		cfg:        cfg,
		licenseJWT: licenseJWT,
		sigPubKey:  sigKey,
		hmacKey:    hmacKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		reportCh:   make(chan reportItem, 512),
		hashes:     make(map[string]float64),
		reported:   make(map[string]time.Time),
		lastEvict:  time.Now(),
	}, nil
}

// CheckIP returns whether ip appears in the cached distributed feed and its
// confidence score. Returns (false, 0) for private/loopback IPs.
func (c *FeedClient) CheckIP(ip string) (bool, float64) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return false, 0
	}
	h := c.hmacHex(ip)
	c.mu.RLock()
	conf, ok := c.hashes[h]
	c.mu.RUnlock()
	return ok, conf
}

// Enqueue queues ip for async reporting to the aggregator.
// No-ops when Report is disabled, for private/loopback IPs, or when the
// same IP was already reported within the last hour (per-process dedup).
// Non-blocking: drops silently if the internal channel is full.
func (c *FeedClient) Enqueue(ip, attackType string, confidence float64) {
	if !c.cfg.Report || ip == "" {
		return
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return
	}

	c.reportedMu.Lock()
	if t, seen := c.reported[ip]; seen && time.Since(t) < time.Hour {
		c.reportedMu.Unlock()
		return
	}
	c.reported[ip] = time.Now()
	if time.Since(c.lastEvict) > time.Hour {
		for k, t := range c.reported {
			if time.Since(t) > time.Hour {
				delete(c.reported, k)
			}
		}
		c.lastEvict = time.Now()
	}
	c.reportedMu.Unlock()

	select {
	case c.reportCh <- reportItem{ip: ip, attackType: attackType, confidence: confidence}:
	default: // drop if buffer is full
	}
}

// Refresh downloads the signed feed from the aggregator, verifies its
// EC P-256 signature, and atomically replaces the in-memory hash set.
func (c *FeedClient) Refresh(ctx context.Context) error {
	url := c.cfg.URL + "/v1/feed"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if c.licenseJWT != "" {
		req.Header.Set("Authorization", "Bearer "+c.licenseJWT)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("shield feed: GET /v1/feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("shield feed: GET /v1/feed: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MiB cap
	if err != nil {
		return fmt.Errorf("shield feed: read body: %w", err)
	}

	var feed SignedFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return fmt.Errorf("shield feed: unmarshal: %w", err)
	}

	if time.Now().After(feed.ExpiresAt) {
		return fmt.Errorf("shield feed: feed expired at %s", feed.ExpiresAt)
	}
	if c.sigPubKey != nil {
		if err := verifyFeedSignature(&feed, c.sigPubKey); err != nil {
			return fmt.Errorf("shield feed: %w", err)
		}
	}

	newHashes := make(map[string]float64, len(feed.Entries))
	for _, e := range feed.Entries {
		newHashes[e.Hash] = e.Confidence
	}
	c.mu.Lock()
	c.hashes = newHashes
	c.mu.Unlock()

	log.Info().Int("entries", len(newHashes)).Msg("shield: threat feed refreshed")
	return nil
}

// Start launches the background goroutine that drains the report queue and
// POSTs items to the aggregator. Call once at process startup.
func (c *FeedClient) Start(ctx context.Context) {
	go c.drainReports(ctx)
}

// UpdateLicenseJWT sets the license JWT used to authenticate reports.
// Call this after the license is loaded (e.g. from Start()).
func (c *FeedClient) UpdateLicenseJWT(jwt string) {
	c.mu.Lock()
	c.licenseJWT = jwt
	c.mu.Unlock()
}

func (c *FeedClient) drainReports(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var pending []reportItem
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-c.reportCh:
			pending = append(pending, item)
		case <-ticker.C:
			if len(pending) == 0 {
				continue
			}
			batch := pending
			pending = nil
			for _, item := range batch {
				c.sendOne(ctx, item)
			}
		}
	}
}

func (c *FeedClient) sendOne(ctx context.Context, item reportItem) {
	payload := map[string]any{
		"hash":        c.hmacHex(item.ip),
		"attack_type": item.attackType,
		"confidence":  item.confidence,
	}
	b, _ := json.Marshal(payload)
	url := c.cfg.URL + "/v1/report"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if c.licenseJWT != "" {
		req.Header.Set("Authorization", "Bearer "+c.licenseJWT)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("shield feed: report send failed")
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		log.Warn().Int("status", resp.StatusCode).Msg("shield feed: report rejected by aggregator")
	}
}

// hmacHex returns hex(HMAC-SHA256(ip, shared_key)).
func (c *FeedClient) hmacHex(ip string) string {
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil))
}

// ── Signature helpers (used by both client and aggregator) ───────────────────

// canonicalFeedJSON returns the JSON used as the signature input:
// the feed without the Signature field, entries sorted ascending by hash.
func canonicalFeedJSON(feed *SignedFeed) ([]byte, error) {
	sorted := make([]FeedEntry, len(feed.Entries))
	copy(sorted, feed.Entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Hash < sorted[j].Hash })

	type canonical struct {
		Version   int         `json:"version"`
		IssuedAt  time.Time   `json:"issued_at"`
		ExpiresAt time.Time   `json:"expires_at"`
		Entries   []FeedEntry `json:"entries"`
	}
	return json.Marshal(canonical{
		Version:   feed.Version,
		IssuedAt:  feed.IssuedAt,
		ExpiresAt: feed.ExpiresAt,
		Entries:   sorted,
	})
}

func verifyFeedSignature(feed *SignedFeed, pub *ecdsa.PublicKey) error {
	canonical, err := canonicalFeedJSON(feed)
	if err != nil {
		return fmt.Errorf("canonical JSON: %w", err)
	}
	digest := sha256.Sum256(canonical)

	sigBytes, err := base64.RawURLEncoding.DecodeString(feed.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sigBytes, &sig); err != nil {
		return fmt.Errorf("unmarshal signature ASN.1: %w", err)
	}
	if !ecdsa.Verify(pub, digest[:], sig.R, sig.S) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// SignFeed signs the feed in place using an EC P-256 private key.
// Used by the aggregator (cmd/shield-feed), not by Clavex installations.
func SignFeed(feed *SignedFeed, key *ecdsa.PrivateKey) error {
	canonical, err := canonicalFeedJSON(feed)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return err
	}
	feed.Signature = base64.RawURLEncoding.EncodeToString(der)
	return nil
}

// ── Key parsing helpers ───────────────────────────────────────────────────────

func parseECPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an EC public key")
	}
	return ec, nil
}

// decodeKey parses a hex or base64-standard-encoded key string.
// An empty string returns an empty key (HMAC degrades to plain SHA-256 — dev only).
func decodeKey(s string) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("key must be hex or base64-encoded")
}
