package risk

// Package risk computes a composite identity risk score (0-100) for a user by
// aggregating multiple signals from login_history and session data.
//
// Signal weights (additive, capped at 100):
//
//   +30  Recent login failures (≥3 in last 24 h in same org)
//   +15  New-country signal   (country not seen in last 90 days for this user)
//   +20  Datacenter / VPN ASN (heuristic: ASN name contains known cloud keywords)
//   +10  Unusual hour         (login outside 06:00–22:00 UTC)
//   +15  Device fingerprint   (device not seen in last 90 days)
//   +25  Impossible travel    (two logins from different countries within 2 h)
//   +30  UEBA behavioural anomaly (personalised time/country/method/subnet distribution,
//        computed by internal/ueba on top of historical successful logins)

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/shield"
	"github.com/clavex-eu/clavex/internal/ueba"
	"github.com/google/uuid"
)

// Score is the full risk assessment for a user at a point in time.
type Score struct {
	Score  int      `json:"score"`  // 0-100
	Level  string   `json:"level"`  // "low" | "medium" | "high" | "critical"
	Reason []string `json:"reason"` // human-readable contributing factors
}

// Scorer computes identity risk scores from login history.
type Scorer struct {
	history  *repository.LoginHistoryRepository
	threatIP *shield.Client     // nil when AbuseIPDB/Tor intel is disabled
	feed     *shield.FeedClient // nil when distributed threat feed is disabled
}

// NewScorer creates a Scorer backed by the given repository.
// Pass non-nil clients to enable threat-intelligence enrichment.
func NewScorer(history *repository.LoginHistoryRepository, threatIP *shield.Client, feed *shield.FeedClient) *Scorer {
	return &Scorer{history: history, threatIP: threatIP, feed: feed}
}

// Compute returns the current risk score for a user within an org.
func (s *Scorer) Compute(ctx context.Context, orgID, userID uuid.UUID) (*Score, error) {
	page, err := s.history.ListLoginHistory(ctx, repository.ListLoginHistoryParams{
		OrgID:  &orgID,
		UserID: &userID,
		Since:  time.Now().UTC().Add(-90 * 24 * time.Hour),
		Limit:  500,
	})
	if err != nil {
		return nil, fmt.Errorf("risk scorer: %w", err)
	}

	sc := scoreEvents(page.Items, time.Now().UTC())

	// ── Threat-intelligence enrichment ─────────────────────────────────────────
	// Check the most-recent event's source IP against external threat feeds.
	if s.threatIP != nil && len(page.Items) > 0 {
		if ip := page.Items[0].IPAddress; ip != nil && *ip != "" {
			verdict := s.threatIP.Check(ctx, *ip)
			if verdict.IsMalicious {
				sc.Score += 20
				if sc.Score > 100 {
					sc.Score = 100
				}
				for _, src := range verdict.Sources {
					sc.Reason = append(sc.Reason, "threat_intel:"+src)
				}
				sc.Level = scoreLevel(sc.Score)
			}
		}
	}

	// ── Distributed threat feed (Clavex Shield) ────────────────────────────────
	// Check the most-recent IP against the community threat feed and auto-report
	// brute-force source IPs back to the aggregator (opt-in, non-blocking).
	if s.feed != nil && len(page.Items) > 0 {
		if ip := page.Items[0].IPAddress; ip != nil && *ip != "" {
			if inFeed, conf := s.feed.CheckIP(*ip); inFeed {
				sc.Score += 20
				if sc.Score > 100 {
					sc.Score = 100
				}
				sc.Reason = append(sc.Reason, fmt.Sprintf("shield_feed:%.0f%%", conf*100))
				sc.Level = scoreLevel(sc.Score)
			}
		}
		recentCutoff := time.Now().UTC().Add(-24 * time.Hour)
		for _, ev := range page.Items {
			if ev.Status == "failure" && ev.IPAddress != nil && ev.CreatedAt.After(recentCutoff) {
				s.feed.Enqueue(*ev.IPAddress, "brute_force", 0.9)
			}
		}
	}

	return sc, nil
}

// OrgSummary returns the aggregated risk dashboard for an organisation.
// It delegates to the login history repository for the heavy SQL work.
func (s *Scorer) OrgSummary(ctx context.Context, orgID uuid.UUID) (*repository.OrgRiskSummary, error) {
	return s.history.GetOrgRiskSummary(ctx, orgID)
}

// scoreEvents is the pure scoring function. Exposed for unit tests.
// now is passed explicitly so tests can control the clock.
func scoreEvents(events []*models.LoginEvent, now time.Time) *Score {
	if len(events) == 0 {
		return &Score{Score: 0, Level: "low"}
	}

	recentCutoff := now.Add(-24 * time.Hour)

	knownCountries := map[string]bool{}
	knownDevices := map[string]bool{}
	for _, ev := range events {
		if ev.CreatedAt.Before(recentCutoff) {
			if ev.CountryCode != nil {
				knownCountries[*ev.CountryCode] = true
			}
			if ev.UserAgent != nil {
				knownDevices[uaFingerprint(*ev.UserAgent)] = true
			}
		}
	}

	var (
		recentFailures     int
		mostRecent         *models.LoginEvent
		lastSuccessCountry string
		lastSuccessTime    time.Time
		impossibleTravel   string
	)

	for i := range events {
		ev := events[i]
		if ev.CreatedAt.Before(recentCutoff) {
			continue
		}
		if ev.Status == "failure" {
			recentFailures++
		}
		if mostRecent == nil {
			mostRecent = ev
		}
		if ev.Status == "success" && ev.CountryCode != nil && *ev.CountryCode != "" {
			c := *ev.CountryCode
			if lastSuccessCountry != "" && lastSuccessCountry != c && !lastSuccessTime.IsZero() {
				diff := lastSuccessTime.Sub(ev.CreatedAt)
				if diff < 0 {
					diff = -diff
				}
				if diff < 2*time.Hour && impossibleTravel == "" {
					impossibleTravel = lastSuccessCountry + "→" + c
				}
			}
			if impossibleTravel == "" {
				lastSuccessCountry = c
				lastSuccessTime = ev.CreatedAt
			}
		}
	}

	total := 0
	var reasons []string
	add := func(pts int, reason string) {
		total += pts
		reasons = append(reasons, reason)
	}

	if recentFailures >= 3 {
		pts := 15 + int(math.Min(float64(recentFailures-3)*3, 15))
		add(pts, fmt.Sprintf("recent_failures:%d_in_24h", recentFailures))
	}
	if impossibleTravel != "" {
		add(25, "impossible_travel:"+impossibleTravel)
	}
	if mostRecent != nil {
		if mostRecent.CountryCode != nil && *mostRecent.CountryCode != "" &&
			!knownCountries[*mostRecent.CountryCode] {
			add(15, "new_country:"+*mostRecent.CountryCode)
		}
		if mostRecent.ASNOrg != nil && isDatacenterASN(*mostRecent.ASNOrg) {
			add(20, "datacenter_or_vpn_asn")
		}
		h := mostRecent.CreatedAt.UTC().Hour()
		if h < 6 || h >= 22 {
			add(10, fmt.Sprintf("unusual_hour:%02d:xx_utc", h))
		}
		if mostRecent.UserAgent != nil && *mostRecent.UserAgent != "" &&
			!knownDevices[uaFingerprint(*mostRecent.UserAgent)] {
			add(15, "new_device_fingerprint")
		}
	}

	// ── UEBA: behavioural-baseline statistical anomaly ─────────────────────────
	// events[0] is the most-recent (current) event; events[1:] form the baseline.
	// Requires at least 2 events (1 current + ≥1 historical) to produce output;
	// internally Build() further requires minSamples successful events.
	if len(events) >= 2 {
		// Session velocity: count successful logins in the 1 h before events[0].
		// The event slice is sorted newest-first so we can break early once we
		// pass the 1-hour horizon — no extra DB query required.
		recentCount := 0
		t0 := events[0].CreatedAt
		for _, ev := range events[1:] {
			if t0.Sub(ev.CreatedAt) <= time.Hour {
				if ev.Status == "success" {
					recentCount++
				}
			} else {
				break
			}
		}
		uebaResult := ueba.Score(events[0], ueba.Build(events[1:]), recentCount)
		total += uebaResult.Score
		reasons = append(reasons, uebaResult.Flags...)
	}

	if total > 100 {
		total = 100
	}
	return &Score{Score: total, Level: scoreLevel(total), Reason: reasons}
}

func scoreLevel(s int) string {
	switch {
	case s >= 70:
		return "critical"
	case s >= 40:
		return "high"
	case s >= 20:
		return "medium"
	default:
		return "low"
	}
}

var datacenterKeywords = []string{
	"amazon", "aws", "google cloud", "microsoft azure", "microsoft-azure", "digitalocean",
	"linode", "vultr", "hetzner", "ovh", "leaseweb",
	"cloudflare", "fastly", "akamai", "tor exit", "nordvpn",
	"expressvpn", "mullvad", "protonvpn", "hosting", "datacenter", "data center",
}

func isDatacenterASN(asn string) bool {
	lower := strings.ToLower(asn)
	for _, kw := range datacenterKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func uaFingerprint(ua string) string {
	if len(ua) > 80 {
		return ua[:80]
	}
	return ua
}
