package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func strPtr(s string) *string { return &s }

// mkEvent builds a minimal LoginEvent for testing scoreEvents.
var mkEventSeq int64

func mkEvent(status, country string, t time.Time) *models.LoginEvent {
	mkEventSeq++
	var cc *string
	if country != "" {
		cc = strPtr(country)
	}
	return &models.LoginEvent{
		ID:          mkEventSeq,
		Status:      status,
		CountryCode: cc,
		CreatedAt:   t,
	}
}

// ── scoreLevel ────────────────────────────────────────────────────────────────

func TestScoreLevel(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "low"},
		{10, "low"},
		{19, "low"},
		{20, "medium"},
		{39, "medium"},
		{40, "high"},
		{69, "high"},
		{70, "critical"},
		{100, "critical"},
	}
	for _, tc := range cases {
		got := scoreLevel(tc.score)
		if got != tc.want {
			t.Errorf("scoreLevel(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// ── isDatacenterASN ───────────────────────────────────────────────────────────

func TestIsDatacenterASN_Known(t *testing.T) {
	positives := []string{
		"AMAZON-02",
		"Amazon Technologies Inc.",
		"Google Cloud LLC",
		"MICROSOFT-AZURE",
		"DigitalOcean, LLC",
		"Linode, LLC",
		"Vultr Holdings LLC",
		"Hetzner Online GmbH",
		"OVH SAS",
		"LeaseWeb Netherlands B.V.",
		"Cloudflare, Inc.",
		"Fastly, Inc.",
		"Akamai Technologies",
		"Tor Exit Node",
		"NordVPN",
		"ExpressVPN",
		"Mullvad VPN",
		"ProtonVPN AG",
		"Great Hosting Provider Ltd.",
		"Some Datacenter Corp.",
		"Data Center Network",
	}
	for _, asn := range positives {
		if !isDatacenterASN(asn) {
			t.Errorf("isDatacenterASN(%q) = false, want true", asn)
		}
	}
}

func TestIsDatacenterASN_Benign(t *testing.T) {
	benign := []string{
		"Deutsche Telekom AG",
		"Comcast Cable Communications",
		"British Telecom",
		"Orange SA",
		"Vodafone GmbH",
		"Swisscom AG",
		"AT&T Services, Inc.",
	}
	for _, asn := range benign {
		if isDatacenterASN(asn) {
			t.Errorf("isDatacenterASN(%q) = true, want false", asn)
		}
	}
}

// ── uaFingerprint ─────────────────────────────────────────────────────────────

func TestUAFingerprint_ShortUA(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64)"
	got := uaFingerprint(ua)
	if got != ua {
		t.Errorf("short UA changed: %q", got)
	}
}

func TestUAFingerprint_LongUA_Truncated(t *testing.T) {
	ua := make([]byte, 200)
	for i := range ua {
		ua[i] = 'A'
	}
	got := uaFingerprint(string(ua))
	if len(got) != 80 {
		t.Errorf("expected 80-char fingerprint, got %d", len(got))
	}
}

func TestUAFingerprint_Exactly80(t *testing.T) {
	ua := make([]byte, 80)
	for i := range ua {
		ua[i] = 'B'
	}
	got := uaFingerprint(string(ua))
	if len(got) != 80 {
		t.Errorf("expected 80, got %d", len(got))
	}
}

func TestUAFingerprint_DifferentUA(t *testing.T) {
	fp1 := uaFingerprint("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	fp2 := uaFingerprint("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	if fp1 == fp2 {
		t.Error("different UAs should have different fingerprints")
	}
}

// ── scoreEvents: impossible travel ────────────────────────────────────────────

// baseNow is a fixed reference point in the middle of the day to avoid
// the unusual-hour signal interfering with impossible-travel assertions.
var baseNow = time.Date(2025, 6, 15, 14, 0, 0, 0, time.UTC)

func TestScoreEvents_ImpossibleTravel_TwoCountriesWithin2h(t *testing.T) {
	// Login from IT at T-0, then from FR 90 minutes later — both within 24h.
	// Travel time between Italy and France is physical impossible in 90 minutes.
	t0 := baseNow.Add(-2 * time.Hour)    // older event (FR)
	t1 := baseNow.Add(-30 * time.Minute) // newer event (IT) — mostRecent

	events := []*models.LoginEvent{
		mkEvent("success", "IT", t1),
		mkEvent("success", "FR", t0),
	}
	score := scoreEvents(events, baseNow)

	if score.Score < 25 {
		t.Errorf("impossible travel should add ≥25 points, got score=%d reasons=%v", score.Score, score.Reason)
	}
	found := false
	for _, r := range score.Reason {
		if strings.HasPrefix(r, "impossible_travel:") {
			found = true
			// Reason should name both countries.
			if !strings.Contains(r, "IT") || !strings.Contains(r, "FR") {
				t.Errorf("impossible_travel reason should mention both countries, got %q", r)
			}
		}
	}
	if !found {
		t.Errorf("expected impossible_travel reason, got %v", score.Reason)
	}
}

func TestScoreEvents_ImpossibleTravel_ExactlyAtBoundary(t *testing.T) {
	// Two logins exactly 2h apart — the window is strict <2h, so this must NOT trigger.
	t0 := baseNow.Add(-4 * time.Hour)
	t1 := baseNow.Add(-2 * time.Hour) // exactly 2h after t0

	events := []*models.LoginEvent{
		mkEvent("success", "DE", t1),
		mkEvent("success", "JP", t0),
	}
	score := scoreEvents(events, baseNow)

	for _, r := range score.Reason {
		if strings.HasPrefix(r, "impossible_travel:") {
			t.Errorf("logins exactly 2h apart should NOT trigger impossible travel, got reason %q", r)
		}
	}
}

func TestScoreEvents_ImpossibleTravel_SameCountry(t *testing.T) {
	// Two logins from the same country — never impossible travel.
	t0 := baseNow.Add(-90 * time.Minute)
	t1 := baseNow.Add(-10 * time.Minute)

	events := []*models.LoginEvent{
		mkEvent("success", "DE", t1),
		mkEvent("success", "DE", t0),
	}
	score := scoreEvents(events, baseNow)

	for _, r := range score.Reason {
		if strings.HasPrefix(r, "impossible_travel:") {
			t.Errorf("same-country logins should not trigger impossible travel, got reason %q", r)
		}
	}
}

func TestScoreEvents_ImpossibleTravel_MoreThan2hApart(t *testing.T) {
	// Two logins >2h apart — too slow to be impossible travel by this scorer.
	t0 := baseNow.Add(-5 * time.Hour)
	t1 := baseNow.Add(-1 * time.Hour)

	events := []*models.LoginEvent{
		mkEvent("success", "BR", t1),
		mkEvent("success", "US", t0),
	}
	score := scoreEvents(events, baseNow)

	for _, r := range score.Reason {
		if strings.HasPrefix(r, "impossible_travel:") {
			t.Errorf("logins >2h apart should not trigger impossible travel, got reason %q", r)
		}
	}
}

func TestScoreEvents_ImpossibleTravel_OnlyOneLoginEvent(t *testing.T) {
	// Single login — no travel possible.
	events := []*models.LoginEvent{
		mkEvent("success", "IT", baseNow.Add(-1*time.Hour)),
	}
	score := scoreEvents(events, baseNow)

	for _, r := range score.Reason {
		if strings.HasPrefix(r, "impossible_travel:") {
			t.Errorf("single login should not trigger impossible travel, got reason %q", r)
		}
	}
}

func TestScoreEvents_ImpossibleTravel_RaisesScoreToHighOrCritical(t *testing.T) {
	// Impossible travel alone (+25) puts the score at "high" (≥40 requires other signals).
	// Combined with a new country (+15) it should reach "high".
	t0 := baseNow.Add(-90 * time.Minute)
	t1 := baseNow.Add(-10 * time.Minute)

	events := []*models.LoginEvent{
		mkEvent("success", "CN", t1), // new country for mostRecent
		mkEvent("success", "AU", t0),
	}
	score := scoreEvents(events, baseNow)

	// impossible_travel (+25) + new_country (+15) = 40 → "high"
	if score.Level != "high" && score.Level != "critical" {
		t.Errorf("IT+new_country should be high or critical, got level=%q score=%d", score.Level, score.Score)
	}
}

func TestScoreEvents_ImpossibleTravel_EmptyEvents(t *testing.T) {
	score := scoreEvents(nil, baseNow)
	if score.Score != 0 || score.Level != "low" {
		t.Errorf("empty events should be score=0/low, got %d/%s", score.Score, score.Level)
	}
}
