package ueba

import (
	"math"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
)

// buildBaseline constructs a Baseline from a slice of (hour, country, method,
// ip, ua) tuples, all marked as successful logins.
func buildBaseline(entries []struct {
	hour    int
	country string
	method  string
	ip      string
	ua      string
}) *Baseline {
	var events []*models.LoginEvent
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, e := range entries {
		t := base.Add(time.Duration(e.hour) * time.Hour)
		ip := e.ip
		cc := e.country
		ua := e.ua
		events = append(events, &models.LoginEvent{
			ID:          int64(len(events) + 1),
			OrgID:       uuid.New(),
			Status:      "success",
			AuthMethod:  e.method,
			IPAddress:   &ip,
			CountryCode: &cc,
			UserAgent:   &ua,
			CreatedAt:   t,
		})
	}
	return Build(events)
}

// mkEntry is a convenience constructor for buildBaseline entries.
func mkEntry(hour int, country, method, ip, ua string) struct {
	hour    int
	country string
	method  string
	ip      string
	ua      string
} {
	return struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}{hour, country, method, ip, ua}
}

// mkEvent creates a single LoginEvent for scoring tests.
func mkEvent(hour int, country, method, ip string) *models.LoginEvent {
	return mkEventUA(hour, country, method, ip, "")
}

func mkEventUA(hour int, country, method, ip, ua string) *models.LoginEvent {
	t := time.Date(2026, 6, 1, hour, 0, 0, 0, time.UTC)
	cc := country
	return &models.LoginEvent{
		Status:      "success",
		AuthMethod:  method,
		IPAddress:   &ip,
		CountryCode: &cc,
		UserAgent:   &ua,
		CreatedAt:   t,
	}
}

func hasFlag(flags []string, prefix string) bool {
	for _, f := range flags {
		if len(f) >= len(prefix) && f[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// ── Cold-start ────────────────────────────────────────────────────────────────

func TestScore_InsufficientBaseline(t *testing.T) {
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < minSamples-1; i++ {
		entries = append(entries, mkEntry(9, "IT", "password", "1.2.3.4", ""))
	}
	result := Score(mkEvent(3, "RO", "password", "5.6.7.8"), buildBaseline(entries), 0)
	if result.Score != 0 {
		t.Errorf("expected score=0 for insufficient baseline, got %d", result.Score)
	}
	if len(result.Flags) != 0 {
		t.Errorf("expected no flags for insufficient baseline, got %v", result.Flags)
	}
}

// ── Time-of-day ───────────────────────────────────────────────────────────────

func TestScore_TimeAnomaly(t *testing.T) {
	// User always logs in 09:00–17:00 (bins 3–5).
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < 50; i++ {
		entries = append(entries, mkEntry(9+(i%9), "IT", "passkey", "192.168.1.1", ""))
	}
	result := Score(mkEvent(3, "IT", "passkey", "192.168.1.1"), buildBaseline(entries), 0)
	if result.Score == 0 {
		t.Error("expected time anomaly signal for 03:00 login against 09-17 baseline")
	}
	if !hasFlag(result.Flags, "ueba:time_anomaly") {
		t.Errorf("expected ueba:time_anomaly flag, got %v", result.Flags)
	}
}

func TestScore_NormalTime_NoAnomaly(t *testing.T) {
	// Uniform distribution over all hours → no anomaly for any hour.
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < 48; i++ {
		entries = append(entries, mkEntry(i%24, "IT", "passkey", "10.0.0.1", ""))
	}
	result := Score(mkEvent(3, "IT", "passkey", "10.0.0.1"), buildBaseline(entries), 0)
	if hasFlag(result.Flags, "ueba:time_anomaly") {
		t.Errorf("unexpected time anomaly flag for uniform distribution: %v", result.Flags)
	}
}

// ── Country ───────────────────────────────────────────────────────────────────

func TestScore_RareCountry(t *testing.T) {
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < 50; i++ {
		entries = append(entries, mkEntry(10, "IT", "passkey", "1.2.3.4", ""))
	}
	result := Score(mkEvent(10, "RO", "passkey", "1.2.3.4"), buildBaseline(entries), 0)
	if !hasFlag(result.Flags, "ueba:rare_country") {
		t.Errorf("expected ueba:rare_country flag, got %v", result.Flags)
	}
	if result.Score == 0 {
		t.Errorf("expected score > 0 for rare country, got %d", result.Score)
	}
}

// ── Auth method ───────────────────────────────────────────────────────────────

func TestScore_AuthMethodShift(t *testing.T) {
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < 50; i++ {
		entries = append(entries, mkEntry(10, "IT", "passkey", "1.2.3.4", ""))
	}
	result := Score(mkEvent(10, "IT", "password", "1.2.3.4"), buildBaseline(entries), 0)
	if !hasFlag(result.Flags, "ueba:auth_method_shift") {
		t.Errorf("expected ueba:auth_method_shift flag, got %v", result.Flags)
	}
}

// ── Subnet ────────────────────────────────────────────────────────────────────

func TestScore_NewSubnet(t *testing.T) {
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < 20; i++ {
		entries = append(entries, mkEntry(10, "IT", "passkey", "192.168.1.100", ""))
	}
	result := Score(mkEvent(10, "IT", "passkey", "10.0.0.50"), buildBaseline(entries), 0)
	if !hasFlag(result.Flags, "ueba:new_subnet") {
		t.Errorf("expected ueba:new_subnet flag, got %v", result.Flags)
	}
	if result.Score == 0 {
		t.Errorf("expected score > 0 for new subnet, got %d", result.Score)
	}
}

// ── User-agent family ─────────────────────────────────────────────────────────

func TestScore_UAFamilyShift(t *testing.T) {
	// User always uses Chrome; now logs in with curl (credential-stuffing indicator).
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < 30; i++ {
		entries = append(entries, mkEntry(10, "IT", "password", "1.2.3.4",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"))
	}
	result := Score(mkEventUA(10, "IT", "password", "1.2.3.4", "curl/7.88.0"), buildBaseline(entries), 0)
	if !hasFlag(result.Flags, "ueba:ua_shift") {
		t.Errorf("expected ueba:ua_shift flag for curl against Chrome baseline, got %v", result.Flags)
	}
}

// ── Score cap ─────────────────────────────────────────────────────────────────

func TestScore_Cap30(t *testing.T) {
	// All signals fire simultaneously — score must be capped at 30.
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < 50; i++ {
		entries = append(entries, mkEntry(10, "IT", "passkey", "1.2.3.4",
			"Mozilla/5.0 Chrome/124.0 Safari/537.36"))
	}
	// 03:00 + RO + different subnet + password + curl = all features anomalous.
	result := Score(mkEventUA(3, "RO", "password", "9.9.9.1", "curl/7.88.0"), buildBaseline(entries), 0)
	if result.Score > 30 {
		t.Errorf("score must be capped at 30, got %d", result.Score)
	}
	if result.Score == 0 {
		t.Errorf("expected non-zero score when all features are anomalous, got 0")
	}
}

// ── Nil baseline ─────────────────────────────────────────────────────────────

func TestScore_NilBaseline(t *testing.T) {
	result := Score(mkEvent(10, "IT", "passkey", "1.2.3.4"), nil, 0)
	if result.Score != 0 || len(result.Flags) != 0 {
		t.Errorf("expected zero result for nil baseline, got score=%d flags=%v", result.Score, result.Flags)
	}
}

// ── Unit tests for helpers ────────────────────────────────────────────────────

func TestHourZScore_Uniform(t *testing.T) {
	var hist [24]int
	for i := range hist {
		hist[i] = 5
	}
	z := hourZScore(hist, 3)
	if z != 0 {
		t.Errorf("expected z=0 for uniform distribution, got %f", z)
	}
}

func TestHourZScore_Empty(t *testing.T) {
	var hist [24]int
	z := hourZScore(hist, 3)
	if z != 0 {
		t.Errorf("expected z=0 for empty histogram, got %f", z)
	}
}

func TestSmoothedProb_ZeroCount(t *testing.T) {
	p := smoothedProb(0, 100, 10)
	if p <= 0 || p >= 1 {
		t.Errorf("smoothedProb(0,100,10) = %f, expected value in (0,1)", p)
	}
}

func TestSubnet24(t *testing.T) {
	cases := []struct{ ip, want string }{
		{"192.168.1.100", "192.168.1"},
		{"10.0.0.1", "10.0.0"},
		{"not-an-ip", "not-an-ip"},
		{"::1", "::1"},
	}
	for _, tc := range cases {
		got := subnet24(tc.ip)
		if got != tc.want {
			t.Errorf("subnet24(%q) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestUAFamily(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/124.0 Safari/537.36", "Chrome"},
		{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/124.0 Safari/537.36 Edg/124.0", "Edge"},
		{"Mozilla/5.0 (X11; Linux) Gecko/20100101 Firefox/125.0", "Firefox"},
		{"Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/604.1", "Safari"},
		{"curl/7.88.0", "curl"},
		{"okhttp/4.10.0", "OkHttp"},
		{"python-requests/2.31.0", "Python"},
		{"Go-http-client/2.0", "Go"},
		{"", "none"},
		{"MyCustomAgent/1.0", "other"},
	}
	for _, tc := range cases {
		got := uaFamily(tc.ua)
		if got != tc.want {
			t.Errorf("uaFamily(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

func TestHistEntropy_Uniform(t *testing.T) {
	hist := []int{5, 5, 5, 5, 5, 5, 5, 5}
	h := histEntropy(hist, 40)
	expected := math.Log2(8) // perfectly uniform 8-bin → H = log2(8) = 3 bits
	if math.Abs(h-expected) > 0.1 {
		t.Errorf("histEntropy uniform: got %.3f, want ~%.3f", h, expected)
	}
}

func TestMapEntropy_SingleValue(t *testing.T) {
	// One dominant value → low entropy (predictable user).
	counts := map[string]int{"IT": 100}
	h := mapEntropy(counts, 100)
	// With strong concentration, entropy should be well below log2(2)=1 bit.
	if h > 0.5 {
		t.Errorf("mapEntropy single dominant value: expected low entropy, got %.3f", h)
	}
}

// ── Session velocity ──────────────────────────────────────────────────────────

func TestScore_SessionVelocity_High(t *testing.T) {
	// User whose baseline shows 0 other logins in preceding 1 h (bin 0).
	// All baseline events are spread 2 hours apart so no two fall in the same hour.
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < 50; i++ {
		entries = append(entries, mkEntry(i*2, "IT", "password", "1.2.3.4", ""))
	}
	baseline := buildBaseline(entries)

	// Score with high velocity (20 other logins in last hour) — must fire flag.
	result := Score(mkEvent(10, "IT", "password", "1.2.3.4"), baseline, 20)
	if !hasFlag(result.Flags, "ueba:session_velocity") {
		t.Errorf("expected ueba:session_velocity flag for high velocity, got %v", result.Flags)
	}
	if result.Score == 0 {
		t.Errorf("expected score > 0 for high velocity, got 0")
	}
}

func TestScore_SessionVelocity_Normal(t *testing.T) {
	// User whose baseline shows 0 other logins per hour (typical single-login pattern).
	var entries []struct {
		hour    int
		country string
		method  string
		ip      string
		ua      string
	}
	for i := 0; i < 50; i++ {
		entries = append(entries, mkEntry(i*2, "IT", "password", "1.2.3.4", ""))
	}
	baseline := buildBaseline(entries)

	// Score with normal velocity (0 other logins) — velocity flag must NOT fire.
	result := Score(mkEvent(10, "IT", "password", "1.2.3.4"), baseline, 0)
	if hasFlag(result.Flags, "ueba:session_velocity") {
		t.Errorf("unexpected ueba:session_velocity flag for normal velocity: %v", result.Flags)
	}
}

func TestVelocityBin(t *testing.T) {
	cases := []struct {
		count, want int
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{3, 2},
		{4, 3},
		{9, 3},
		{10, 4},
		{100, 4},
	}
	for _, tc := range cases {
		got := velocityBin(tc.count)
		if got != tc.want {
			t.Errorf("velocityBin(%d) = %d, want %d", tc.count, got, tc.want)
		}
	}
}

func TestBuild_VelocityBinHist_Populated(t *testing.T) {
	// Build a baseline where events are clustered: 5 events within 30 minutes,
	// then a long gap. The clustered events should land in higher velocity bins.
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	var events []*models.LoginEvent
	ip := "1.2.3.4"
	cc := "IT"
	ua := ""
	// 5 events in the same 30-minute window (high velocity).
	for i := 0; i < 5; i++ {
		events = append(events, &models.LoginEvent{
			Status:      "success",
			AuthMethod:  "password",
			IPAddress:   &ip,
			CountryCode: &cc,
			UserAgent:   &ua,
			CreatedAt:   base.Add(time.Duration(i) * 5 * time.Minute),
		})
	}
	// 15 isolated events (one per day).
	for i := 1; i <= 15; i++ {
		events = append(events, &models.LoginEvent{
			Status:      "success",
			AuthMethod:  "password",
			IPAddress:   &ip,
			CountryCode: &cc,
			UserAgent:   &ua,
			CreatedAt:   base.Add(-time.Duration(i) * 24 * time.Hour),
		})
	}
	b := Build(events)

	// The isolated events should all land in bin 0 (0 preceding logins).
	if b.VelocityBinHist[0] == 0 {
		t.Errorf("expected some events in velocity bin 0, got 0")
	}
	// The clustered events should push some counts into higher bins (≥ bin 2).
	higher := b.VelocityBinHist[2] + b.VelocityBinHist[3] + b.VelocityBinHist[4]
	if higher == 0 {
		t.Errorf("expected clustered events to populate velocity bins 2+, got histogram %v", b.VelocityBinHist)
	}
}

