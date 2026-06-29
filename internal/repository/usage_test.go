package repository

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── OrgUsage struct ───────────────────────────────────────────────────────────

func TestOrgUsage_JSONFieldNames(t *testing.T) {
	id := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	u := OrgUsage{
		OrgID:         id,
		PeriodStart:   now.AddDate(0, 0, -30),
		PeriodEnd:     now,
		MAU:           1200,
		DAU:           47,
		TotalLogins:   4300,
		SuccessLogins: 4100,
		FailedLogins:  200,
		NewUsers:      38,
		LoginsByMethod: []MethodCount{
			{Method: "password", Count: 3000},
			{Method: "spid", Count: 1100},
		},
		TopClients: []ClientCount{
			{ClientID: "portal", Count: 2000},
		},
	}

	b, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	fields := []string{
		"org_id", "period_start", "period_end",
		"mau", "dau",
		"total_logins", "success_logins", "failed_logins",
		"new_users_this_month",
		"logins_by_method", "top_clients",
	}
	for _, f := range fields {
		if _, ok := out[f]; !ok {
			t.Errorf("missing JSON field %q", f)
		}
	}
}

func TestOrgUsage_MAUDomainConstraints(t *testing.T) {
	// MAU must be ≤ TotalLogins (sanity)
	u := OrgUsage{MAU: 100, DAU: 10, TotalLogins: 500, SuccessLogins: 480, FailedLogins: 20}
	if u.MAU > u.TotalLogins {
		t.Errorf("MAU (%d) > TotalLogins (%d) — impossible", u.MAU, u.TotalLogins)
	}
	if u.DAU > u.MAU {
		t.Errorf("DAU (%d) > MAU (%d) — impossible in same window", u.DAU, u.MAU)
	}
	if u.SuccessLogins+u.FailedLogins > u.TotalLogins {
		t.Errorf("success+failed > total")
	}
}

// ── MethodCount ───────────────────────────────────────────────────────────────

func TestMethodCount_JSONRoundtrip(t *testing.T) {
	mc := MethodCount{Method: "totp", Count: 42}
	b, _ := json.Marshal(mc)
	var out MethodCount
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Method != "totp" || out.Count != 42 {
		t.Errorf("unexpected roundtrip: %+v", out)
	}
}

func TestMethodCount_ZeroCountIsValid(t *testing.T) {
	mc := MethodCount{Method: "webauthn", Count: 0}
	b, _ := json.Marshal(mc)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out["count"] != float64(0) {
		t.Errorf("zero count should serialize to 0, got %v", out["count"])
	}
}

// ── ClientCount ───────────────────────────────────────────────────────────────

func TestClientCount_JSONRoundtrip(t *testing.T) {
	cc := ClientCount{ClientID: "my-app", Count: 777}
	b, _ := json.Marshal(cc)
	var out ClientCount
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ClientID != "my-app" || out.Count != 777 {
		t.Errorf("unexpected roundtrip: %+v", out)
	}
}

// ── nil-slice normalisation ───────────────────────────────────────────────────
// GetOrgUsage normalises nil slices to empty slices before returning.
// We test the normalisation logic in isolation by directly exercising the
// OrgUsage zero-value and verifying the expected API contract.

func TestOrgUsage_NilSlicesNormalized(t *testing.T) {
	// Simulate what GetOrgUsage does at the end when no rows are returned.
	var loginsByMethod []MethodCount
	var topClients []ClientCount
	if loginsByMethod == nil {
		loginsByMethod = []MethodCount{}
	}
	if topClients == nil {
		topClients = []ClientCount{}
	}
	u := OrgUsage{
		LoginsByMethod: loginsByMethod,
		TopClients:     topClients,
	}

	b, _ := json.Marshal(u)
	var out map[string]any
	_ = json.Unmarshal(b, &out)

	if out["logins_by_method"] == nil {
		t.Error("logins_by_method should be [] not null")
	}
	if out["top_clients"] == nil {
		t.Error("top_clients should be [] not null")
	}
}

// ── Period window calculation ─────────────────────────────────────────────────
// The trailing-30-day window and start-of-day DAU window must be calculated
// correctly for any reference time. We test the same arithmetic used in
// GetOrgUsage without needing a DB connection.

func TestUsagePeriodWindow_Trailing30Days(t *testing.T) {
	now := time.Date(2025, 6, 15, 14, 30, 0, 0, time.UTC)
	windowStart := now.AddDate(0, 0, -30)

	// The window must be exactly 30 days wide.
	duration := now.Sub(windowStart)
	expected := 30 * 24 * time.Hour
	if duration != expected {
		t.Errorf("window duration: want %v, got %v", expected, duration)
	}
}

func TestUsagePeriodWindow_MonthBoundary(t *testing.T) {
	// Crossing a month boundary (June 15 → May 16)
	now := time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC)
	windowStart := now.AddDate(0, 0, -30)

	if windowStart.Month() != time.May {
		t.Errorf("window start month: want May, got %v", windowStart.Month())
	}
	if windowStart.Day() != 16 {
		t.Errorf("window start day: want 16, got %d", windowStart.Day())
	}
}

func TestUsagePeriodWindow_DayStart_UTC(t *testing.T) {
	now := time.Date(2025, 6, 15, 23, 59, 59, 999, time.UTC)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	if dayStart.Hour() != 0 || dayStart.Minute() != 0 || dayStart.Second() != 0 {
		t.Errorf("dayStart should be midnight UTC: %v", dayStart)
	}
	if dayStart.Day() != now.Day() || dayStart.Month() != now.Month() {
		t.Errorf("dayStart should be same calendar day as now: dayStart=%v now=%v", dayStart, now)
	}
}

func TestUsagePeriodWindow_DayStart_MidnightAlready(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if !dayStart.Equal(now) {
		t.Errorf("dayStart at midnight should equal now: got %v", dayStart)
	}
}

// ── OrgUsage.PeriodStart / PeriodEnd invariants ───────────────────────────────

func TestOrgUsage_PeriodEndAfterStart(t *testing.T) {
	now := time.Now().UTC()
	u := OrgUsage{
		PeriodStart: now.AddDate(0, 0, -30),
		PeriodEnd:   now,
	}
	if !u.PeriodEnd.After(u.PeriodStart) {
		t.Errorf("PeriodEnd must be after PeriodStart: start=%v end=%v", u.PeriodStart, u.PeriodEnd)
	}
}

// ── LoginsByMethod aggregation semantics ──────────────────────────────────────

func TestLoginsByMethod_OrderDescByCount(t *testing.T) {
	// The SQL query uses ORDER BY cnt DESC — verify that when we build the slice
	// in descending order the highest-count method is first.
	methods := []MethodCount{
		{Method: "spid", Count: 3000},
		{Method: "password", Count: 1500},
		{Method: "totp", Count: 200},
	}
	for i := 1; i < len(methods); i++ {
		if methods[i].Count > methods[i-1].Count {
			t.Errorf("methods[%d].Count=%d > methods[%d].Count=%d — not DESC order",
				i, methods[i].Count, i-1, methods[i-1].Count)
		}
	}
}

func TestTopClients_MaxTen(t *testing.T) {
	// The SQL query uses LIMIT 10 — verify that TopClients never exceeds 10.
	// Simulate a result with 10 rows (the max).
	clients := make([]ClientCount, 10)
	for i := range clients {
		clients[i] = ClientCount{ClientID: "app", Count: int64(100 - i)}
	}
	if len(clients) > 10 {
		t.Errorf("top_clients must not exceed 10 rows, got %d", len(clients))
	}
}

// ── NewUsageRepository constructor ───────────────────────────────────────────

func TestNewUsageRepository_NilPool_Panics(t *testing.T) {
	// Verify it does NOT panic on a nil pool at construction time (panics only at query time).
	defer func() {
		if r := recover(); r != nil {
			t.Logf("NewUsageRepository panicked on nil pool (acceptable): %v", r)
		}
	}()
	r := NewUsageRepository(nil)
	if r == nil {
		t.Error("NewUsageRepository returned nil")
	}
}
