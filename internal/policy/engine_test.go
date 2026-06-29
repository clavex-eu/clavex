package policy

import (
	"testing"
	"time"
)

// boolPtr is a helper to get a *bool.
func boolPtr(b bool) *bool { return &b }

// ── Evaluate ──────────────────────────────────────────────────────────────────

func TestEvaluate_NilPolicy(t *testing.T) {
	out := Evaluate(nil, EvalInput{})
	if out.Action != ActionAllow {
		t.Fatalf("want allow, got %q", out.Action)
	}
}

func TestEvaluate_EmptyPolicy(t *testing.T) {
	out := Evaluate(&Policy{}, EvalInput{})
	if out.Action != ActionAllow {
		t.Fatalf("want allow, got %q", out.Action)
	}
}

func TestEvaluate_AllowRule(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name: "open", Priority: 10, Enabled: true, Action: ActionAllow,
	}}}
	out := Evaluate(p, EvalInput{})
	if out.Action != ActionAllow || out.RuleName != "open" {
		t.Fatalf("unexpected outcome: %+v", out)
	}
}

func TestEvaluate_DenyRule(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name: "block-all", Priority: 10, Enabled: true, Action: ActionDeny,
	}}}
	out := Evaluate(p, EvalInput{})
	if !out.IsDeny() {
		t.Fatalf("expected deny, got %+v", out)
	}
}

func TestEvaluate_RequireMFA(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:     "force-mfa",
		Priority: 10,
		Enabled:  true,
		Action:   ActionRequireMFA,
	}}}
	out := Evaluate(p, EvalInput{})
	if !out.IsMFARequired() || !out.MFAForced {
		t.Fatalf("expected MFA forced, got %+v", out)
	}
}

func TestEvaluate_StepUpAlias(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:     "step-up",
		Priority: 10,
		Enabled:  true,
		Action:   ActionStepUp,
	}}}
	out := Evaluate(p, EvalInput{})
	if !out.IsMFARequired() {
		t.Fatalf("step_up should be treated as require_mfa: %+v", out)
	}
}

func TestEvaluate_DisabledRuleSkipped(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Name: "skip-me", Priority: 5, Enabled: false, Action: ActionDeny},
		{Name: "allow", Priority: 10, Enabled: true, Action: ActionAllow},
	}}
	out := Evaluate(p, EvalInput{})
	if out.Action != ActionAllow {
		t.Fatalf("disabled rule should be skipped; got %+v", out)
	}
}

func TestEvaluate_PriorityOrder(t *testing.T) {
	// Lower priority number = evaluated first.
	p := &Policy{Rules: []Rule{
		{Name: "high-p", Priority: 1, Enabled: true, Action: ActionDeny},
		{Name: "low-p", Priority: 100, Enabled: true, Action: ActionAllow},
	}}
	out := Evaluate(p, EvalInput{})
	if out.Action != ActionDeny || out.RuleName != "high-p" {
		t.Fatalf("expected high-priority rule to win; got %+v", out)
	}
}

// ── IP CIDR ───────────────────────────────────────────────────────────────────

func TestEvaluate_IPCIDRMatch(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:       "block-internal",
		Priority:   10,
		Enabled:    true,
		Action:     ActionDeny,
		Conditions: Conditions{IPCIDRs: []string{"10.0.0.0/8"}},
	}}}
	out := Evaluate(p, EvalInput{IPAddress: "10.1.2.3"})
	if !out.IsDeny() {
		t.Fatalf("IP in CIDR should be denied; got %+v", out)
	}
}

func TestEvaluate_IPCIDRNoMatch(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:       "block-internal",
		Priority:   10,
		Enabled:    true,
		Action:     ActionDeny,
		Conditions: Conditions{IPCIDRs: []string{"10.0.0.0/8"}},
	}}}
	out := Evaluate(p, EvalInput{IPAddress: "8.8.8.8"})
	if out.Action != ActionAllow {
		t.Fatalf("IP outside CIDR should fall through to allow; got %+v", out)
	}
}

func TestIPMatchesCIDRs_BareIP(t *testing.T) {
	if !ipMatchesCIDRs("192.168.1.1", []string{"192.168.1.1"}) {
		t.Fatal("bare IP match failed")
	}
	if ipMatchesCIDRs("192.168.1.2", []string{"192.168.1.1"}) {
		t.Fatal("bare IP mismatch not caught")
	}
}

func TestIPMatchesCIDRs_IPv6(t *testing.T) {
	if !ipMatchesCIDRs("::1", []string{"::1/128"}) {
		t.Fatal("IPv6 loopback should match")
	}
}

// ── Country conditions ────────────────────────────────────────────────────────

func TestEvaluate_CountryDenylist(t *testing.T) {
	// NotCountries: fire the rule only if country is NOT in the list.
	// So: deny for all countries except CN/RU (rule matches when country is NOT CN/RU).
	p := &Policy{Rules: []Rule{{
		Name:       "allow-eu",
		Priority:   10,
		Enabled:    true,
		Action:     ActionDeny,
		Conditions: Conditions{NotCountries: []string{"CN", "RU"}},
	}}}
	// IT is NOT in the denylist → condition matches → deny
	if !Evaluate(p, EvalInput{Country: "IT"}).IsDeny() {
		t.Fatal("IT not in country_not list should trigger deny rule")
	}
	// CN IS in the denylist → condition fails → no rule matches → allow
	if Evaluate(p, EvalInput{Country: "CN"}).IsDeny() {
		t.Fatal("CN in country_not list means rule skipped → allow")
	}
}

func TestEvaluate_CountryAllowlistPositive(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:       "eu-mfa",
		Priority:   10,
		Enabled:    true,
		Action:     ActionRequireMFA,
		Conditions: Conditions{Countries: []string{"DE", "FR"}},
	}}}
	if !Evaluate(p, EvalInput{Country: "DE"}).IsMFARequired() {
		t.Fatal("DE should require MFA")
	}
	if Evaluate(p, EvalInput{Country: "US"}).IsMFARequired() {
		t.Fatal("US should not require MFA")
	}
}

// ── MFA enrolled ──────────────────────────────────────────────────────────────

func TestEvaluate_MFAEnrolledCondition(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:       "unenrolled-deny",
		Priority:   10,
		Enabled:    true,
		Action:     ActionDeny,
		Conditions: Conditions{MFAEnrolled: boolPtr(false)},
	}}}
	if !Evaluate(p, EvalInput{MFAEnrolled: false}).IsDeny() {
		t.Fatal("unenrolled user should be denied")
	}
	if Evaluate(p, EvalInput{MFAEnrolled: true}).IsDeny() {
		t.Fatal("enrolled user should not be denied")
	}
}

// ── New country ───────────────────────────────────────────────────────────────

func TestEvaluate_NewCountry(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:       "new-country-mfa",
		Priority:   10,
		Enabled:    true,
		Action:     ActionRequireMFA,
		Conditions: Conditions{NewCountry: boolPtr(true)},
	}}}
	if !Evaluate(p, EvalInput{NewCountry: true}).IsMFARequired() {
		t.Fatal("new country should require MFA")
	}
	if Evaluate(p, EvalInput{NewCountry: false}).IsMFARequired() {
		t.Fatal("known country should not require MFA")
	}
}

// ── Hour range ────────────────────────────────────────────────────────────────

func TestEvaluate_HourRangeNormal(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:       "office-hours-only",
		Priority:   10,
		Enabled:    true,
		Action:     ActionDeny,
		Conditions: Conditions{HourRange: &HourRange{From: 9, To: 17}},
	}}}
	// 14:00 UTC → within range → deny
	t14, _ := time.Parse(time.RFC3339, "2024-01-15T14:00:00Z")
	if !Evaluate(p, EvalInput{RequestTime: t14}).IsDeny() {
		t.Fatal("14:00 within 9-17 should be denied")
	}
	// 20:00 UTC → outside range → allow
	t20, _ := time.Parse(time.RFC3339, "2024-01-15T20:00:00Z")
	if Evaluate(p, EvalInput{RequestTime: t20}).IsDeny() {
		t.Fatal("20:00 outside 9-17 should not be denied")
	}
}

func TestEvaluate_HourRangeWrapAround(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:     "night-mfa",
		Priority: 10,
		Enabled:  true,
		Action:   ActionRequireMFA,
		// 22:00 → 06:00 UTC (night window)
		Conditions: Conditions{HourRange: &HourRange{From: 22, To: 6}},
	}}}
	t23, _ := time.Parse(time.RFC3339, "2024-01-15T23:00:00Z")
	if !Evaluate(p, EvalInput{RequestTime: t23}).IsMFARequired() {
		t.Fatal("23:00 in night window should require MFA")
	}
	t03, _ := time.Parse(time.RFC3339, "2024-01-15T03:00:00Z")
	if !Evaluate(p, EvalInput{RequestTime: t03}).IsMFARequired() {
		t.Fatal("03:00 in night window should require MFA")
	}
	t12, _ := time.Parse(time.RFC3339, "2024-01-15T12:00:00Z")
	if Evaluate(p, EvalInput{RequestTime: t12}).IsMFARequired() {
		t.Fatal("12:00 not in night window should not require MFA")
	}
}

// ── LastLoginBefore ───────────────────────────────────────────────────────────

func TestEvaluate_LastLoginBeforeNilLastLogin(t *testing.T) {
	// A user who has never logged in → LastLoginAt = nil → should match.
	p := &Policy{Rules: []Rule{{
		Name:       "inactive-deny",
		Priority:   10,
		Enabled:    true,
		Action:     ActionDeny,
		Conditions: Conditions{LastLoginBefore: "720h"}, // 30 days
	}}}
	if !Evaluate(p, EvalInput{LastLoginAt: nil}).IsDeny() {
		t.Fatal("never logged in should match last_login_before")
	}
}

func TestEvaluate_LastLoginBeforeOldLogin(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:       "stale-deny",
		Priority:   10,
		Enabled:    true,
		Action:     ActionDeny,
		Conditions: Conditions{LastLoginBefore: "720h"},
	}}}
	oldLogin := time.Now().Add(-800 * time.Hour)
	if !Evaluate(p, EvalInput{LastLoginAt: &oldLogin}).IsDeny() {
		t.Fatal("login 800h ago should match last_login_before=720h")
	}
}

func TestEvaluate_LastLoginBeforeRecentLogin(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:       "stale-deny",
		Priority:   10,
		Enabled:    true,
		Action:     ActionDeny,
		Conditions: Conditions{LastLoginBefore: "720h"},
	}}}
	recent := time.Now().Add(-1 * time.Hour)
	if Evaluate(p, EvalInput{LastLoginAt: &recent}).IsDeny() {
		t.Fatal("recent login should NOT match last_login_before=720h")
	}
}

// ── SortedRules / MatchAll exports ───────────────────────────────────────────

func TestSortedRules(t *testing.T) {
	rules := []Rule{
		{Name: "c", Priority: 30},
		{Name: "a", Priority: 10},
		{Name: "b", Priority: 20},
	}
	sorted := SortedRules(rules)
	if sorted[0].Name != "a" || sorted[1].Name != "b" || sorted[2].Name != "c" {
		t.Fatalf("unexpected sort order: %v", sorted)
	}
}

func TestMatchAll_EmptyConditions(t *testing.T) {
	if !MatchAll(Conditions{}, EvalInput{}) {
		t.Fatal("empty conditions should always match")
	}
}
