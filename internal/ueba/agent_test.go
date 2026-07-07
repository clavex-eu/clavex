package ueba

import (
	"testing"
	"time"
)

// steadyBaseline builds an AgentBaseline that has been observed for `hours`
// hours with `total` recorded calls (so mean ≈ total/hours per hour) and the
// given historical scope distribution.
func steadyBaseline(total, hours int, scopes map[string]int) *AgentBaseline {
	return &AgentBaseline{
		TotalCalls:  total,
		FirstSeen:   time.Now().Add(-time.Duration(hours) * time.Hour),
		ScopeCounts: scopes,
	}
}

// ── Cold-start ────────────────────────────────────────────────────────────────

func TestAgentScore_NilBaseline(t *testing.T) {
	r := AgentScore(100, "mcp:write", nil)
	if r.Score != 0 || len(r.Flags) != 0 {
		t.Errorf("expected zero result for nil baseline, got score=%d flags=%v", r.Score, r.Flags)
	}
}

func TestAgentScore_InsufficientBaseline(t *testing.T) {
	// Fewer than minAgentSamples events → scorer stays silent even for a burst
	// with a novel scope.
	b := steadyBaseline(minAgentSamples-1, 100, map[string]int{"mcp:read": minAgentSamples - 1})
	r := AgentScore(500, "mcp:admin", b)
	if r.Score != 0 {
		t.Errorf("expected score=0 below minAgentSamples, got %d", r.Score)
	}
	if len(r.Flags) != 0 {
		t.Errorf("expected no flags below minAgentSamples, got %v", r.Flags)
	}
}

// ── Normal steady-state ─────────────────────────────────────────────────────────

func TestAgentScore_NormalSteadyState(t *testing.T) {
	// 200 calls over 100h → mean 2/h. Current hour 2 calls with a known scope:
	// no burst, no drift → score 0.
	b := steadyBaseline(200, 100, map[string]int{"mcp:read": 180, "openid": 200})
	r := AgentScore(2, "mcp:read openid", b)
	if r.Score != 0 {
		t.Errorf("expected score=0 for steady rate + known scope, got %d (flags %v)", r.Score, r.Flags)
	}
	if len(r.Flags) != 0 {
		t.Errorf("expected no flags for normal activity, got %v", r.Flags)
	}
}

func TestAgentScore_SlightlyElevated_NoFlag(t *testing.T) {
	// Mean 2/h, current 3/h (1.5×) with a known scope: below the 15-point flag
	// gate, must not raise a burst flag.
	b := steadyBaseline(200, 100, map[string]int{"mcp:read": 200})
	r := AgentScore(3, "mcp:read", b)
	if hasFlag(r.Flags, "ueba:agent_call_burst") {
		t.Errorf("did not expect burst flag for 1.5x rate, got %v", r.Flags)
	}
}

// ── Call-rate burst ─────────────────────────────────────────────────────────────

func TestAgentScore_CallBurst(t *testing.T) {
	// Mean 2/h, current 40/h (20× → saturated 16×) with a known scope. Burst
	// alone should raise the flag and a substantial score.
	b := steadyBaseline(200, 100, map[string]int{"mcp:read": 200})
	r := AgentScore(40, "mcp:read", b)
	if !hasFlag(r.Flags, "ueba:agent_call_burst") {
		t.Errorf("expected ueba:agent_call_burst flag, got %v", r.Flags)
	}
	if r.Score < 50 {
		t.Errorf("expected high score for 20x burst, got %d", r.Score)
	}
}

// ── Scope drift ─────────────────────────────────────────────────────────────────

func TestAgentScore_ScopeDrift(t *testing.T) {
	// Agent historically only ever presented mcp:read; now requests mcp:write
	// at a normal rate. Scope drift alone must trip the step-up threshold (>=60).
	b := steadyBaseline(200, 100, map[string]int{"mcp:read": 200, "openid": 200})
	r := AgentScore(2, "mcp:read mcp:write", b)
	if !hasFlag(r.Flags, "ueba:agent_scope_drift") {
		t.Errorf("expected ueba:agent_scope_drift flag, got %v", r.Flags)
	}
	if r.Score < 40 {
		t.Errorf("expected meaningful score for novel scope, got %d", r.Score)
	}
}

func TestAgentScore_BurstPlusDrift_High(t *testing.T) {
	// Combined burst + novel scope → near-max score, both flags present.
	b := steadyBaseline(200, 100, map[string]int{"mcp:read": 200})
	r := AgentScore(40, "mcp:read mcp:admin", b)
	if !hasFlag(r.Flags, "ueba:agent_call_burst") {
		t.Errorf("expected burst flag, got %v", r.Flags)
	}
	if !hasFlag(r.Flags, "ueba:agent_scope_drift") {
		t.Errorf("expected scope drift flag, got %v", r.Flags)
	}
	if r.Score < 80 {
		t.Errorf("expected near-max score for burst+drift, got %d", r.Score)
	}
	if r.Score > 100 {
		t.Errorf("score must be capped at 100, got %d", r.Score)
	}
}

func TestAgentScore_MultipleNovelScopesCapped(t *testing.T) {
	// Three novel scopes at 40 each = 120, must cap at 70 for the feature.
	b := steadyBaseline(200, 100, map[string]int{"mcp:read": 200})
	r := AgentScore(2, "mcp:write mcp:admin mcp:resources:write", b)
	if r.Score > 70 {
		t.Errorf("scope-drift feature must cap at 70 (no burst), got %d", r.Score)
	}
	if r.Score < 60 {
		t.Errorf("expected capped-but-high score for multiple novel scopes, got %d", r.Score)
	}
}
