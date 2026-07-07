package ueba

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// minAgentSamples is the minimum number of recorded usage events before the
// agent scorer produces non-zero output. Below this we lack the history to
// distinguish anomalous from normal behaviour and would only emit false
// positives (mirrors minSamples for the per-user login scorer).
const minAgentSamples = 10

// AgentBaseline is the historical behavioural model for one AI-agent identity
// (agent_id). It is derived from the agent_token_usage table by the caller and
// deliberately mirrors the shape of the per-user login Baseline: a call count,
// the observation window, and a per-scope frequency map.
type AgentBaseline struct {
	// TotalCalls is the number of recorded usage events for the agent.
	TotalCalls int
	// FirstSeen is the timestamp of the earliest recorded usage event, used to
	// derive the historical calls-per-hour rate.
	FirstSeen time.Time
	// ScopeCounts maps each individual scope token the agent has historically
	// presented to how many usage events carried it.
	ScopeCounts map[string]int
}

// AgentScore measures how anomalous the current agent activity is relative to
// the agent's own baseline, on a 0–100 scale directly comparable with the
// wallet step-up risk threshold. It combines two independent features:
//
//   - Call-rate surprise: the calls observed in the trailing hour versus the
//     agent's historical mean calls-per-hour. A sudden burst (e.g. a stolen
//     token driven by an attacker) scores high; steady traffic scores ~0.
//   - Scope drift: a scope the agent has never historically used (e.g. an agent
//     that only ever called mcp:read suddenly presenting mcp:write) is a strong
//     escalation signal and dominates the score when present.
//
// callsLastHour and requestedScope describe the current activity. requestedScope
// is the space-separated scope string on the presented token.
//
// The scorer stays silent (Score 0) until the baseline has at least
// minAgentSamples events, exactly like the per-user scorer's cold-start guard.
func AgentScore(callsLastHour int, requestedScope string, baseline *AgentBaseline) *Result {
	r := &Result{}
	if baseline == nil || baseline.TotalCalls < minAgentSamples {
		return r
	}

	// ── 1. Call-rate anomaly ─────────────────────────────────────────────────
	// Historical mean calls-per-hour over the observation window (floored at 1h
	// so a very young-but-active agent is not divided by a tiny denominator).
	windowHours := time.Since(baseline.FirstSeen).Hours()
	if windowHours < 1 {
		windowHours = 1
	}
	meanPerHour := float64(baseline.TotalCalls) / windowHours
	if meanPerHour < 1 {
		meanPerHour = 1 // avoid over-reacting to naturally low-traffic agents
	}
	// Ratio of the current hour's rate to the baseline mean. A ratio of 1 is
	// normal; log2 turns multiplicative bursts into a bounded, additive signal.
	ratio := float64(callsLastHour) / meanPerHour
	rateScore := 0.0
	var rateFlag string
	if ratio > 1 {
		// log2(ratio) reaches 1 bit at 2×, 3 bits at 8×, 4 bits at 16×.
		// Saturate at ~4 bits (16×) and map onto 0..60.
		bits := math.Log2(ratio)
		if bits > 4 {
			bits = 4
		}
		rateScore = (bits / 4.0) * 60.0
		if rateScore >= 15 {
			rateFlag = fmt.Sprintf("ueba:agent_call_burst:recent_%d:mean_%.1f/h:ratio_%.1fx",
				callsLastHour, meanPerHour, ratio)
		}
	}

	// ── 2. Scope drift ───────────────────────────────────────────────────────
	// Any requested scope the agent has never presented before is novel. Novel
	// scopes are a strong escalation signal, so each contributes a large fixed
	// amount, capped so the feature alone can trip the threshold.
	var novelScopes []string
	for _, s := range strings.Fields(requestedScope) {
		if baseline.ScopeCounts[s] == 0 {
			novelScopes = append(novelScopes, s)
		}
	}
	scopeScore := 0.0
	var scopeFlag string
	if len(novelScopes) > 0 {
		scopeScore = float64(len(novelScopes)) * 40.0
		if scopeScore > 70 {
			scopeScore = 70
		}
		scopeFlag = fmt.Sprintf("ueba:agent_scope_drift:new_%s", strings.Join(novelScopes, ","))
	}

	// ── Combine ──────────────────────────────────────────────────────────────
	// The two signals are additive but capped at 100. Scope drift is intended to
	// be able to trip the threshold on its own; a burst reinforces it.
	total := rateScore + scopeScore
	if total > 100 {
		total = 100
	}
	r.Score = int(math.Round(total))

	if rateFlag != "" {
		r.Flags = append(r.Flags, rateFlag)
	}
	if scopeFlag != "" {
		r.Flags = append(r.Flags, scopeFlag)
	}
	return r
}
