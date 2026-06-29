package worker

// ConformanceScoreWorker computes a real-time security posture score (0-100)
// for every active organization every 5 minutes.
//
// Score dimensions:
//   - MFA adoption     (max 30): % of active users with at least one MFA credential
//   - PKCE clients     (max 25): % of active OAuth2 clients with require_pkce enabled
//   - DPoP clients     (max 25): % of active clients with dpop_bound_access_tokens enabled
//   - NIS2 policies    (max 20): org-level policy checklist (mfa_required, breach check,
//     token TTL, admin count)
//
// When the score crosses below the configured threshold (default 70):
//   - Slack/Teams alert via PAMNotifier
//   - SSF SET event: https://clavex.eu/events/conformance/score-below-threshold
//
// Alert deduplication: a "below threshold" alert fires only once per descent.
// alerted_at is cleared when the score recovers above the threshold.

import (
	"context"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/alerting"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const conformanceScoreInterval = 5 * time.Minute

// ConformanceScoreDeps are external collaborators for the score worker.
type ConformanceScoreDeps struct {
	// Notifier sends Slack/Teams alerts when the score drops below the threshold.
	// May be nil — alerts are skipped.
	Notifier *alerting.PAMNotifier
	// SSFDispatch emits a SET event on threshold crossing.
	// May be nil — no SSF events are sent.
	SSFDispatch *ssf.Dispatcher
}

// RunConformanceScoreWorker starts the continuous assurance background goroutine.
// Call as `go RunConformanceScoreWorker(ctx, pool, deps)`.
func RunConformanceScoreWorker(ctx context.Context, pool *pgxpool.Pool, deps ConformanceScoreDeps) {
	scoreRepo := repository.NewConformanceScoreRepository(pool)
	driftRepo := repository.NewComplianceDriftRepository(pool)
	ticker := time.NewTicker(conformanceScoreInterval)
	defer ticker.Stop()

	log.Info().Str("interval", conformanceScoreInterval.String()).
		Msg("conformance-score-worker: started")

	// Run immediately on startup.
	scanConformanceScores(ctx, scoreRepo, driftRepo, deps)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("conformance-score-worker: stopping")
			return
		case <-ticker.C:
			scanConformanceScores(ctx, scoreRepo, driftRepo, deps)
		}
	}
}

func scanConformanceScores(
	ctx context.Context,
	scoreRepo *repository.ConformanceScoreRepository,
	driftRepo *repository.ComplianceDriftRepository,
	deps ConformanceScoreDeps,
) {
	orgIDs, err := driftRepo.AllActiveOrgIDs(ctx)
	if err != nil {
		log.Error().Err(err).Msg("conformance-score: list orgs failed")
		return
	}
	for _, orgID := range orgIDs {
		if err := computeAndStoreScore(ctx, scoreRepo, driftRepo, deps, orgID); err != nil {
			log.Error().Err(err).Str("org_id", orgID.String()).
				Msg("conformance-score: org computation failed")
		}
	}
}

func computeAndStoreScore(
	ctx context.Context,
	scoreRepo *repository.ConformanceScoreRepository,
	driftRepo *repository.ComplianceDriftRepository,
	deps ConformanceScoreDeps,
	orgID uuid.UUID,
) error {
	// ── Load raw metrics ─────────────────────────────────────────────────────
	metrics, err := scoreRepo.GetScoreMetrics(ctx, orgID)
	if err != nil {
		return fmt.Errorf("get metrics: %w", err)
	}
	state, err := driftRepo.GetOrgSecurityState(ctx, orgID)
	if err != nil {
		return nil // org may have been deleted
	}

	// ── Compute component scores ─────────────────────────────────────────────
	mfaScore, mfaComp := computeMFAScore(metrics)
	pkceScore, pkceComp := computePKCEScore(metrics)
	dpopScore, dpopComp := computeDPoPScore(metrics)
	nis2Score, nis2Comp := computeNIS2Score(state)

	total := mfaScore + pkceScore + dpopScore + nis2Score

	components := map[string]any{
		"mfa_adoption": mfaComp,
		"pkce_clients": pkceComp,
		"dpop_clients": dpopComp,
		"nis2_policies": nis2Comp,
	}

	in := repository.ConformanceScoreInput{
		OrgID:      orgID,
		Score:      total,
		ScoreMFA:   mfaScore,
		ScorePKCE:  pkceScore,
		ScoreDPoP:  dpopScore,
		ScoreNIS2:  nis2Score,
		Components: components,
	}

	// ── Load previous score for threshold-crossing detection ─────────────────
	prev, _ := scoreRepo.GetScore(ctx, orgID) // nil on first run

	// ── Persist latest score + history point ─────────────────────────────────
	if err := scoreRepo.UpsertScore(ctx, in); err != nil {
		return fmt.Errorf("upsert score: %w", err)
	}
	if err := scoreRepo.AppendHistory(ctx, in); err != nil {
		log.Warn().Err(err).Str("org_id", orgID.String()).
			Msg("conformance-score: append history failed (non-fatal)")
	}

	log.Debug().
		Str("org", state.OrgSlug).
		Int("score", total).
		Int("mfa", mfaScore).Int("pkce", pkceScore).
		Int("dpop", dpopScore).Int("nis2", nis2Score).
		Msg("conformance-score: computed")

	// ── Threshold alert logic ─────────────────────────────────────────────────
	threshold := 70
	if prev != nil {
		threshold = prev.Threshold
	}

	belowThreshold := total < threshold
	wasAlerted := prev != nil && prev.AlertedAt != nil

	switch {
	case belowThreshold && !wasAlerted:
		// Score just dropped below threshold — fire alert once.
		log.Warn().
			Str("org", state.OrgSlug).
			Int("score", total).Int("threshold", threshold).
			Msg("conformance-score: below threshold — alerting")

		_ = scoreRepo.MarkAlerted(ctx, orgID)

		if deps.Notifier != nil && deps.Notifier.IsEnabled() {
			deps.Notifier.AlertConformanceScoreDrop(state.OrgName, state.OrgSlug, total, threshold, components)
		}
		if deps.SSFDispatch != nil {
			deps.SSFDispatch.Dispatch(orgID, state.OrgSlug, "", "https://clavex.eu/events/conformance/score-below-threshold",
				map[string]interface{}{
					"score":     total,
					"threshold": threshold,
					"score_mfa":  mfaScore,
					"score_pkce": pkceScore,
					"score_dpop": dpopScore,
					"score_nis2": nis2Score,
				})
		}

	case !belowThreshold && wasAlerted:
		// Score recovered — clear the alert state.
		log.Info().
			Str("org", state.OrgSlug).
			Int("score", total).Int("threshold", threshold).
			Msg("conformance-score: recovered above threshold")
		_ = scoreRepo.ClearAlerted(ctx, orgID)
	}

	return nil
}

// ── Score component computations ──────────────────────────────────────────────

const (
	weightMFA  = 30
	weightPKCE = 25
	weightDPoP = 25
	weightNIS2 = 20
)

func computeMFAScore(m *repository.ScoreMetrics) (int, map[string]any) {
	pct := 0.0
	if m.UsersTotal > 0 {
		pct = float64(m.UsersWithMFA) / float64(m.UsersTotal) * 100
	}
	score := int(pct / 100 * float64(weightMFA))
	return score, map[string]any{
		"score": score, "max": weightMFA,
		"pct": round1(pct), "enrolled": m.UsersWithMFA, "total": m.UsersTotal,
	}
}

func computePKCEScore(m *repository.ScoreMetrics) (int, map[string]any) {
	pct := 0.0
	if m.ClientsTotal > 0 {
		pct = float64(m.ClientsPKCE) / float64(m.ClientsTotal) * 100
	}
	score := int(pct / 100 * float64(weightPKCE))
	return score, map[string]any{
		"score": score, "max": weightPKCE,
		"pct": round1(pct), "pkce_clients": m.ClientsPKCE, "total": m.ClientsTotal,
	}
}

func computeDPoPScore(m *repository.ScoreMetrics) (int, map[string]any) {
	pct := 0.0
	if m.ClientsTotal > 0 {
		pct = float64(m.ClientsDPoP) / float64(m.ClientsTotal) * 100
	}
	score := int(pct / 100 * float64(weightDPoP))
	return score, map[string]any{
		"score": score, "max": weightDPoP,
		"pct": round1(pct), "dpop_clients": m.ClientsDPoP, "total": m.ClientsTotal,
	}
}

// computeNIS2Score awards up to 20 points based on org-level policy checks.
func computeNIS2Score(state *repository.OrgSecurityState) (int, map[string]any) {
	score := 0
	checks := map[string]bool{}

	// +8: org-level MFA enforcement
	checks["mfa_required"] = state.MFARequired
	if state.MFARequired {
		score += 8
	}

	// +4: breached-password check is active
	bpa := state.BreachedPwdAction
	checks["breach_check_enabled"] = bpa != "" && bpa != "none" && bpa != "allow"
	if checks["breach_check_enabled"] {
		score += 4
	}

	// +4: short access-token TTL (≤3600 s = 1 h)
	checks["short_access_ttl"] = state.AccessTokenTTL != nil && *state.AccessTokenTTL <= 3600
	if checks["short_access_ttl"] {
		score += 4
	}

	// +4: reasonable admin count (1–10)
	checks["limited_admins"] = state.AdminCount >= 1 && state.AdminCount <= 10
	if checks["limited_admins"] {
		score += 4
	}

	return score, map[string]any{
		"score": score, "max": weightNIS2, "checks": checks,
	}
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
