package worker

// ComplianceDriftWorker scans all active organizations every hour and detects
// changes in security-relevant controls required by NIS2 / zero-trust baselines:
//
//   - MFA enforcement (mfa_required)
//   - Access token TTL (session duration)
//   - Refresh token TTL (session persistence)
//   - Admin role assignment count
//   - Password minimum length
//   - Breached-password-check policy
//
// Detection algorithm:
//  1. Compute a deterministic SHA-256 fingerprint of the org's current security
//     state as a flat key→value map.
//  2. Compare the hash to the stored snapshot (compliance_snapshots table).
//  3. If the hash differs, diff the maps field-by-field and emit one
//     ComplianceDriftEvent per changed control.
//  4. Persist the new snapshot and alert via Slack/Teams + SSF.
//
// Idempotency: the snapshot upsert is idempotent so concurrent replicas converge.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/clavex-eu/clavex/internal/alerting"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const complianceDriftInterval = 1 * time.Hour

// ComplianceDriftDeps are external collaborators for the drift worker.
type ComplianceDriftDeps struct {
	// Notifier is used to send Slack/Teams alerts when drift is detected.
	// May be nil — alerts are simply skipped.
	Notifier *alerting.PAMNotifier
	// SSFDispatch emits a SET event for each drift event detected.
	// May be nil — no SSF events are sent.
	SSFDispatch *ssf.Dispatcher
}

// RunComplianceDriftWorker starts the NIS2 compliance drift detection background goroutine.
// Call as `go RunComplianceDriftWorker(ctx, pool, deps)`.
func RunComplianceDriftWorker(ctx context.Context, pool *pgxpool.Pool, deps ComplianceDriftDeps) {
	repo := repository.NewComplianceDriftRepository(pool)
	ticker := time.NewTicker(complianceDriftInterval)
	defer ticker.Stop()

	log.Info().Str("interval", complianceDriftInterval.String()).
		Msg("compliance-drift-worker: started")

	// Run once immediately on startup to establish baseline snapshots.
	scanComplianceDrift(ctx, repo, deps)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("compliance-drift-worker: stopping")
			return
		case <-ticker.C:
			scanComplianceDrift(ctx, repo, deps)
		}
	}
}

func scanComplianceDrift(ctx context.Context, repo *repository.ComplianceDriftRepository, deps ComplianceDriftDeps) {
	orgIDs, err := repo.AllActiveOrgIDs(ctx)
	if err != nil {
		log.Error().Err(err).Msg("compliance-drift: list orgs failed")
		return
	}
	for _, orgID := range orgIDs {
		if err := checkOrgDrift(ctx, repo, deps, orgID); err != nil {
			log.Error().Err(err).Str("org_id", orgID.String()).
				Msg("compliance-drift: org scan failed")
		}
	}
}

// checkOrgDrift computes the current security fingerprint for one org, diffs it
// against the stored snapshot and emits drift events if anything changed.
func checkOrgDrift(
	ctx context.Context,
	repo *repository.ComplianceDriftRepository,
	deps ComplianceDriftDeps,
	orgID uuid.UUID,
) error {
	state, err := repo.GetOrgSecurityState(ctx, orgID)
	if err != nil {
		// Org may have been deleted between listing and now — silently skip.
		return nil
	}

	current := snapshotFromState(state)
	hash := hashSnapshot(current)

	prev, err := repo.GetSnapshot(ctx, orgID)
	if err != nil {
		// No previous snapshot — this is the first scan. Establish baseline silently.
		return repo.UpsertSnapshot(ctx, orgID, current, hash)
	}

	if prev.SnapshotHash == hash {
		// No change — update captured_at so we know the worker is running.
		return repo.UpsertSnapshot(ctx, orgID, current, hash)
	}

	// ── Drift detected — diff the two snapshots ───────────────────────────────
	drifts := diffSnapshots(prev.Snapshot, current)
	for _, d := range drifts {
		e := repository.ComplianceDriftEvent{
			OrgID:         orgID,
			Control:       d.Control,
			PreviousValue: d.Previous,
			CurrentValue:  d.Current,
			Severity:      d.Severity,
		}
		if err := repo.InsertDriftEvent(ctx, e); err != nil {
			log.Error().Err(err).Str("org_id", orgID.String()).
				Str("control", d.Control).Msg("compliance-drift: insert event failed")
		}

		log.Warn().
			Str("org", state.OrgSlug).
			Str("control", d.Control).
			Str("severity", d.Severity).
			Str("previous", ptrStr(d.Previous)).
			Str("current", ptrStr(d.Current)).
			Msg("compliance-drift: control changed")

		// SSF SET event.
		if deps.SSFDispatch != nil {
			deps.SSFDispatch.Dispatch(orgID, state.OrgSlug, "", "https://clavex.eu/events/compliance/drift",
				map[string]interface{}{
					"control":        d.Control,
					"previous_value": ptrStr(d.Previous),
					"current_value":  ptrStr(d.Current),
					"severity":       d.Severity,
				})
		}
	}

	// Send a single consolidated Slack/Teams alert for this org if drift found.
	if len(drifts) > 0 && deps.Notifier != nil && deps.Notifier.IsEnabled() {
		deps.Notifier.AlertComplianceDrift(state.OrgName, state.OrgSlug, drifts)
	}

	return repo.UpsertSnapshot(ctx, orgID, current, hash)
}

// ── Snapshot helpers ──────────────────────────────────────────────────────────

// snapshotFromState converts an OrgSecurityState into a flat string map suitable
// for hashing and field-by-field diffing.
func snapshotFromState(s *repository.OrgSecurityState) map[string]string {
	snap := map[string]string{
		"mfa_required":   fmt.Sprintf("%v", s.MFARequired),
		"admin_count":    fmt.Sprintf("%d", s.AdminCount),
		"access_ttl":     nullIntStr(s.AccessTokenTTL),
		"refresh_ttl":    nullIntStr(s.RefreshTokenTTL),
		"pw_min_length":  nullIntStr(s.PasswordMinLength),
		"pw_complexity":  s.PasswordComplexity,
		"pw_breach_mode": s.BreachedPwdAction,
	}
	return snap
}

func nullIntStr(v *int) string {
	if v == nil {
		return "default"
	}
	return fmt.Sprintf("%d", *v)
}

func ptrStr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func hashSnapshot(snap map[string]string) string {
	// Sort keys for determinism then SHA-256 the JSON.
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		ordered = append(ordered, map[string]string{k: snap[k]})
	}
	b, _ := json.Marshal(ordered)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ── Diff ──────────────────────────────────────────────────────────────────────

// driftChange is an alias for alerting.ComplianceDriftChange — avoids defining
// the same struct twice and prevents a circular import.
type driftChange = alerting.ComplianceDriftChange

// severityFor returns the NIS2-aligned severity for a given control change.
func severityFor(control, prev, curr string) string {
	switch control {
	case "mfa_required":
		// Disabling MFA is critical.
		if prev == "true" && curr == "false" {
			return "critical"
		}
		return "high"
	case "pw_breach_mode":
		if curr == "" || curr == "none" || curr == "allow" {
			return "high"
		}
		return "medium"
	case "access_ttl", "refresh_ttl":
		return "high"
	case "pw_min_length":
		return "medium"
	case "admin_count":
		return "high"
	default:
		return "info"
	}
}

func diffSnapshots(previous, current map[string]string) []driftChange {
	var changes []driftChange

	// All keys from current (new keys are also a drift).
	for k, curr := range current {
		prev, existed := previous[k]
		if !existed || prev != curr {
			p := prev
			c := curr
			sev := severityFor(k, prev, c)
			changes = append(changes, driftChange{
				Control:  k,
				Previous: &p,
				Current:  &c,
				Severity: sev,
			})
		}
	}

	// Keys that disappeared (controls removed).
	for k, prev := range previous {
		if _, ok := current[k]; !ok {
			p := prev
			changes = append(changes, driftChange{
				Control:  k,
				Previous: &p,
				Current:  nil,
				Severity: severityFor(k, prev, ""),
			})
		}
	}

	return changes
}
