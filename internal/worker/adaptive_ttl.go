package worker

// adaptive_ttl.go — Adaptive Credential Freshness worker.
//
// RunAdaptiveTTLWorker runs every hour and performs two passes:
//
//  1. Renewal pass: finds credentials whose adaptive_ttl is enabled and that
//     have consumed ≥ renewal_threshold of their TTL (e.g. 80%).  For each,
//     if there is an active-use signal (last_presented_at or user last_login_at
//     within min_ttl_seconds), the credential's ExpiresAt is extended by
//     ttl_seconds from now, hard-capped at issued_at + max_ttl_seconds.
//
//  2. Inactivity pass: finds credentials with presentation_count = 0 AND user
//     inactive for >= inactivity_revoke_days.  Revokes them with reason
//     "adaptive_inactivity" so the status-list bit is also flipped.
//
// Idempotency: the SQL predicates are exact — re-running the worker on a row
// that was already renewed is a no-op because the new expires_at no longer
// satisfies the renewal predicate.

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const adaptiveTTLWorkerInterval = 1 * time.Hour

// RunAdaptiveTTLWorker starts the background goroutine.
// Call as `go RunAdaptiveTTLWorker(ctx, pool)`.
func RunAdaptiveTTLWorker(ctx context.Context, pool *pgxpool.Pool) {
	repo := repository.NewOID4WRepository(pool)
	ticker := time.NewTicker(adaptiveTTLWorkerInterval)
	defer ticker.Stop()

	log.Info().Msg("adaptive-ttl-worker: started (interval=1h)")

	// Run immediately on startup to clear any backlog.
	tickAdaptiveTTL(ctx, repo)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("adaptive-ttl-worker: stopping")
			return
		case <-ticker.C:
			tickAdaptiveTTL(ctx, repo)
		}
	}
}

func tickAdaptiveTTL(ctx context.Context, repo *repository.OID4WRepository) {
	renewPass(ctx, repo)
	inactivityPass(ctx, repo)
}

// renewPass extends ExpiresAt for credentials nearing their threshold.
func renewPass(ctx context.Context, repo *repository.OID4WRepository) {
	candidates, err := repo.ListCredentialsForRenewal(ctx)
	if err != nil {
		log.Error().Err(err).Msg("adaptive-ttl-worker: list renewal candidates")
		return
	}

	for _, c := range candidates {
		// New expiry: now + ttl_seconds, but no later than issued_at + max_ttl_seconds.
		ceiling := c.IssuedAt.Add(time.Duration(c.MaxTTLSeconds) * time.Second)
		proposed := time.Now().Add(time.Duration(c.TTLSeconds) * time.Second)
		if proposed.After(ceiling) {
			proposed = ceiling
		}
		// Don't renew if the ceiling is already in the past (expired max_ttl).
		if proposed.Before(time.Now().Add(time.Duration(c.MinTTLSeconds) * time.Second)) {
			continue
		}

		if err := repo.RenewCredential(ctx, c.CredID, proposed); err != nil {
			log.Error().Err(err).
				Str("cred_id", c.CredID.String()).
				Str("vct", c.VCT).
				Msg("adaptive-ttl-worker: renew credential")
		} else {
			log.Info().
				Str("cred_id", c.CredID.String()).
				Str("vct", c.VCT).
				Time("new_expires_at", proposed).
				Msg("adaptive-ttl-worker: credential renewed")
		}
	}
}

// inactivityPass revokes dormant credentials.
func inactivityPass(ctx context.Context, repo *repository.OID4WRepository) {
	ids, err := repo.ListInactiveCredentials(ctx)
	if err != nil {
		log.Error().Err(err).Msg("adaptive-ttl-worker: list inactive credentials")
		return
	}

	for _, id := range ids {
		if err := repo.RevokeIssuedCredential(ctx, id, "adaptive_inactivity"); err != nil {
			log.Error().Err(err).
				Str("cred_id", id.String()).
				Msg("adaptive-ttl-worker: inactivity revoke")
		} else {
			log.Info().
				Str("cred_id", id.String()).
				Msg("adaptive-ttl-worker: revoked for inactivity")
		}
	}
}
