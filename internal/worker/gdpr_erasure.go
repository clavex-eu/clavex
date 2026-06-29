package worker

// GDPRErasureWorker periodically processes GDPR Art.17 self-service erasure
// requests that have passed their 30-day grace period.
//
// It runs in a background goroutine started at server initialisation.
// Each tick finds all gdpr_erasure_requests WHERE status='scheduled'
// AND scheduled_for <= NOW() and runs the same anonymisation transaction
// used by the admin-facing GDPRErasure handler.
//
// The worker is deliberately simple (no distributed lock, no dead-letter queue).
// For multi-instance deployments, the UNIQUE constraint on the table and the
// conditional UPDATE (WHERE status='scheduled') make concurrent workers
// idempotent — only one will win the row update, others will get 0 rows affected.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	erasureWorkerInterval = 1 * time.Hour
)

// RunGDPRErasureWorker starts the background goroutine. It blocks until ctx
// is cancelled. Call it as `go RunGDPRErasureWorker(ctx, pool)`.
func RunGDPRErasureWorker(ctx context.Context, pool *pgxpool.Pool) {
	repo := repository.NewErasureRequestRepository(pool)
	ticker := time.NewTicker(erasureWorkerInterval)
	defer ticker.Stop()

	log.Info().Msg("gdpr-erasure-worker: started (interval=1h)")

	// Run once immediately on startup to process any backlog.
	processErasures(ctx, pool, repo)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("gdpr-erasure-worker: stopping")
			return
		case <-ticker.C:
			processErasures(ctx, pool, repo)
		}
	}
}

func processErasures(ctx context.Context, pool *pgxpool.Pool, repo *repository.ErasureRequestRepository) {
	due, err := repo.ListDue(ctx)
	if err != nil {
		log.Error().Err(err).Msg("gdpr-erasure-worker: failed to list due requests")
		return
	}
	if len(due) == 0 {
		return
	}
	log.Info().Int("count", len(due)).Msg("gdpr-erasure-worker: processing due erasures")

	for _, req := range due {
		if err := runErasure(ctx, pool, req); err != nil {
			log.Error().Err(err).
				Str("request_id", req.ID.String()).
				Str("user_id", req.UserID.String()).
				Msg("gdpr-erasure-worker: erasure failed")
		} else {
			if err := repo.MarkCompleted(ctx, req.ID); err != nil {
				log.Error().Err(err).Str("request_id", req.ID.String()).
					Msg("gdpr-erasure-worker: failed to mark completed")
			}
		}
	}
}

// runErasure executes the same anonymisation logic as the admin GDPRErasure
// handler, within a single DB transaction.
func runErasure(ctx context.Context, pool *pgxpool.Pool, req *repository.ErasureRequest) error {
	orgID := req.OrgID
	userID := req.UserID

	h256 := sha256.Sum256([]byte(userID.String()))
	anonEmail := fmt.Sprintf("erased_%x@gdpr.invalid", h256[:8])

	return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// Verify the user still exists in this org (may already be deleted by admin).
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND org_id = $2)`,
			userID, orgID,
		).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			// Already erased (e.g. by an admin) — mark the request completed.
			log.Info().Str("user_id", userID.String()).Msg("gdpr-erasure-worker: user already erased; skipping")
			return nil
		}

		// 1. Anonymise the users row.
		if _, err := tx.Exec(ctx, `
			UPDATE users SET
				email         = $1,
				first_name    = 'ERASED',
				last_name     = 'ERASED',
				password_hash = '',
				metadata      = '{}',
				is_active     = FALSE,
				updated_at    = NOW()
			WHERE id = $2 AND org_id = $3`,
			anonEmail, userID, orgID,
		); err != nil {
			return fmt.Errorf("anonymise user: %w", err)
		}

		// 2. Scrub personal data from login_history (keep events for NIS2 audit continuity).
		if _, err := tx.Exec(ctx, `
			UPDATE login_history SET
				email      = NULL,
				ip_address = NULL,
				user_agent = NULL,
				city       = NULL,
				asn_org    = NULL
			WHERE user_id = $1`, userID,
		); err != nil {
			return fmt.Errorf("scrub login_history: %w", err)
		}

		// 3. Revoke issued verifiable credentials.
		if _, err := tx.Exec(ctx, `
			UPDATE issued_credentials SET
				is_revoked        = TRUE,
				revoked_at        = NOW(),
				revocation_reason = 'gdpr_erasure'
			WHERE user_id = $1 AND is_revoked = FALSE`, userID,
		); err != nil {
			return fmt.Errorf("revoke credentials: %w", err)
		}

		// 4. Delete sessions + tokens.
		for _, q := range []string{
			`DELETE FROM browser_sessions  WHERE user_id = $1`,
			`DELETE FROM refresh_tokens    WHERE user_id = $1`,
			`DELETE FROM mfa_credentials   WHERE user_id = $1`,
			`DELETE FROM user_idp_links    WHERE user_id = $1`,
			`DELETE FROM user_roles        WHERE user_id = $1`,
			`DELETE FROM group_members     WHERE user_id = $1`,
			`DELETE FROM rar_grants        WHERE user_id = $1`,
		} {
			if _, err := tx.Exec(ctx, q, userID); err != nil {
				return fmt.Errorf("cleanup (%s): %w", q[:30], err)
			}
		}

		return nil
	})
}

// compile-time check that uuid is used
var _ = uuid.Nil
