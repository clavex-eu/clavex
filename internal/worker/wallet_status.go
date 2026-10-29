package worker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// Monitor only authenticated, persisted parent status links. No background
// request is made for tenants/credentials that have no such dependency.
func RunWalletStatusMonitor(ctx context.Context, pool *pgxpool.Pool) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		passCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		if err := PollWalletStatusParents(passCtx, pool); err != nil && ctx.Err() == nil {
			log.Warn().Err(err).Msg("wallet parent status monitor pass incomplete")
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Bounded oldest-first batches avoid unbounded work and starvation on outage.
// Fresh verification at authentication/delivery remains mandatory independently
// of this eventual propagation to published local lists.
func PollWalletStatusParents(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `SELECT id,org_id FROM identity.issued_credentials WHERE NOT is_revoked
 AND status_parents<>'[]'::jsonb AND (expires_at IS NULL OR expires_at>clock_timestamp())
 AND (parents_checked_at IS NULL OR parents_checked_at<clock_timestamp()-interval '30 seconds')
 ORDER BY parents_checked_at NULLS FIRST,id LIMIT 64`)
	if err != nil {
		return err
	}
	type candidate struct{ id, org uuid.UUID }
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.org); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range candidates {
		if err := pollWalletParent(ctx, pool, item.id, item.org); err != nil {
			return err
		}
	}
	return nil
}
func pollWalletParent(ctx context.Context, pool *pgxpool.Pool, id, org uuid.UUID) error {
	repo, tx, err := repository.NewOID4WRepository(pool).BeginIssuance(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	settings, err := repo.LockWalletStatusPolicy(ctx, org)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var raw json.RawMessage
	var suspended, hold bool
	err = tx.QueryRow(ctx, `SELECT status_parents,is_suspended,parent_status_hold FROM identity.issued_credentials
 WHERE id=$1 AND org_id=$2 AND NOT is_revoked AND (parents_checked_at IS NULL OR parents_checked_at<clock_timestamp()-interval '30 seconds')
 FOR UPDATE SKIP LOCKED`, id, org).Scan(&raw, &suspended, &hold)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	stateErr := oid4w.CheckStatusParents(ctx, org.String(), settings, raw)
	switch {
	case errors.Is(stateErr, oid4w.ErrRevoked):
		if err := repo.RevokeIssuedCredential(ctx, id, "parent_attestation_revoked"); err != nil {
			return err
		}
	case errors.Is(stateErr, oid4w.ErrSuspended):
		if !suspended {
			if err := repo.SuspendIssuedCredential(ctx, id, "parent_attestation_suspended"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE identity.issued_credentials SET parent_status_hold=true WHERE id=$1`, id); err != nil {
				return err
			}
		}
	case stateErr == nil && suspended && hold:
		if err := repo.RestoreIssuedCredential(ctx, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity.issued_credentials SET parent_status_hold=false WHERE id=$1`, id); err != nil {
			return err
		}
	}
	// Unavailability/invalid/unrecognised state never restores or falsely revokes
	// credentials. The synchronous decision fails closed until evidence returns.
	if _, err := tx.Exec(ctx, `UPDATE identity.issued_credentials SET parents_checked_at=clock_timestamp() WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
