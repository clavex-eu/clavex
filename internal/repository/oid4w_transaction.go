package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BeginIssuance starts a request-local transaction. Callers use the returned
// repository for every issuance write and commit before releasing credentials.
func (r *OID4WRepository) BeginIssuance(ctx context.Context) (*OID4WRepository, pgx.Tx, error) {
	beginner, ok := r.pool.(interface {
		Begin(context.Context) (pgx.Tx, error)
	})
	if !ok {
		return nil, nil, fmt.Errorf("issuance transaction is unavailable")
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	return NewOID4WRepository(tx), tx, nil
}

// LockIssuanceOffer serialises consumption across nodes and rechecks state after
// obtaining the lock. NOWAIT avoids holding HTTP requests behind slow signers.
func (r *OID4WRepository) LockIssuanceOffer(ctx context.Context, id, orgID uuid.UUID, tokenHash string) error {
	grant, err := r.LockWalletGrant(ctx, id, orgID)
	if err != nil {
		return err
	}
	var status string
	var expires time.Time
	var actual *string
	err = r.pool.QueryRow(ctx, `SELECT status,expires_at,access_token_hash FROM credential_offers
	 WHERE id=$1 AND org_id=$2 FOR UPDATE NOWAIT`, id, orgID).Scan(&status, &expires, &actual)
	if err != nil {
		return err
	}
	if status != "pending" || !time.Now().Before(expires) {
		return pgx.ErrNoRows
	}
	if grant == nil {
		var valid bool
		if err := r.pool.QueryRow(ctx, `SELECT access_token_expires_at>clock_timestamp() FROM credential_offers WHERE id=$1`, id).Scan(&valid); err != nil {
			return err
		}
		if !valid || actual == nil || *actual != tokenHash {
			return pgx.ErrNoRows
		}
	} else {
		current, err := r.GetOfferByAccessToken(ctx, tokenHash)
		if err != nil {
			return err
		}
		if current.ID != id {
			return pgx.ErrNoRows
		}
		if err := r.CheckWalletEligibility(ctx, grant, current); err != nil {
			return err
		}
	}
	return nil
}

func (r *OID4WRepository) LockDeferredIssuance(ctx context.Context, transactionID string, orgID uuid.UUID) error {
	var status string
	var expires time.Time
	err := r.pool.QueryRow(ctx, `SELECT status,expires_at FROM deferred_credentials
	 WHERE transaction_id=$1 AND org_id=$2 FOR UPDATE NOWAIT`, transactionID, orgID).Scan(&status, &expires)
	if err != nil {
		return err
	}
	if status != "pending" || !time.Now().Before(expires) {
		return pgx.ErrNoRows
	}
	return nil
}
