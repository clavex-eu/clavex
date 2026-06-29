package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GracePeriod is the GDPR Art.17 grace period before actual erasure.
// GDPR allows delaying erasure where technically necessary; 30 days is
// a common industry standard that provides a reasonable cancellation window.
const GracePeriod = 30 * 24 * time.Hour

// ErasureStatus mirrors the DB CHECK constraint values.
const (
	ErasureStatusPendingConfirmation = "pending_confirmation"
	ErasureStatusScheduled           = "scheduled"
	ErasureStatusCompleted           = "completed"
	ErasureStatusCancelled           = "cancelled"
)

// ErasureRequest is a self-service GDPR Art.17 erasure request.
type ErasureRequest struct {
	ID               uuid.UUID  `json:"id"`
	OrgID            uuid.UUID  `json:"org_id"`
	UserID           uuid.UUID  `json:"user_id"`
	Status           string     `json:"status"`
	ConfirmExpiresAt *time.Time `json:"confirm_expires_at,omitempty"`
	ScheduledFor     *time.Time `json:"scheduled_for,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	CancelledAt      *time.Time `json:"cancelled_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// ErasureRequestRepository manages the gdpr_erasure_requests table.
type ErasureRequestRepository struct {
	pool *pgxpool.Pool
}

func NewErasureRequestRepository(pool *pgxpool.Pool) *ErasureRequestRepository {
	return &ErasureRequestRepository{pool: pool}
}

const erasureCols = `id, org_id, user_id, status, confirm_expires_at, scheduled_for,
	completed_at, cancelled_at, created_at`

func scanErasureRequest(row pgx.Row) (*ErasureRequest, error) {
	r := &ErasureRequest{}
	err := row.Scan(
		&r.ID, &r.OrgID, &r.UserID, &r.Status,
		&r.ConfirmExpiresAt, &r.ScheduledFor,
		&r.CompletedAt, &r.CancelledAt, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Create inserts a new erasure request in status=pending_confirmation and returns
// the raw (unhashed) confirm token and cancel token. Both tokens are stored hashed.
//
// There can be at most one active request per (user_id, org_id). The UNIQUE
// constraint is DEFERRABLE so the caller must handle pgx.ErrNoRows / unique errors.
func (r *ErasureRequestRepository) Create(
	ctx context.Context,
	orgID, userID uuid.UUID,
) (*ErasureRequest, string, string, error) {
	confirmRaw, err := generateErasureToken()
	if err != nil {
		return nil, "", "", err
	}
	cancelRaw, err := generateErasureToken()
	if err != nil {
		return nil, "", "", err
	}
	confirmHash := hashErasureToken(confirmRaw)
	cancelHash := hashErasureToken(cancelRaw)

	req, err := scanErasureRequest(r.pool.QueryRow(ctx, `
		INSERT INTO gdpr_erasure_requests
		    (org_id, user_id, confirm_token_hash, confirm_expires_at, cancel_token_hash)
		VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours', $4)
		RETURNING `+erasureCols,
		orgID, userID, confirmHash, cancelHash,
	))
	if err != nil {
		return nil, "", "", err
	}
	return req, confirmRaw, cancelRaw, nil
}

// GetActiveByUser returns the most recent non-completed, non-cancelled request
// for this user, or pgx.ErrNoRows if none exists.
func (r *ErasureRequestRepository) GetActiveByUser(
	ctx context.Context,
	orgID, userID uuid.UUID,
) (*ErasureRequest, error) {
	return scanErasureRequest(r.pool.QueryRow(ctx, `
		SELECT `+erasureCols+`
		FROM gdpr_erasure_requests
		WHERE org_id = $1 AND user_id = $2
		  AND status IN ('pending_confirmation', 'scheduled')
		ORDER BY created_at DESC
		LIMIT 1
	`, orgID, userID))
}

// Confirm validates the confirm token, moves status → scheduled, sets
// scheduled_for = NOW() + 30 days, and clears the confirm token (one-time use).
// Returns the updated record or pgx.ErrNoRows if the token is invalid/expired.
func (r *ErasureRequestRepository) Confirm(
	ctx context.Context,
	rawToken string,
) (*ErasureRequest, error) {
	hash := hashErasureToken(rawToken)
	return scanErasureRequest(r.pool.QueryRow(ctx, `
		UPDATE gdpr_erasure_requests
		SET status              = 'scheduled',
		    scheduled_for       = NOW() + INTERVAL '30 days',
		    confirm_token_hash  = NULL,
		    confirm_expires_at  = NULL
		WHERE confirm_token_hash = $1
		  AND status             = 'pending_confirmation'
		  AND confirm_expires_at > NOW()
		RETURNING `+erasureCols,
		hash,
	))
}

// Cancel validates the cancel token and moves status → cancelled.
// Only scheduled requests (still within grace period) can be cancelled.
// Returns the updated record or pgx.ErrNoRows if invalid.
func (r *ErasureRequestRepository) Cancel(
	ctx context.Context,
	rawToken string,
) (*ErasureRequest, error) {
	hash := hashErasureToken(rawToken)
	return scanErasureRequest(r.pool.QueryRow(ctx, `
		UPDATE gdpr_erasure_requests
		SET status       = 'cancelled',
		    cancelled_at = NOW(),
		    cancel_token_hash = NULL
		WHERE cancel_token_hash = $1
		  AND status            = 'scheduled'
		  AND scheduled_for     > NOW()
		RETURNING `+erasureCols,
		hash,
	))
}

// ListDue returns all requests that are scheduled and past their scheduled_for
// time. Called by the background worker to identify erasures to execute.
func (r *ErasureRequestRepository) ListDue(ctx context.Context) ([]*ErasureRequest, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+erasureCols+`
		FROM gdpr_erasure_requests
		WHERE status = 'scheduled' AND scheduled_for <= NOW()
		ORDER BY scheduled_for
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ErasureRequest
	for rows.Next() {
		req, err := scanErasureRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, req)
	}
	return out, rows.Err()
}

// MarkCompleted transitions a request to status=completed after the erasure
// transaction has committed successfully.
func (r *ErasureRequestRepository) MarkCompleted(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE gdpr_erasure_requests
		SET status = 'completed', completed_at = NOW(), cancel_token_hash = NULL
		WHERE id = $1 AND status = 'scheduled'
	`, id)
	return err
}

// ── token helpers ─────────────────────────────────────────────────────────────

func generateErasureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashErasureToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
