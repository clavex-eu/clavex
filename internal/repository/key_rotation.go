package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Key kinds for key_rotation_policies. Only the global installation signing
// keys are auto-rotatable; per-org BYOK keys are intentionally not represented
// here (the DB CHECK constraint rejects any other value).
const (
	KeyKindOIDC = "oidc"
	KeyKindPQC  = "pqc"
)

// Rotation policies.
const (
	RotationPolicyManual    = "manual"
	RotationPolicyScheduled = "scheduled"
)

// KeyRotationPolicy is the scheduled-rotation configuration for one global
// signing key kind.
type KeyRotationPolicy struct {
	KeyKind        string     `json:"key_kind"`
	RotationPolicy string     `json:"rotation_policy"`
	IntervalDays   int        `json:"rotation_interval_days"`
	LastRotatedAt  *time.Time `json:"last_rotated_at,omitempty"`
}

// KeyRotationPolicyRepository persists the global signing-key rotation policy.
type KeyRotationPolicyRepository struct {
	pool *pgxpool.Pool
}

func NewKeyRotationPolicyRepository(pool *pgxpool.Pool) *KeyRotationPolicyRepository {
	return &KeyRotationPolicyRepository{pool: pool}
}

// Get returns the policy for a key kind. Returns pgx.ErrNoRows if none is
// configured (callers treat that as the "manual" default).
func (r *KeyRotationPolicyRepository) Get(ctx context.Context, keyKind string) (*KeyRotationPolicy, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT key_kind, rotation_policy, rotation_interval_days, last_rotated_at
		FROM key_rotation_policies WHERE key_kind = $1`, keyKind)
	var p KeyRotationPolicy
	if err := row.Scan(&p.KeyKind, &p.RotationPolicy, &p.IntervalDays, &p.LastRotatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// Upsert creates or updates the policy for a key kind.
func (r *KeyRotationPolicyRepository) Upsert(ctx context.Context, keyKind, policy string, intervalDays int) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO key_rotation_policies (key_kind, rotation_policy, rotation_interval_days, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (key_kind) DO UPDATE SET
			rotation_policy        = EXCLUDED.rotation_policy,
			rotation_interval_days = EXCLUDED.rotation_interval_days,
			updated_at             = NOW()`,
		keyKind, policy, intervalDays)
	return err
}

// MarkRotated records that a key kind was just rotated.
func (r *KeyRotationPolicyRepository) MarkRotated(ctx context.Context, keyKind string, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE key_rotation_policies SET last_rotated_at = $2, updated_at = NOW()
		WHERE key_kind = $1`, keyKind, at)
	return err
}

// ListDue returns every scheduled policy whose interval has elapsed relative to
// now (or that has never been rotated).
func (r *KeyRotationPolicyRepository) ListDue(ctx context.Context, now time.Time) ([]KeyRotationPolicy, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT key_kind, rotation_policy, rotation_interval_days, last_rotated_at
		FROM key_rotation_policies
		WHERE rotation_policy = 'scheduled'
		  AND (last_rotated_at IS NULL
		       OR last_rotated_at + (rotation_interval_days || ' days')::interval <= $1)`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyRotationPolicy
	for rows.Next() {
		var p KeyRotationPolicy
		if err := rows.Scan(&p.KeyKind, &p.RotationPolicy, &p.IntervalDays, &p.LastRotatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
