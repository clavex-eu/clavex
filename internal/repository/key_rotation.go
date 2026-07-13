package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
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

// KeyRotationPolicy is the scheduled-rotation configuration for one signing key.
// OrgID is nil for global keys (PQC, or a legacy global OIDC row) and set for a
// per-org OIDC policy.
type KeyRotationPolicy struct {
	KeyKind        string     `json:"key_kind"`
	OrgID          *uuid.UUID `json:"org_id,omitempty"`
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

// Get returns the GLOBAL policy for a key kind (org_id IS NULL). Returns
// pgx.ErrNoRows if none is configured (callers treat that as the "manual"
// default). Used for PQC and any legacy global OIDC row.
func (r *KeyRotationPolicyRepository) Get(ctx context.Context, keyKind string) (*KeyRotationPolicy, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT key_kind, org_id, rotation_policy, rotation_interval_days, last_rotated_at
		FROM key_rotation_policies WHERE key_kind = $1 AND org_id IS NULL`, keyKind)
	var p KeyRotationPolicy
	if err := row.Scan(&p.KeyKind, &p.OrgID, &p.RotationPolicy, &p.IntervalDays, &p.LastRotatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetForOrg returns the org-scoped policy for a key kind, or pgx.ErrNoRows if
// the org has not configured one (callers treat that as the "manual" default).
func (r *KeyRotationPolicyRepository) GetForOrg(ctx context.Context, keyKind string, orgID uuid.UUID) (*KeyRotationPolicy, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT key_kind, org_id, rotation_policy, rotation_interval_days, last_rotated_at
		FROM key_rotation_policies WHERE key_kind = $1 AND org_id = $2`, keyKind, orgID)
	var p KeyRotationPolicy
	if err := row.Scan(&p.KeyKind, &p.OrgID, &p.RotationPolicy, &p.IntervalDays, &p.LastRotatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// Upsert creates or updates the GLOBAL policy for a key kind (org_id IS NULL).
func (r *KeyRotationPolicyRepository) Upsert(ctx context.Context, keyKind, policy string, intervalDays int) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO key_rotation_policies (key_kind, org_id, rotation_policy, rotation_interval_days, updated_at)
		VALUES ($1, NULL, $2, $3, NOW())
		ON CONFLICT (key_kind) WHERE org_id IS NULL DO UPDATE SET
			rotation_policy        = EXCLUDED.rotation_policy,
			rotation_interval_days = EXCLUDED.rotation_interval_days,
			updated_at             = NOW()`,
		keyKind, policy, intervalDays)
	return err
}

// UpsertForOrg creates or updates an org-scoped policy for a key kind.
func (r *KeyRotationPolicyRepository) UpsertForOrg(ctx context.Context, keyKind string, orgID uuid.UUID, policy string, intervalDays int) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO key_rotation_policies (key_kind, org_id, rotation_policy, rotation_interval_days, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (key_kind, org_id) WHERE org_id IS NOT NULL DO UPDATE SET
			rotation_policy        = EXCLUDED.rotation_policy,
			rotation_interval_days = EXCLUDED.rotation_interval_days,
			updated_at             = NOW()`,
		keyKind, orgID, policy, intervalDays)
	return err
}

// MarkRotated records that a global key kind was just rotated (org_id IS NULL).
func (r *KeyRotationPolicyRepository) MarkRotated(ctx context.Context, keyKind string, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE key_rotation_policies SET last_rotated_at = $2, updated_at = NOW()
		WHERE key_kind = $1 AND org_id IS NULL`, keyKind, at)
	return err
}

// MarkRotatedForOrg records that an org's key kind was just rotated.
func (r *KeyRotationPolicyRepository) MarkRotatedForOrg(ctx context.Context, keyKind string, orgID uuid.UUID, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE key_rotation_policies SET last_rotated_at = $3, updated_at = NOW()
		WHERE key_kind = $1 AND org_id = $2`, keyKind, orgID, at)
	return err
}

// ListDue returns every scheduled policy (global and per-org) whose interval has
// elapsed relative to now (or that has never been rotated). The worker
// dispatches on p.OrgID: nil ⇒ global signer, set ⇒ that org's signer.
func (r *KeyRotationPolicyRepository) ListDue(ctx context.Context, now time.Time) ([]KeyRotationPolicy, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT key_kind, org_id, rotation_policy, rotation_interval_days, last_rotated_at
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
		if err := rows.Scan(&p.KeyKind, &p.OrgID, &p.RotationPolicy, &p.IntervalDays, &p.LastRotatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
