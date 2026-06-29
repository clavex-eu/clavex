package scim

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SCIMToken represents a SCIM bearer token record (no raw token, only hash stored).
type SCIMToken struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// SCIMTokenRepository handles persistence of SCIM tokens.
type SCIMTokenRepository struct {
	pool *pgxpool.Pool
}

func NewSCIMTokenRepository(pool *pgxpool.Pool) *SCIMTokenRepository {
	return &SCIMTokenRepository{pool: pool}
}

func (r *SCIMTokenRepository) Create(ctx context.Context, orgID uuid.UUID, tokenHash, label string) (*SCIMToken, error) {
	t := &SCIMToken{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO scim_tokens (org_id, token_hash, label)
		VALUES ($1, $2, $3)
		RETURNING id, org_id, label, created_at, last_used_at
	`, orgID, tokenHash, label).Scan(&t.ID, &t.OrgID, &t.Label, &t.CreatedAt, &t.LastUsedAt)
	return t, err
}

func (r *SCIMTokenRepository) Validate(ctx context.Context, orgID uuid.UUID, tokenHash string) (bool, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `
		SELECT id FROM scim_tokens WHERE org_id = $1 AND token_hash = $2
	`, orgID, tokenHash).Scan(&id)
	if err != nil {
		return false, nil //nolint
	}
	return true, nil
}

func (r *SCIMTokenRepository) TouchLastUsed(ctx context.Context, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE scim_tokens SET last_used_at = NOW() WHERE token_hash = $1
	`, tokenHash)
	return err
}

func (r *SCIMTokenRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*SCIMToken, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, label, created_at, last_used_at
		FROM scim_tokens WHERE org_id = $1 ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SCIMToken
	for rows.Next() {
		t := &SCIMToken{}
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Label, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *SCIMTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM scim_tokens WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}
