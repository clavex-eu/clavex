package repository

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RARGrantRepository manages RFC 9396 grant persistence.
type RARGrantRepository struct {
	pool *pgxpool.Pool
}

func NewRARGrantRepository(pool *pgxpool.Pool) *RARGrantRepository {
	return &RARGrantRepository{pool: pool}
}

func scanGrant(row interface{ Scan(dest ...any) error }) (*models.RARGrant, error) {
	g := &models.RARGrant{}
	var rawDetails []byte
	if err := row.Scan(
		&g.ID, &g.OrgID, &g.UserID, &g.ClientID, &g.Scope,
		&rawDetails, &g.GrantedAt, &g.LastUsedAt, &g.RevokedAt, &g.IsActive,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rawDetails, &g.AuthorizationDetails)
	return g, nil
}

// Upsert creates or replaces the active grant for (org, user, client).
// Called at token exchange time whenever authorization_details are present.
func (r *RARGrantRepository) Upsert(
	ctx context.Context,
	orgID, userID uuid.UUID,
	clientID, scope string,
	authDetails []map[string]any,
) (*models.RARGrant, error) {
	raw, err := json.Marshal(authDetails)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO rar_grants (org_id, user_id, client_id, scope, authorization_details)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (org_id, user_id, client_id) WHERE is_active = TRUE
		DO UPDATE SET
		    scope                 = EXCLUDED.scope,
		    authorization_details = EXCLUDED.authorization_details,
		    last_used_at          = NOW()
		RETURNING id, org_id, user_id, client_id, scope,
		          authorization_details, granted_at, last_used_at, revoked_at, is_active
	`, orgID, userID, clientID, scope, raw)
	return scanGrant(row)
}

// ListByOrg returns all active grants for an org (for the admin dashboard).
func (r *RARGrantRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.RARGrant, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, user_id, client_id, scope,
		       authorization_details, granted_at, last_used_at, revoked_at, is_active
		FROM rar_grants
		WHERE org_id = $1
		ORDER BY granted_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.RARGrant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListByUser returns all active grants for a specific user (for user self-service).
func (r *RARGrantRepository) ListByUser(ctx context.Context, orgID, userID uuid.UUID) ([]*models.RARGrant, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, user_id, client_id, scope,
		       authorization_details, granted_at, last_used_at, revoked_at, is_active
		FROM rar_grants
		WHERE org_id = $1 AND user_id = $2 AND is_active = TRUE
		ORDER BY granted_at DESC
	`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.RARGrant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Revoke marks a grant as inactive. The grant must belong to the given org.
func (r *RARGrantRepository) Revoke(ctx context.Context, orgID, grantID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE rar_grants SET is_active = FALSE, revoked_at = NOW()
		WHERE id = $1 AND org_id = $2 AND is_active = TRUE
	`, grantID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("grant not found or already revoked")
	}
	return nil
}

// RevokeAllByUser revokes all active grants for a user (e.g. on account deletion).
func (r *RARGrantRepository) RevokeAllByUser(ctx context.Context, orgID, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE rar_grants SET is_active = FALSE, revoked_at = NOW()
		WHERE org_id = $1 AND user_id = $2 AND is_active = TRUE
	`, orgID, userID)
	return err
}

// GetByID returns a single grant, scoped to the org.
func (r *RARGrantRepository) GetByID(ctx context.Context, orgID, grantID uuid.UUID) (*models.RARGrant, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, client_id, scope,
		       authorization_details, granted_at, last_used_at, revoked_at, is_active
		FROM rar_grants WHERE id = $1 AND org_id = $2
	`, grantID, orgID)
	g, err := scanGrant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return g, err
}
