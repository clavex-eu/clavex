package repository

import (
	"context"
	"errors"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentTokenRepository persists AI agent token records.
type AgentTokenRepository struct {
	pool *pgxpool.Pool
}

func NewAgentTokenRepository(pool *pgxpool.Pool) *AgentTokenRepository {
	return &AgentTokenRepository{pool: pool}
}

const agentTokenCols = `
	id, org_id, user_id, agent_id, agent_name, scope, jti,
	is_revoked, expires_at, revoked_at, revoked_by, created_at, created_by,
	last_used_at, mcp_server_id, mcp_resource_url`

func scanAgentToken(row interface{ Scan(...any) error }) (*models.AgentToken, error) {
	t := &models.AgentToken{}
	err := row.Scan(
		&t.ID, &t.OrgID, &t.UserID, &t.AgentID, &t.AgentName, &t.Scope, &t.JTI,
		&t.IsRevoked, &t.ExpiresAt, &t.RevokedAt, &t.RevokedBy, &t.CreatedAt, &t.CreatedBy,
		&t.LastUsedAt, &t.MCPServerID, &t.MCPResourceURL,
	)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Create persists a new agent token record (the signed JWT string is returned
// by the handler; only metadata is stored here).
func (r *AgentTokenRepository) Create(
	ctx context.Context,
	orgID, userID uuid.UUID,
	agentID, agentName, scope, jti string,
	expiresAt time.Time,
	createdBy *uuid.UUID,
	mcpServerID *string,
	mcpResourceURL *string,
) (*models.AgentToken, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO agent_tokens
			(org_id, user_id, agent_id, agent_name, scope, jti, expires_at, created_by,
			 mcp_server_id, mcp_resource_url)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING `+agentTokenCols,
		orgID, userID, agentID, agentName, scope, jti, expiresAt, createdBy,
		mcpServerID, mcpResourceURL)
	return scanAgentToken(row)
}

// GetByJTI looks up a token record by its JWT ID for revocation checks.
func (r *AgentTokenRepository) GetByJTI(ctx context.Context, jti string) (*models.AgentToken, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+agentTokenCols+` FROM agent_tokens WHERE jti = $1`, jti)
	t, err := scanAgentToken(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// ListByOrg returns active (non-revoked, non-expired) agent tokens for an org.
func (r *AgentTokenRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.AgentToken, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+agentTokenCols+`
		FROM agent_tokens
		WHERE org_id = $1
		ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.AgentToken
	for rows.Next() {
		t, err := scanAgentToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListByUser returns all agent tokens for a specific user within an org.
func (r *AgentTokenRepository) ListByUser(ctx context.Context, orgID, userID uuid.UUID) ([]*models.AgentToken, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+agentTokenCols+`
		FROM agent_tokens
		WHERE org_id = $1 AND user_id = $2
		ORDER BY created_at DESC`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.AgentToken
	for rows.Next() {
		t, err := scanAgentToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListMine returns all agent tokens delegated by a specific user, keyed on
// user_id alone. This powers the self-service "My Active Agents" panel: it must
// NOT be scoped to an org because it deliberately returns only the caller's own
// grants, never every token in their organization (that is the admin ListByOrg).
func (r *AgentTokenRepository) ListMine(ctx context.Context, userID uuid.UUID) ([]*models.AgentToken, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+agentTokenCols+`
		FROM agent_tokens
		WHERE user_id = $1
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.AgentToken
	for rows.Next() {
		t, err := scanAgentToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeByOwner lets a user revoke one of their OWN agent tokens without admin
// permission. Ownership is enforced in the WHERE clause (user_id = $2): a token
// belonging to another user — even in the same org — yields pgx.ErrNoRows and is
// never revoked. revokedBy is recorded as the acting (self) user.
func (r *AgentTokenRepository) RevokeByOwner(ctx context.Context, id, userID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE agent_tokens
		SET is_revoked = TRUE, revoked_at = NOW(), revoked_by = $2
		WHERE id = $1 AND user_id = $2 AND is_revoked = FALSE`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// TouchLastUsed records that the token identified by jti was just presented to a
// resource server. Best-effort: errors are ignored (non-critical analytics write).
func (r *AgentTokenRepository) TouchLastUsed(ctx context.Context, jti string) {
	_, _ = r.pool.Exec(ctx, `UPDATE agent_tokens SET last_used_at = NOW() WHERE jti = $1`, jti)
}

// Revoke marks a token as revoked, scoped to its owning org so a cross-tenant
// token id cannot be revoked. Returns pgx.ErrNoRows if not found in the org.
func (r *AgentTokenRepository) Revoke(ctx context.Context, id, orgID, revokedBy uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE agent_tokens
		SET is_revoked = TRUE, revoked_at = NOW(), revoked_by = $2
		WHERE id = $1 AND org_id = $3 AND is_revoked = FALSE`, id, revokedBy, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// RevokeAllForUser revokes all active agent tokens for a user (used on account suspension).
func (r *AgentTokenRepository) RevokeAllForUser(ctx context.Context, orgID, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE agent_tokens
		SET is_revoked = TRUE, revoked_at = NOW()
		WHERE org_id = $1 AND user_id = $2 AND is_revoked = FALSE`,
		orgID, userID)
	return err
}

// TouchClientLastUsed updates last_used_at for an OIDC client.
// Called on every successful token issuance.
func TouchClientLastUsed(ctx context.Context, pool *pgxpool.Pool, clientID string) {
	// Best-effort: ignore errors — this is a non-critical analytics write.
	_, _ = pool.Exec(ctx,
		`UPDATE oidc_clients SET last_used_at = NOW() WHERE client_id = $1`, clientID)
}
