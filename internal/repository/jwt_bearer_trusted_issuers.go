package repository

import (
	"context"
	"encoding/json"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JWTBearerTrustedIssuerRepository manages per-org trusted issuer configuration
// for the RFC 7523 JWT Bearer authorization grant.
type JWTBearerTrustedIssuerRepository struct {
	pool *pgxpool.Pool
}

func NewJWTBearerTrustedIssuerRepository(pool *pgxpool.Pool) *JWTBearerTrustedIssuerRepository {
	return &JWTBearerTrustedIssuerRepository{pool: pool}
}

const jwtBearerTrustedIssuerCols = `id, org_id, issuer, jwks, jwks_uri, claim_mappings,
	allowed_scopes, is_active, created_at, created_by`

func scanJWTBearerTrustedIssuer(row pgx.Row) (*models.JWTBearerTrustedIssuer, error) {
	t := &models.JWTBearerTrustedIssuer{}
	err := row.Scan(
		&t.ID, &t.OrgID, &t.Issuer, &t.JWKS, &t.JWKSURI, &t.ClaimMappings,
		&t.AllowedScopes, &t.IsActive, &t.CreatedAt, &t.CreatedBy,
	)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Create registers a new trusted issuer for an org. Returns an error if the
// (org_id, issuer) pair already exists.
func (r *JWTBearerTrustedIssuerRepository) Create(
	ctx context.Context,
	orgID uuid.UUID,
	issuer string,
	jwks *json.RawMessage,
	jwksURI *string,
	claimMappings map[string]string,
	allowedScopes []string,
	createdBy string,
) (*models.JWTBearerTrustedIssuer, error) {
	if claimMappings == nil {
		claimMappings = map[string]string{}
	}
	return scanJWTBearerTrustedIssuer(r.pool.QueryRow(ctx, `
		INSERT INTO jwt_bearer_trusted_issuers
		    (org_id, issuer, jwks, jwks_uri, claim_mappings, allowed_scopes, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+jwtBearerTrustedIssuerCols,
		orgID, issuer, jwks, jwksURI, claimMappings,
		toNullableTextArray(allowedScopes), createdBy,
	))
}

// GetActiveByIssuer returns the active trusted-issuer record for (orgID, issuer),
// or pgx.ErrNoRows if none exists. Used at grant time to resolve the assertion's
// verification key set.
func (r *JWTBearerTrustedIssuerRepository) GetActiveByIssuer(
	ctx context.Context,
	orgID uuid.UUID,
	issuer string,
) (*models.JWTBearerTrustedIssuer, error) {
	return scanJWTBearerTrustedIssuer(r.pool.QueryRow(ctx, `
		SELECT `+jwtBearerTrustedIssuerCols+`
		FROM jwt_bearer_trusted_issuers
		WHERE org_id = $1 AND issuer = $2 AND is_active = TRUE
	`, orgID, issuer))
}

// ListByOrg returns all trusted-issuer records (active and revoked) for an org.
func (r *JWTBearerTrustedIssuerRepository) ListByOrg(
	ctx context.Context,
	orgID uuid.UUID,
) ([]*models.JWTBearerTrustedIssuer, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+jwtBearerTrustedIssuerCols+`
		FROM jwt_bearer_trusted_issuers
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.JWTBearerTrustedIssuer
	for rows.Next() {
		t, err := scanJWTBearerTrustedIssuer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke soft-deletes a trusted issuer by setting is_active = FALSE. Returns
// pgx.ErrNoRows if the record doesn't exist or doesn't belong to orgID.
func (r *JWTBearerTrustedIssuerRepository) Revoke(ctx context.Context, id, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE jwt_bearer_trusted_issuers
		SET is_active = FALSE
		WHERE id = $1 AND org_id = $2 AND is_active = TRUE
	`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
