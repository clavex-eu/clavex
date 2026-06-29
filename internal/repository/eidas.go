package repository

import (
	"context"
	"errors"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EidasRepository handles persistence for eIDAS SP configurations.
type EidasRepository struct{ pool *pgxpool.Pool }

func NewEidasRepository(pool *pgxpool.Pool) *EidasRepository {
	return &EidasRepository{pool: pool}
}

// GetConfig returns the eIDAS config for orgID, or (nil, nil) if not found.
func (r *EidasRepository) GetConfig(ctx context.Context, orgID uuid.UUID) (*models.EidasConfig, error) {
	const q = `SELECT id, org_id, entity_id, eidas_node_url, acs_url,
	                   idp_cert_pem, sp_cert_pem, sp_key_pem, requested_loa,
	                   org_name, org_display_name, org_url, contact_email,
	                   is_active, created_at, updated_at
	             FROM eidas_configs WHERE org_id = $1`
	row := r.pool.QueryRow(ctx, q, orgID)
	cfg := &models.EidasConfig{}
	err := row.Scan(
		&cfg.ID, &cfg.OrgID, &cfg.EntityID, &cfg.EidasNodeURL, &cfg.ACSURL,
		&cfg.IdpCertPem, &cfg.SpCertPem, &cfg.SpKeyPem, &cfg.RequestedLoA,
		&cfg.OrgName, &cfg.OrgDisplayName, &cfg.OrgURL, &cfg.ContactEmail,
		&cfg.IsActive, &cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return cfg, err
}

// Upsert creates or fully replaces the eIDAS config for an org.
func (r *EidasRepository) Upsert(ctx context.Context, cfg *models.EidasConfig) (*models.EidasConfig, error) {
	const q = `INSERT INTO eidas_configs
	               (org_id, entity_id, eidas_node_url, acs_url,
	                idp_cert_pem, sp_cert_pem, sp_key_pem, requested_loa,
	                org_name, org_display_name, org_url, contact_email, is_active)
	           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	           ON CONFLICT (org_id) DO UPDATE SET
	               entity_id        = EXCLUDED.entity_id,
	               eidas_node_url   = EXCLUDED.eidas_node_url,
	               acs_url          = EXCLUDED.acs_url,
	               idp_cert_pem     = EXCLUDED.idp_cert_pem,
	               sp_cert_pem      = CASE WHEN EXCLUDED.sp_cert_pem = '' THEN eidas_configs.sp_cert_pem ELSE EXCLUDED.sp_cert_pem END,
	               sp_key_pem       = CASE WHEN EXCLUDED.sp_key_pem  = '' THEN eidas_configs.sp_key_pem  ELSE EXCLUDED.sp_key_pem  END,
	               requested_loa    = EXCLUDED.requested_loa,
	               org_name         = EXCLUDED.org_name,
	               org_display_name = EXCLUDED.org_display_name,
	               org_url          = EXCLUDED.org_url,
	               contact_email    = EXCLUDED.contact_email,
	               is_active        = EXCLUDED.is_active,
	               updated_at       = NOW()
	           RETURNING id, org_id, entity_id, eidas_node_url, acs_url,
	                     idp_cert_pem, sp_cert_pem, sp_key_pem, requested_loa,
	                     org_name, org_display_name, org_url, contact_email,
	                     is_active, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		cfg.OrgID, cfg.EntityID, cfg.EidasNodeURL, cfg.ACSURL,
		cfg.IdpCertPem, cfg.SpCertPem, cfg.SpKeyPem, cfg.RequestedLoA,
		cfg.OrgName, cfg.OrgDisplayName, cfg.OrgURL, cfg.ContactEmail, cfg.IsActive,
	)
	out := &models.EidasConfig{}
	err := row.Scan(
		&out.ID, &out.OrgID, &out.EntityID, &out.EidasNodeURL, &out.ACSURL,
		&out.IdpCertPem, &out.SpCertPem, &out.SpKeyPem, &out.RequestedLoA,
		&out.OrgName, &out.OrgDisplayName, &out.OrgURL, &out.ContactEmail,
		&out.IsActive, &out.CreatedAt, &out.UpdatedAt,
	)
	return out, err
}
