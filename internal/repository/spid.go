package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SPIDRepository handles SPID/CIE database operations.
type SPIDRepository struct {
	pool *pgxpool.Pool
}

func NewSPIDRepository(pool *pgxpool.Pool) *SPIDRepository {
	return &SPIDRepository{pool: pool}
}

// Pool returns the underlying connection pool (used by handlers needing other repos).
func (r *SPIDRepository) Pool() *pgxpool.Pool { return r.pool }

// ── SPID instance config (singleton) ──────────────────────────────────────────

const spidInstanceCols = `id, entity_id, org_name, org_display_name, org_locality, org_url,
	contact_email, contact_phone, vat_number, ipa_code, entity_type,
	sp_cert_pem, sp_key_pem, created_at, updated_at`

func scanSPIDInstanceConfig(row interface{ Scan(...any) error }) (*models.SPIDInstanceConfig, error) {
	c := &models.SPIDInstanceConfig{}
	return c, row.Scan(
		&c.ID, &c.EntityID, &c.OrgName, &c.OrgDisplayName, &c.OrgLocality, &c.OrgURL,
		&c.ContactEmail, &c.ContactPhone, &c.VATNumber, &c.IPACode, &c.EntityType,
		&c.SpCertPem, &c.SpKeyPem, &c.CreatedAt, &c.UpdatedAt,
	)
}

// GetSPIDInstanceConfig returns the singleton instance config (nil if not configured).
func (r *SPIDRepository) GetSPIDInstanceConfig(ctx context.Context) (*models.SPIDInstanceConfig, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+spidInstanceCols+` FROM spid_instance_config LIMIT 1`)
	c, err := scanSPIDInstanceConfig(row)
	if err != nil {
		return nil, nil
	}
	return c, nil
}

// UpsertSPIDInstanceConfig inserts or updates the singleton instance config.
func (r *SPIDRepository) UpsertSPIDInstanceConfig(ctx context.Context, c *models.SPIDInstanceConfig) (*models.SPIDInstanceConfig, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO spid_instance_config
			(entity_id, org_name, org_display_name, org_locality, org_url,
			 contact_email, contact_phone, vat_number, ipa_code, entity_type,
			 sp_cert_pem, sp_key_pem)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT ((true)) DO UPDATE SET
			entity_id        = EXCLUDED.entity_id,
			org_name         = EXCLUDED.org_name,
			org_display_name = EXCLUDED.org_display_name,
			org_locality     = EXCLUDED.org_locality,
			org_url          = EXCLUDED.org_url,
			contact_email    = EXCLUDED.contact_email,
			contact_phone    = EXCLUDED.contact_phone,
			vat_number       = EXCLUDED.vat_number,
			ipa_code         = EXCLUDED.ipa_code,
			entity_type      = EXCLUDED.entity_type,
			sp_cert_pem      = COALESCE(EXCLUDED.sp_cert_pem, spid_instance_config.sp_cert_pem),
			sp_key_pem       = COALESCE(EXCLUDED.sp_key_pem, spid_instance_config.sp_key_pem),
			updated_at       = NOW()
		RETURNING `+spidInstanceCols,
		c.EntityID, c.OrgName, c.OrgDisplayName, c.OrgLocality, c.OrgURL,
		c.ContactEmail, c.ContactPhone, c.VATNumber, c.IPACode, c.EntityType,
		c.SpCertPem, c.SpKeyPem,
	)
	return scanSPIDInstanceConfig(row)
}

// ── SPID per-org config ────────────────────────────────────────────────────────

const spidConfigCols = `org_id, authn_level, attribute_set, is_active, created_at, updated_at`

func scanSPIDConfig(row interface{ Scan(...any) error }) (*models.SPIDConfig, error) {
	c := &models.SPIDConfig{}
	return c, row.Scan(
		&c.OrgID, &c.AuthnLevel, &c.AttributeSet,
		&c.IsActive, &c.CreatedAt, &c.UpdatedAt,
	)
}

// GetSPIDConfig retrieves the SPID config for an org (returns nil if not configured).
func (r *SPIDRepository) GetSPIDConfig(ctx context.Context, orgID uuid.UUID) (*models.SPIDConfig, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+spidConfigCols+` FROM spid_configs WHERE org_id = $1`, orgID)
	c, err := scanSPIDConfig(row)
	if err != nil {
		return nil, nil
	}
	return c, nil
}

// UpsertSPIDConfig inserts or updates the per-org SPID preferences.
func (r *SPIDRepository) UpsertSPIDConfig(ctx context.Context, c *models.SPIDConfig) (*models.SPIDConfig, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO spid_configs (org_id, authn_level, attribute_set, is_active)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (org_id) DO UPDATE SET
			authn_level   = EXCLUDED.authn_level,
			attribute_set = EXCLUDED.attribute_set,
			is_active     = EXCLUDED.is_active,
			updated_at    = NOW()
		RETURNING `+spidConfigCols,
		c.OrgID, c.AuthnLevel, c.AttributeSet, c.IsActive,
	)
	return scanSPIDConfig(row)
}

// ── SPID IdP Registry ──────────────────────────────────────────────────────────

const spidIdpCols = `id, entity_id, display_name, logo_url, metadata_url,
	metadata_xml, metadata_fetched_at, is_active, is_test, created_at, updated_at`

func scanSPIDIdP(row interface{ Scan(...any) error }) (*models.SPIDIdP, error) {
	p := &models.SPIDIdP{}
	return p, row.Scan(
		&p.ID, &p.EntityID, &p.DisplayName, &p.LogoURL,
		&p.MetadataURL, &p.MetadataXML, &p.MetadataFetchedAt,
		&p.IsActive, &p.IsTest, &p.CreatedAt, &p.UpdatedAt,
	)
}

// ListIdPs returns all SPID IdPs (active ones by default, optional includeTest flag).
func (r *SPIDRepository) ListIdPs(ctx context.Context, includeTest bool) ([]*models.SPIDIdP, error) {
	q := `SELECT ` + spidIdpCols + ` FROM spid_idp_registry WHERE is_active = true`
	if !includeTest {
		q += ` AND is_test = false`
	}
	q += ` ORDER BY display_name`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.SPIDIdP
	for rows.Next() {
		p, err := scanSPIDIdP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []*models.SPIDIdP{}
	}
	return out, rows.Err()
}

// GetIdPByEntityID returns a SPID IdP by its SAML entity ID.
func (r *SPIDRepository) GetIdPByEntityID(ctx context.Context, entityID string) (*models.SPIDIdP, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+spidIdpCols+` FROM spid_idp_registry WHERE entity_id = $1`, entityID)
	p, err := scanSPIDIdP(row)
	if err != nil {
		return nil, fmt.Errorf("spid idp not found: %s", entityID)
	}
	return p, nil
}

// GetIdPByID returns a SPID IdP by its UUID.
func (r *SPIDRepository) GetIdPByID(ctx context.Context, id uuid.UUID) (*models.SPIDIdP, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+spidIdpCols+` FROM spid_idp_registry WHERE id = $1`, id)
	p, err := scanSPIDIdP(row)
	if err != nil {
		return nil, fmt.Errorf("spid idp not found: %s", id)
	}
	return p, nil
}

// SaveIdPMetadata caches the fetched IdP metadata XML.
func (r *SPIDRepository) SaveIdPMetadata(ctx context.Context, entityID, metadataXML string) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx, `
		UPDATE spid_idp_registry
		SET metadata_xml = $2, metadata_fetched_at = $3, updated_at = $3
		WHERE entity_id = $1`, entityID, metadataXML, now)
	return err
}
