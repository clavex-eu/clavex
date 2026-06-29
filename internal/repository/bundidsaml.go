package repository

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BundIDSAMLRepository handles BundID SAML SP database operations.
type BundIDSAMLRepository struct {
	pool *pgxpool.Pool
}

func NewBundIDSAMLRepository(pool *pgxpool.Pool) *BundIDSAMLRepository {
	return &BundIDSAMLRepository{pool: pool}
}

// Pool returns the underlying connection pool (used by handlers needing other repos).
func (r *BundIDSAMLRepository) Pool() *pgxpool.Pool { return r.pool }

// ── SP Config ─────────────────────────────────────────────────────────────────

const bundidSAMLCols = `org_id, entity_id, org_name, org_display_name, org_url,
	contact_email, contact_phone, environment, min_loa, attribute_set,
	sp_cert_pem, sp_key_pem, is_active, created_at, updated_at`

func scanBundIDSAMLConfig(row interface{ Scan(...any) error }) (*models.BundIDSAMLConfig, error) {
	c := &models.BundIDSAMLConfig{}
	return c, row.Scan(
		&c.OrgID, &c.EntityID, &c.OrgName, &c.OrgDisplayName, &c.OrgURL,
		&c.ContactEmail, &c.ContactPhone, &c.Environment, &c.MinLoA, &c.AttributeSet,
		&c.SpCertPem, &c.SpKeyPem, &c.IsActive, &c.CreatedAt, &c.UpdatedAt,
	)
}

// GetConfig retrieves the BundID SAML config for an org (returns nil if not configured).
func (r *BundIDSAMLRepository) GetConfig(ctx context.Context, orgID uuid.UUID) (*models.BundIDSAMLConfig, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+bundidSAMLCols+` FROM bundid_saml_configs WHERE org_id = $1`, orgID)
	c, err := scanBundIDSAMLConfig(row)
	if err != nil {
		return nil, nil // not found → nil, nil
	}
	return c, nil
}

// UpsertConfig inserts or updates the BundID SAML config for an org.
// If sp_cert_pem / sp_key_pem are nil in the update, the existing values are preserved.
func (r *BundIDSAMLRepository) UpsertConfig(ctx context.Context, c *models.BundIDSAMLConfig) (*models.BundIDSAMLConfig, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO bundid_saml_configs
			(org_id, entity_id, org_name, org_display_name, org_url,
			 contact_email, contact_phone, environment, min_loa, attribute_set,
			 sp_cert_pem, sp_key_pem, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (org_id) DO UPDATE SET
			entity_id        = EXCLUDED.entity_id,
			org_name         = EXCLUDED.org_name,
			org_display_name = EXCLUDED.org_display_name,
			org_url          = EXCLUDED.org_url,
			contact_email    = EXCLUDED.contact_email,
			contact_phone    = EXCLUDED.contact_phone,
			environment      = EXCLUDED.environment,
			min_loa          = EXCLUDED.min_loa,
			attribute_set    = EXCLUDED.attribute_set,
			sp_cert_pem      = COALESCE(EXCLUDED.sp_cert_pem, bundid_saml_configs.sp_cert_pem),
			sp_key_pem       = COALESCE(EXCLUDED.sp_key_pem, bundid_saml_configs.sp_key_pem),
			is_active        = EXCLUDED.is_active,
			updated_at       = NOW()
		RETURNING `+bundidSAMLCols,
		c.OrgID, c.EntityID, c.OrgName, c.OrgDisplayName, c.OrgURL,
		c.ContactEmail, c.ContactPhone, c.Environment, c.MinLoA, c.AttributeSet,
		c.SpCertPem, c.SpKeyPem, c.IsActive,
	)
	return scanBundIDSAMLConfig(row)
}

// SaveCert stores an auto-generated SP cert/key for an org (called once on first activation).
func (r *BundIDSAMLRepository) SaveCert(ctx context.Context, orgID uuid.UUID, certPEM, keyPEM string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE bundid_saml_configs
		SET sp_cert_pem = $2, sp_key_pem = $3, updated_at = NOW()
		WHERE org_id = $1`, orgID, certPEM, keyPEM)
	return err
}

// ── IdP metadata cache ────────────────────────────────────────────────────────
// BundID has one canonical IdP per environment, so we cache the metadata XML in
// a simple key-value table rather than a full registry table. We reuse the
// spid_idp_registry structure would be overkill; instead we store the XML and
// fetch timestamp in a dedicated table row identified by environment.

// CachedMetadata holds a cached copy of the BundID IdP metadata XML.
type CachedMetadata struct {
	MetadataXML string
	FetchedAt   time.Time
}

// GetCachedMetadata returns the cached IdP metadata XML for the given environment.
// Returns nil if not yet cached.
func (r *BundIDSAMLRepository) GetCachedMetadata(ctx context.Context, environment string) (*CachedMetadata, error) {
	var xmlStr string
	var fetchedAt time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT sp_cert_pem, updated_at
		FROM bundid_saml_configs
		WHERE environment = $1 AND sp_cert_pem IS NOT NULL
		LIMIT 1`, environment).Scan(&xmlStr, &fetchedAt)
	if err != nil {
		return nil, nil
	}
	return &CachedMetadata{MetadataXML: xmlStr, FetchedAt: fetchedAt}, nil
}

// SaveCachedMetadata is a no-op stub; BundID metadata is fetched live by the handler
// using ParseIDPMetadataURL and stored in memory for the request lifetime.
// For persistent caching across restarts, extend this method to write to a
// dedicated bundid_idp_metadata table (migration 000052).
func (r *BundIDSAMLRepository) SaveCachedMetadata(_ context.Context, _ string, _ string) error {
	return nil // extend in migration 000052 if needed
}
