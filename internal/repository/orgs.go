package repository

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OrgRepository handles organization persistence.
type OrgRepository struct {
	pool *pgxpool.Pool
}

func NewOrgRepository(pool *pgxpool.Pool) *OrgRepository {
	return &OrgRepository{pool: pool}
}

func (r *OrgRepository) Create(ctx context.Context, name, slug string, logoURL *string) (*models.Organization, error) {
	org := &models.Organization{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug, logo_url)
		VALUES ($1, $2, $3)
		RETURNING id, name, slug, logo_url, settings, is_active, mfa_required,
		          claims_enrichment_url, claims_enrichment_secret, custom_login_html, access_token_ttl, refresh_token_ttl, conformance_mode, created_at, updated_at
	`, name, slug, logoURL).Scan(
		&org.ID, &org.Name, &org.Slug, &org.LogoURL,
		&org.Settings, &org.IsActive, &org.MFARequired,
		&org.ClaimsEnrichmentURL, &org.ClaimsEnrichmentSecret, &org.CustomLoginHTML, &org.AccessTokenTTL, &org.RefreshTokenTTL, &org.ConformanceMode, &org.CreatedAt, &org.UpdatedAt,
	)
	return org, err
}

func (r *OrgRepository) List(ctx context.Context) ([]*models.Organization, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, slug, logo_url, settings, is_active, mfa_required,
		       claims_enrichment_url, claims_enrichment_secret, custom_login_html, access_token_ttl, refresh_token_ttl, conformance_mode, created_at, updated_at
		FROM organizations ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	orgs := make([]*models.Organization, 0)
	for rows.Next() {
		o := &models.Organization{}
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.LogoURL, &o.Settings, &o.IsActive, &o.MFARequired,
			&o.ClaimsEnrichmentURL, &o.ClaimsEnrichmentSecret, &o.CustomLoginHTML, &o.AccessTokenTTL, &o.RefreshTokenTTL, &o.ConformanceMode, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

func (r *OrgRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	o := &models.Organization{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, slug, logo_url, settings, is_active, mfa_required,
		       claims_enrichment_url, claims_enrichment_secret, custom_login_html, access_token_ttl, refresh_token_ttl, conformance_mode, created_at, updated_at
		FROM organizations WHERE id = $1
	`, id).Scan(&o.ID, &o.Name, &o.Slug, &o.LogoURL, &o.Settings, &o.IsActive, &o.MFARequired,
		&o.ClaimsEnrichmentURL, &o.ClaimsEnrichmentSecret, &o.CustomLoginHTML, &o.AccessTokenTTL, &o.RefreshTokenTTL, &o.ConformanceMode, &o.CreatedAt, &o.UpdatedAt)
	return o, err
}

func (r *OrgRepository) GetBySlug(ctx context.Context, slug string) (*models.Organization, error) {
	o := &models.Organization{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, slug, logo_url, settings, is_active, mfa_required,
		       claims_enrichment_url, claims_enrichment_secret, custom_login_html, access_token_ttl, refresh_token_ttl, conformance_mode, created_at, updated_at
		FROM organizations WHERE slug = $1
	`, slug).Scan(&o.ID, &o.Name, &o.Slug, &o.LogoURL, &o.Settings, &o.IsActive, &o.MFARequired,
		&o.ClaimsEnrichmentURL, &o.ClaimsEnrichmentSecret, &o.CustomLoginHTML, &o.AccessTokenTTL, &o.RefreshTokenTTL, &o.ConformanceMode, &o.CreatedAt, &o.UpdatedAt)
	return o, err
}

func (r *OrgRepository) Update(ctx context.Context, id uuid.UUID, name, logoURL *string, isActive, mfaRequired *bool, accessTokenTTL, refreshTokenTTL *int) (*models.Organization, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	o := &models.Organization{}
	if err = tx.QueryRow(ctx, `
		UPDATE organizations SET
			name              = COALESCE($2, name),
			logo_url          = COALESCE($3, logo_url),
			is_active         = COALESCE($4, is_active),
			mfa_required      = COALESCE($5, mfa_required),
			access_token_ttl  = CASE WHEN $6 IS NULL THEN access_token_ttl WHEN $6 = 0 THEN NULL ELSE $6 END,
			refresh_token_ttl = CASE WHEN $7 IS NULL THEN refresh_token_ttl WHEN $7 = 0 THEN NULL ELSE $7 END,
			updated_at        = NOW()
		WHERE id = $1
		RETURNING id, name, slug, logo_url, settings, is_active, mfa_required,
		          claims_enrichment_url, claims_enrichment_secret, custom_login_html, access_token_ttl, refresh_token_ttl, conformance_mode, created_at, updated_at
	`, id, name, logoURL, isActive, mfaRequired, accessTokenTTL, refreshTokenTTL).Scan(
		&o.ID, &o.Name, &o.Slug, &o.LogoURL, &o.Settings, &o.IsActive, &o.MFARequired,
		&o.ClaimsEnrichmentURL, &o.ClaimsEnrichmentSecret, &o.CustomLoginHTML, &o.AccessTokenTTL, &o.RefreshTokenTTL, &o.ConformanceMode, &o.CreatedAt, &o.UpdatedAt,
	); err != nil {
		return nil, err
	}

	// Emit org.policy_changed whenever a policy-relevant field is touched.
	if isActive != nil || mfaRequired != nil {
		payload := map[string]any{"updated_at": time.Now().UTC().Format(time.RFC3339)}
		if isActive != nil {
			payload["is_active"] = *isActive
		}
		if mfaRequired != nil {
			payload["mfa_required"] = *mfaRequired
		}
		evRepo := NewEntityEventsRepository(r.pool)
		if evErr := evRepo.AppendTx(ctx, tx, AppendParams{
			OrgID:      id,
			EntityType: "org",
			EntityID:   id.String(),
			EventType:  "org.policy_changed",
			Payload:    payload,
			OccurredAt: time.Now().UTC(),
		}); evErr != nil {
			return nil, evErr
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return o, nil
}

func (r *OrgRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	return err
}

// GetIDBySlug returns only the UUID of an org by its slug.
func (r *OrgRepository) GetIDBySlug(ctx context.Context, slug string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `SELECT id FROM organizations WHERE slug = $1`, slug).Scan(&id)
	return id, err
}

// SetEnrichmentConfig updates the per-org claims-enrichment hook.
// Pass nil for both url and secret to disable the hook.
func (r *OrgRepository) SetEnrichmentConfig(ctx context.Context, orgID uuid.UUID, url, secret *string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE organizations
		   SET claims_enrichment_url    = $2,
		       claims_enrichment_secret = $3,
		       updated_at               = NOW()
		 WHERE id = $1
	`, orgID, url, secret)
	return err
}

// SetCustomLoginHTML sets or clears the per-org custom Universal Login template.
// Pass nil to revert to the built-in login page.
func (r *OrgRepository) SetCustomLoginHTML(ctx context.Context, orgID uuid.UUID, html *string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE organizations
		   SET custom_login_html = $2,
		       updated_at        = NOW()
		 WHERE id = $1
	`, orgID, html)
	return err
}

// GetCustomLoginHTML returns the custom login HTML for an org, or nil if not set.
func (r *OrgRepository) GetCustomLoginHTML(ctx context.Context, orgID uuid.UUID) (*string, error) {
	var html *string
	err := r.pool.QueryRow(ctx, `SELECT custom_login_html FROM organizations WHERE id = $1`, orgID).Scan(&html)
	return html, err
}

// GetAIKey returns the raw Anthropic API key for an org, or nil if not configured.
func (r *OrgRepository) GetAIKey(ctx context.Context, orgID uuid.UUID) (*string, error) {
	var key *string
	err := r.pool.QueryRow(ctx, `SELECT ai_anthropic_key FROM organizations WHERE id = $1`, orgID).Scan(&key)
	return key, err
}

// SetAIKey stores or clears the Anthropic API key for an org.
// Pass nil to remove the key.
func (r *OrgRepository) SetAIKey(ctx context.Context, orgID uuid.UUID, key *string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE organizations
		   SET ai_anthropic_key = $2,
		       updated_at       = NOW()
		 WHERE id = $1
	`, orgID, key)
	return err
}

// SetAutoEnrollConfig updates the domain-based enrollment configuration for an org.
// domains is the list of email domains that trigger automatic enrollment (e.g. ["acme.com"]).
// roleID is the role to assign; pass nil to enroll without a role.
func (r *OrgRepository) SetAutoEnrollConfig(ctx context.Context, orgID uuid.UUID, domains []string, roleID *uuid.UUID) error {
	if domains == nil {
		domains = []string{}
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE organizations
		   SET auto_enroll_domains = $2,
		       auto_enroll_role_id = $3,
		       updated_at          = NOW()
		 WHERE id = $1
	`, orgID, domains, roleID)
	return err
}

// FindAutoEnrollOrg returns the org (if any) that should auto-enroll a user
// based on their email domain. Checks all active orgs with non-empty auto_enroll_domains.
// Returns nil, nil if no match.
func (r *OrgRepository) FindAutoEnrollOrg(ctx context.Context, emailDomain string) (*models.Organization, error) {
	o := &models.Organization{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, slug, logo_url, settings, is_active, mfa_required,
		       claims_enrichment_url, auto_enroll_domains, auto_enroll_role_id,
		       created_at, updated_at
		FROM organizations
		WHERE is_active = true
		  AND $1 = ANY(auto_enroll_domains)
		LIMIT 1
	`, emailDomain).Scan(
		&o.ID, &o.Name, &o.Slug, &o.LogoURL, &o.Settings, &o.IsActive, &o.MFARequired,
		&o.ClaimsEnrichmentURL, &o.AutoEnrollDomains, &o.AutoEnrollRoleID,
		&o.CreatedAt, &o.UpdatedAt,
	)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return o, nil
}

// GetAutoEnrollConfig returns only the enrollment config fields for an org.
func (r *OrgRepository) GetAutoEnrollConfig(ctx context.Context, orgID uuid.UUID) (domains []string, roleID *uuid.UUID, err error) {
	err = r.pool.QueryRow(ctx, `
		SELECT auto_enroll_domains, auto_enroll_role_id FROM organizations WHERE id = $1
	`, orgID).Scan(&domains, &roleID)
	if domains == nil {
		domains = []string{}
	}
	return
}

// GetFleetSecret returns the fleet_ingest_secret for an org.
// Returns nil, nil when the secret is unset (fleet ingestion disabled).
func (r *OrgRepository) GetFleetSecret(ctx context.Context, orgID uuid.UUID) (*string, error) {
	var secret *string
	err := r.pool.QueryRow(ctx, `SELECT fleet_ingest_secret FROM organizations WHERE id = $1`, orgID).Scan(&secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// SetFleetSecret updates the fleet_ingest_secret for an org.
// Pass nil to disable fleet ingestion.
func (r *OrgRepository) SetFleetSecret(ctx context.Context, orgID uuid.UUID, secret *string) error {
	_, err := r.pool.Exec(ctx, `UPDATE organizations SET fleet_ingest_secret = $2, updated_at = NOW() WHERE id = $1`, orgID, secret)
	return err
}

// ─── Email Policy ─────────────────────────────────────────────────────────────

// SetEmailPolicy overwrites the blocklist/allowlist for an org.
// Pass empty slices to clear the policy.
func (r *OrgRepository) SetEmailPolicy(ctx context.Context, orgID uuid.UUID, blocklist, allowlist []string) error {
	if blocklist == nil {
		blocklist = []string{}
	}
	if allowlist == nil {
		allowlist = []string{}
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE organizations
		   SET email_blocklist = $2,
		       email_allowlist = $3,
		       updated_at      = NOW()
		 WHERE id = $1
	`, orgID, blocklist, allowlist)
	return err
}

// GetEmailPolicy returns the blocklist and allowlist for an org.
func (r *OrgRepository) GetEmailPolicy(ctx context.Context, orgID uuid.UUID) (blocklist, allowlist []string, err error) {
	err = r.pool.QueryRow(ctx, `
		SELECT email_blocklist, email_allowlist FROM organizations WHERE id = $1
	`, orgID).Scan(&blocklist, &allowlist)
	if blocklist == nil {
		blocklist = []string{}
	}
	if allowlist == nil {
		allowlist = []string{}
	}
	return
}
