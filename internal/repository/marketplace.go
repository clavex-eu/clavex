package repository

// marketplace.go — database queries for the Clavex Credential Marketplace.
//
// Public (unauthenticated) queries: ListPublic, GetPublic, SearchPublic.
// Authenticated (org-scoped) queries: ListForOrg, Create, Update, Delete.
// Superadmin queries: Approve, Reject, ListPending.

import (
	"context"
	"encoding/json"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MarketplaceRepository handles reads and writes for credential_marketplace_listings.
type MarketplaceRepository struct {
	pool *pgxpool.Pool
}

// NewMarketplaceRepository creates a MarketplaceRepository.
func NewMarketplaceRepository(pool *pgxpool.Pool) *MarketplaceRepository {
	return &MarketplaceRepository{pool: pool}
}

// ── Column list (shared across all queries) ───────────────────────────────────

const marketplaceCols = `
	l.id, l.org_id, l.credential_config_id,
	l.display_name, l.description, l.issuer_name,
	l.vct, l.credential_format, l.lang,
	l.issuer_endpoint, l.schema_json, l.offer_template,
	l.tags, l.status, l.is_public, l.moderation_note,
	l.created_at, l.updated_at
`

const marketplacePublicCols = `
	l.id, l.display_name, l.description, l.issuer_name,
	o.slug AS issuer_org_slug,
	l.vct, l.credential_format, l.lang,
	l.issuer_endpoint, l.schema_json, l.offer_template,
	l.tags, l.created_at
`

// ── Public queries ────────────────────────────────────────────────────────────

// ListPublic returns all publicly-visible, verified listings.
// Optional: filter by lang or tag (empty string = no filter).
func (r *MarketplaceRepository) ListPublic(ctx context.Context, lang, tag, search string) ([]models.MarketplaceListingPublic, error) {
	q := `
		SELECT ` + marketplacePublicCols + `
		FROM credential_marketplace_listings l
		JOIN organizations o ON o.id = l.org_id
		WHERE l.is_public = true
		  AND l.status   = 'verified'
		  AND ($1 = '' OR l.lang  = $1)
		  AND ($2 = '' OR $2 = ANY(l.tags))
		  AND ($3 = '' OR l.tsv @@ plainto_tsquery('simple', $3))
		ORDER BY l.created_at DESC
	`
	rows, err := r.pool.Query(ctx, q, lang, tag, search)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPublicRows(rows)
}

// GetPublic returns a single publicly-visible, verified listing by ID.
func (r *MarketplaceRepository) GetPublic(ctx context.Context, id uuid.UUID) (*models.MarketplaceListingPublic, error) {
	q := `
		SELECT ` + marketplacePublicCols + `
		FROM credential_marketplace_listings l
		JOIN organizations o ON o.id = l.org_id
		WHERE l.id        = $1
		  AND l.is_public = true
		  AND l.status    = 'verified'
	`
	rows, err := r.pool.Query(ctx, q, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results, err := scanPublicRows(rows)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, pgx.ErrNoRows
	}
	return &results[0], nil
}

// ── Org-scoped queries (authenticated) ───────────────────────────────────────

// ListForOrg returns all listings for an org (all statuses).
func (r *MarketplaceRepository) ListForOrg(ctx context.Context, orgID uuid.UUID) ([]models.MarketplaceListing, error) {
	q := `
		SELECT ` + marketplaceCols + `
		FROM credential_marketplace_listings l
		WHERE l.org_id = $1
		ORDER BY l.created_at DESC
	`
	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// GetForOrg returns a single listing owned by orgID.
func (r *MarketplaceRepository) GetForOrg(ctx context.Context, id, orgID uuid.UUID) (*models.MarketplaceListing, error) {
	q := `
		SELECT ` + marketplaceCols + `
		FROM credential_marketplace_listings l
		WHERE l.id = $1 AND l.org_id = $2
	`
	rows, err := r.pool.Query(ctx, q, id, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, pgx.ErrNoRows
	}
	return &results[0], nil
}

// Create inserts a new listing (status='pending', is_public=false until approved).
func (r *MarketplaceRepository) Create(ctx context.Context, l *models.MarketplaceListing) error {
	schemaBytes, err := json.Marshal(l.SchemaJSON)
	if err != nil {
		return err
	}
	q := `
		INSERT INTO credential_marketplace_listings
			(org_id, credential_config_id,
			 display_name, description, issuer_name,
			 vct, credential_format, lang,
			 issuer_endpoint, schema_json, offer_template,
			 tags)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, status, is_public, created_at, updated_at
	`
	return r.pool.QueryRow(ctx, q,
		l.OrgID, l.CredentialConfigID,
		l.DisplayName, l.Description, l.IssuerName,
		l.VCT, l.CredentialFormat, l.Lang,
		l.IssuerEndpoint, schemaBytes, l.OfferTemplate,
		l.Tags,
	).Scan(&l.ID, &l.Status, &l.IsPublic, &l.CreatedAt, &l.UpdatedAt)
}

// Update allows the owner to update mutable fields of their listing.
// Changing VCT resets status to 'pending' and is_public to false.
func (r *MarketplaceRepository) Update(ctx context.Context, l *models.MarketplaceListing) error {
	schemaBytes, err := json.Marshal(l.SchemaJSON)
	if err != nil {
		return err
	}
	q := `
		UPDATE credential_marketplace_listings SET
			display_name       = $3,
			description        = $4,
			issuer_name        = $5,
			vct                = $6,
			credential_format  = $7,
			lang               = $8,
			issuer_endpoint    = $9,
			schema_json        = $10,
			offer_template     = $11,
			tags               = $12,
			status             = CASE WHEN vct != $6 THEN 'pending' ELSE status END,
			is_public          = CASE WHEN vct != $6 THEN false       ELSE is_public END,
			updated_at         = NOW()
		WHERE id = $1 AND org_id = $2
		RETURNING status, is_public, updated_at
	`
	return r.pool.QueryRow(ctx, q,
		l.ID, l.OrgID,
		l.DisplayName, l.Description, l.IssuerName,
		l.VCT, l.CredentialFormat, l.Lang,
		l.IssuerEndpoint, schemaBytes, l.OfferTemplate,
		l.Tags,
	).Scan(&l.Status, &l.IsPublic, &l.UpdatedAt)
}

// Delete removes a listing owned by orgID.
func (r *MarketplaceRepository) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM credential_marketplace_listings WHERE id = $1 AND org_id = $2`,
		id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ── Superadmin queries ────────────────────────────────────────────────────────

// ListPending returns listings awaiting moderation.
func (r *MarketplaceRepository) ListPending(ctx context.Context) ([]models.MarketplaceListing, error) {
	q := `
		SELECT ` + marketplaceCols + `
		FROM credential_marketplace_listings l
		WHERE l.status = 'pending'
		ORDER BY l.created_at ASC
	`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// Approve marks a listing as verified and makes it publicly visible.
func (r *MarketplaceRepository) Approve(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE credential_marketplace_listings
		SET status = 'verified', is_public = true, moderation_note = NULL, updated_at = NOW()
		WHERE id = $1
	`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// Reject marks a listing as rejected with an optional note.
func (r *MarketplaceRepository) Reject(ctx context.Context, id uuid.UUID, note string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE credential_marketplace_listings
		SET status = 'rejected', is_public = false, moderation_note = $2, updated_at = NOW()
		WHERE id = $1
	`, id, note)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ── Row scanners ──────────────────────────────────────────────────────────────

func scanPublicRows(rows pgx.Rows) ([]models.MarketplaceListingPublic, error) {
	var results []models.MarketplaceListingPublic
	for rows.Next() {
		var l models.MarketplaceListingPublic
		var schemaBytes []byte
		if err := rows.Scan(
			&l.ID, &l.DisplayName, &l.Description, &l.IssuerName,
			&l.IssuerOrgSlug,
			&l.VCT, &l.CredentialFormat, &l.Lang,
			&l.IssuerEndpoint, &schemaBytes, &l.OfferTemplate,
			&l.Tags, &l.CreatedAt,
		); err != nil {
			return nil, err
		}
		if len(schemaBytes) > 0 {
			_ = json.Unmarshal(schemaBytes, &l.SchemaJSON)
		}
		results = append(results, l)
	}
	return results, rows.Err()
}

func scanRows(rows pgx.Rows) ([]models.MarketplaceListing, error) {
	var results []models.MarketplaceListing
	for rows.Next() {
		var l models.MarketplaceListing
		var schemaBytes []byte
		if err := rows.Scan(
			&l.ID, &l.OrgID, &l.CredentialConfigID,
			&l.DisplayName, &l.Description, &l.IssuerName,
			&l.VCT, &l.CredentialFormat, &l.Lang,
			&l.IssuerEndpoint, &schemaBytes, &l.OfferTemplate,
			&l.Tags, &l.Status, &l.IsPublic, &l.ModerationNote,
			&l.CreatedAt, &l.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(schemaBytes) > 0 {
			_ = json.Unmarshal(schemaBytes, &l.SchemaJSON)
		}
		results = append(results, l)
	}
	return results, rows.Err()
}
