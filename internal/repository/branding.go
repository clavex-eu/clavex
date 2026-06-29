package repository

import (
	"context"
	"errors"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type BrandingRepository struct {
	pool *pgxpool.Pool
}

func NewBrandingRepository(pool *pgxpool.Pool) *BrandingRepository {
	return &BrandingRepository{pool: pool}
}

// Get returns the branding for an org, or defaults if none set.
func (r *BrandingRepository) Get(ctx context.Context, orgID uuid.UUID) (*models.OrgBranding, error) {
	b := &models.OrgBranding{}
	err := r.pool.QueryRow(ctx, `
		SELECT org_id, company_name, logo_url, favicon_url,
		       primary_color, bg_color, text_color,
		       welcome_title, welcome_subtitle, custom_css, updated_at
		FROM org_branding WHERE org_id = $1
	`, orgID).Scan(
		&b.OrgID, &b.CompanyName, &b.LogoURL, &b.FaviconURL,
		&b.PrimaryColor, &b.BgColor, &b.TextColor,
		&b.WelcomeTitle, &b.WelcomeSubtitle, &b.CustomCSS, &b.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// Return defaults so the frontend always gets a valid object
		return &models.OrgBranding{
			OrgID:        orgID,
			PrimaryColor: "#4f46e5",
			BgColor:      "#f9fafb",
			TextColor:    "#111827",
			WelcomeTitle: "Sign in",
		}, nil
	}
	return b, err
}

// Upsert saves (or replaces) branding for an org.
func (r *BrandingRepository) Upsert(ctx context.Context, b *models.OrgBranding) (*models.OrgBranding, error) {
	out := &models.OrgBranding{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO org_branding
		  (org_id, company_name, logo_url, favicon_url,
		   primary_color, bg_color, text_color,
		   welcome_title, welcome_subtitle, custom_css, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())
		ON CONFLICT (org_id) DO UPDATE SET
		  company_name     = EXCLUDED.company_name,
		  logo_url         = EXCLUDED.logo_url,
		  favicon_url      = EXCLUDED.favicon_url,
		  primary_color    = EXCLUDED.primary_color,
		  bg_color         = EXCLUDED.bg_color,
		  text_color       = EXCLUDED.text_color,
		  welcome_title    = EXCLUDED.welcome_title,
		  welcome_subtitle = EXCLUDED.welcome_subtitle,
		  custom_css       = EXCLUDED.custom_css,
		  updated_at       = now()
		RETURNING org_id, company_name, logo_url, favicon_url,
		          primary_color, bg_color, text_color,
		          welcome_title, welcome_subtitle, custom_css, updated_at
	`,
		b.OrgID, b.CompanyName, b.LogoURL, b.FaviconURL,
		b.PrimaryColor, b.BgColor, b.TextColor,
		b.WelcomeTitle, b.WelcomeSubtitle, b.CustomCSS,
	).Scan(
		&out.OrgID, &out.CompanyName, &out.LogoURL, &out.FaviconURL,
		&out.PrimaryColor, &out.BgColor, &out.TextColor,
		&out.WelcomeTitle, &out.WelcomeSubtitle, &out.CustomCSS, &out.UpdatedAt,
	)
	return out, err
}
