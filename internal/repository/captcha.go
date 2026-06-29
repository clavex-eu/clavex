package repository

import (
	"context"
	"errors"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CaptchaRepository manages per-org CAPTCHA settings.
type CaptchaRepository struct {
	pool *pgxpool.Pool
}

func NewCaptchaRepository(pool *pgxpool.Pool) *CaptchaRepository {
	return &CaptchaRepository{pool: pool}
}

// Get returns the CAPTCHA settings for an org; returns nil, nil if not configured.
func (r *CaptchaRepository) Get(ctx context.Context, orgID uuid.UUID) (*models.CaptchaSettings, error) {
	s := &models.CaptchaSettings{}
	err := r.pool.QueryRow(ctx, `
		SELECT org_id, provider, site_key, secret_key, is_active
		FROM identity.org_captcha_settings WHERE org_id = $1
	`, orgID).Scan(&s.OrgID, &s.Provider, &s.SiteKey, &s.SecretKey, &s.IsActive)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return s, err
}

// Upsert creates or replaces the CAPTCHA settings for an org.
func (r *CaptchaRepository) Upsert(ctx context.Context, s *models.CaptchaSettings) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO identity.org_captcha_settings (org_id, provider, site_key, secret_key, is_active, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (org_id) DO UPDATE
		SET provider   = EXCLUDED.provider,
		    site_key   = EXCLUDED.site_key,
		    secret_key = EXCLUDED.secret_key,
		    is_active  = EXCLUDED.is_active,
		    updated_at = NOW()
	`, s.OrgID, s.Provider, s.SiteKey, s.SecretKey, s.IsActive)
	return err
}

// Delete removes the CAPTCHA settings for an org entirely.
func (r *CaptchaRepository) Delete(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM identity.org_captcha_settings WHERE org_id = $1`, orgID)
	return err
}
