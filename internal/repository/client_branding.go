package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ClientBrandingRepository manages per-client branding overrides.
type ClientBrandingRepository struct {
	pool *pgxpool.Pool
}

func NewClientBrandingRepository(pool *pgxpool.Pool) *ClientBrandingRepository {
	return &ClientBrandingRepository{pool: pool}
}

// Get returns the client branding for the given client ID.
// Returns nil, nil if no branding row exists (not an error — use org branding fallback).
func (r *ClientBrandingRepository) Get(ctx context.Context, clientID string) (*models.ClientBranding, error) {
	b := &models.ClientBranding{}
	err := r.pool.QueryRow(ctx, `
		SELECT client_id, company_name, logo_url, primary_color, created_at, updated_at
		  FROM client_branding
		 WHERE client_id = $1
	`, clientID).Scan(&b.ClientID, &b.CompanyName, &b.LogoURL, &b.PrimaryColor, &b.CreatedAt, &b.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get client branding: %w", err)
	}
	return b, nil
}

// Upsert creates or replaces client branding.
func (r *ClientBrandingRepository) Upsert(ctx context.Context, b *models.ClientBranding) (*models.ClientBranding, error) {
	out := &models.ClientBranding{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO client_branding (client_id, company_name, logo_url, primary_color)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (client_id) DO UPDATE
		  SET company_name  = EXCLUDED.company_name,
		      logo_url      = EXCLUDED.logo_url,
		      primary_color = EXCLUDED.primary_color,
		      updated_at    = NOW()
		RETURNING client_id, company_name, logo_url, primary_color, created_at, updated_at
	`, b.ClientID, b.CompanyName, b.LogoURL, b.PrimaryColor).Scan(
		&out.ClientID, &out.CompanyName, &out.LogoURL, &out.PrimaryColor, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert client branding: %w", err)
	}
	return out, nil
}

// Delete removes client branding (reverts to org-level branding).
func (r *ClientBrandingRepository) Delete(ctx context.Context, clientID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM client_branding WHERE client_id = $1`, clientID)
	return err
}
