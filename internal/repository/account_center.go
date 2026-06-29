package repository

import (
	"context"
	"errors"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AccountCenterRepository persists per-org Account Center widget configuration.
type AccountCenterRepository struct {
	pool *pgxpool.Pool
}

func NewAccountCenterRepository(pool *pgxpool.Pool) *AccountCenterRepository {
	return &AccountCenterRepository{pool: pool}
}

const selectAccountCenterSQL = `
	SELECT org_id, show_profile, show_password, show_mfa, show_passkeys,
	       show_sessions, show_activity, show_data_export, page_title, updated_at
	FROM   account_center_configs
	WHERE  org_id = $1`

// GetByOrg returns the account center config for the given org.
// If no row has been saved yet it returns a default config (all sections
// enabled) rather than an error, so callers never need to special-case the
// "not configured" state.
func (r *AccountCenterRepository) GetByOrg(ctx context.Context, orgID uuid.UUID) (*models.AccountCenterConfig, error) {
	cfg := &models.AccountCenterConfig{}
	err := r.pool.QueryRow(ctx, selectAccountCenterSQL, orgID).Scan(
		&cfg.OrgID, &cfg.ShowProfile, &cfg.ShowPassword, &cfg.ShowMFA,
		&cfg.ShowPasskeys, &cfg.ShowSessions, &cfg.ShowActivity,
		&cfg.ShowDataExport, &cfg.PageTitle, &cfg.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.DefaultAccountCenterConfig(orgID), nil
		}
		return nil, err
	}
	return cfg, nil
}

const upsertAccountCenterSQL = `
	INSERT INTO account_center_configs
	    (org_id, show_profile, show_password, show_mfa, show_passkeys,
	     show_sessions, show_activity, show_data_export, page_title, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
	ON CONFLICT (org_id) DO UPDATE SET
	    show_profile     = EXCLUDED.show_profile,
	    show_password    = EXCLUDED.show_password,
	    show_mfa         = EXCLUDED.show_mfa,
	    show_passkeys    = EXCLUDED.show_passkeys,
	    show_sessions    = EXCLUDED.show_sessions,
	    show_activity    = EXCLUDED.show_activity,
	    show_data_export = EXCLUDED.show_data_export,
	    page_title       = EXCLUDED.page_title,
	    updated_at       = NOW()
	RETURNING org_id, show_profile, show_password, show_mfa, show_passkeys,
	          show_sessions, show_activity, show_data_export, page_title, updated_at`

// Upsert creates or replaces the account center config for the given org and
// returns the persisted row.
func (r *AccountCenterRepository) Upsert(ctx context.Context, cfg *models.AccountCenterConfig) (*models.AccountCenterConfig, error) {
	out := &models.AccountCenterConfig{}
	err := r.pool.QueryRow(ctx, upsertAccountCenterSQL,
		cfg.OrgID, cfg.ShowProfile, cfg.ShowPassword, cfg.ShowMFA,
		cfg.ShowPasskeys, cfg.ShowSessions, cfg.ShowActivity,
		cfg.ShowDataExport, cfg.PageTitle,
	).Scan(
		&out.OrgID, &out.ShowProfile, &out.ShowPassword, &out.ShowMFA,
		&out.ShowPasskeys, &out.ShowSessions, &out.ShowActivity,
		&out.ShowDataExport, &out.PageTitle, &out.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}
