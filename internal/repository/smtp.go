package repository

import (
	"context"
	"fmt"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SMTPRepository manages per-org SMTP server settings.
type SMTPRepository struct {
	pool *pgxpool.Pool
}

func NewSMTPRepository(pool *pgxpool.Pool) *SMTPRepository {
	return &SMTPRepository{pool: pool}
}

const smtpColumns = `org_id, host, port, username, from_address, from_name, use_tls, is_active, updated_at`

// Get returns SMTP settings for an org (password is never included).
func (r *SMTPRepository) Get(ctx context.Context, orgID uuid.UUID) (*models.SMTPSettings, error) {
	s := &models.SMTPSettings{}
	err := r.pool.QueryRow(ctx,
		`SELECT `+smtpColumns+` FROM org_smtp_settings WHERE org_id = $1`, orgID,
	).Scan(&s.OrgID, &s.Host, &s.Port, &s.Username, &s.FromAddress, &s.FromName, &s.UseTLS, &s.IsActive, &s.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get smtp settings: %w", err)
	}
	return s, nil
}

// GetWithPassword returns SMTP settings including the stored password.
// Used only by the mailer service — never returned via the API.
func (r *SMTPRepository) GetWithPassword(ctx context.Context, orgID uuid.UUID) (*models.SMTPSettings, error) {
	s := &models.SMTPSettings{}
	var password *string
	err := r.pool.QueryRow(ctx,
		`SELECT `+smtpColumns+`, password FROM org_smtp_settings WHERE org_id = $1`, orgID,
	).Scan(&s.OrgID, &s.Host, &s.Port, &s.Username, &s.FromAddress, &s.FromName, &s.UseTLS, &s.IsActive, &s.UpdatedAt, &password)
	if err != nil {
		return nil, fmt.Errorf("get smtp settings with password: %w", err)
	}
	s.Password = password
	return s, nil
}

// Upsert creates or replaces SMTP settings. Password is only updated when non-empty.
func (r *SMTPRepository) Upsert(ctx context.Context, s *models.SMTPSettings, rawPassword string) (*models.SMTPSettings, error) {
	out := &models.SMTPSettings{}

	var query string
	var args []interface{}
	if rawPassword != "" {
		query = `
			INSERT INTO org_smtp_settings
				(org_id, host, port, username, password, from_address, from_name, use_tls, is_active, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
			ON CONFLICT (org_id) DO UPDATE SET
				host=EXCLUDED.host, port=EXCLUDED.port, username=EXCLUDED.username,
				password=EXCLUDED.password, from_address=EXCLUDED.from_address,
				from_name=EXCLUDED.from_name, use_tls=EXCLUDED.use_tls,
				is_active=EXCLUDED.is_active, updated_at=NOW()
			RETURNING ` + smtpColumns
		args = []interface{}{s.OrgID, s.Host, s.Port, s.Username, rawPassword,
			s.FromAddress, s.FromName, s.UseTLS, s.IsActive}
	} else {
		query = `
			INSERT INTO org_smtp_settings
				(org_id, host, port, username, from_address, from_name, use_tls, is_active, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
			ON CONFLICT (org_id) DO UPDATE SET
				host=EXCLUDED.host, port=EXCLUDED.port, username=EXCLUDED.username,
				from_address=EXCLUDED.from_address, from_name=EXCLUDED.from_name,
				use_tls=EXCLUDED.use_tls, is_active=EXCLUDED.is_active, updated_at=NOW()
			RETURNING ` + smtpColumns
		args = []interface{}{s.OrgID, s.Host, s.Port, s.Username,
			s.FromAddress, s.FromName, s.UseTLS, s.IsActive}
	}

	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&out.OrgID, &out.Host, &out.Port, &out.Username,
		&out.FromAddress, &out.FromName, &out.UseTLS, &out.IsActive, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert smtp settings: %w", err)
	}
	return out, nil
}
