package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GDPRRetentionPolicy holds the per-org GDPR Art.5(1)(e) data retention settings.
type GDPRRetentionPolicy struct {
	OrgID            uuid.UUID `json:"org_id"`
	RetentionDays    int       `json:"retention_days"`
	ActivityField    string    `json:"activity_field"`   // "last_login_at" | "updated_at"
	ExemptRoleNames  []string  `json:"exempt_role_names"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// GDPRRetentionRepository manages org_gdpr_retention rows and runs anonymisation.
type GDPRRetentionRepository struct {
	pool *pgxpool.Pool
}

// NewGDPRRetentionRepository creates a new GDPRRetentionRepository.
func NewGDPRRetentionRepository(pool *pgxpool.Pool) *GDPRRetentionRepository {
	return &GDPRRetentionRepository{pool: pool}
}

// Get loads the GDPR retention policy for an org.
// Returns nil, nil when no policy row exists (feature is not configured).
func (r *GDPRRetentionRepository) Get(ctx context.Context, orgID uuid.UUID) (*GDPRRetentionPolicy, error) {
	p := &GDPRRetentionPolicy{}
	err := r.pool.QueryRow(ctx, `
		SELECT org_id, retention_days, activity_field, exempt_role_names,
		       enabled, created_at, updated_at
		FROM org_gdpr_retention
		WHERE org_id = $1
	`, orgID).Scan(
		&p.OrgID, &p.RetentionDays, &p.ActivityField, &p.ExemptRoleNames,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if p.ExemptRoleNames == nil {
		p.ExemptRoleNames = []string{}
	}
	return p, nil
}

// Upsert creates or replaces the GDPR retention policy for an org.
func (r *GDPRRetentionRepository) Upsert(ctx context.Context, p GDPRRetentionPolicy) error {
	if p.ActivityField != "last_login_at" && p.ActivityField != "updated_at" {
		p.ActivityField = "last_login_at"
	}
	if p.RetentionDays <= 0 {
		p.RetentionDays = 730
	}
	if p.ExemptRoleNames == nil {
		p.ExemptRoleNames = []string{}
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO org_gdpr_retention
		    (org_id, retention_days, activity_field, exempt_role_names, enabled, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (org_id) DO UPDATE SET
		    retention_days    = EXCLUDED.retention_days,
		    activity_field    = EXCLUDED.activity_field,
		    exempt_role_names = EXCLUDED.exempt_role_names,
		    enabled           = EXCLUDED.enabled,
		    updated_at        = EXCLUDED.updated_at
	`, p.OrgID, p.RetentionDays, p.ActivityField, p.ExemptRoleNames, p.Enabled)
	return err
}

// Delete removes the GDPR retention policy for an org.
func (r *GDPRRetentionRepository) Delete(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM org_gdpr_retention WHERE org_id = $1`, orgID)
	return err
}

// AnonymizeInactiveUsers anonymises users across all orgs that have an enabled
// retention policy where the user's last activity is older than retention_days.
//
// Anonymisation replaces PII with placeholders:
//   - email          → "anon-<uuid>@gdpr.deleted"
//   - first_name     → NULL
//   - last_name      → NULL
//   - avatar_url     → NULL
//   - password_hash  → NULL
//   - metadata       → {}
//   - is_active      → false
//
// Users that already carry the anon email pattern, users that are already
// inactive, and users that hold any of the org's exempt_role_names are skipped.
// Returns the number of users anonymised.
func (r *GDPRRetentionRepository) AnonymizeInactiveUsers(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users u
		SET
		    email         = 'anon-' || u.id::text || '@gdpr.deleted',
		    first_name    = NULL,
		    last_name     = NULL,
		    avatar_url    = NULL,
		    password_hash = NULL,
		    metadata      = '{}',
		    is_active     = false,
		    updated_at    = now()
		FROM org_gdpr_retention p
		WHERE u.org_id = p.org_id
		  AND p.enabled = true
		  AND u.is_active = true
		  AND u.email NOT LIKE 'anon-%@gdpr.deleted'
		  AND (
		      (p.activity_field = 'last_login_at'
		       AND (u.last_login_at IS NULL
		            OR u.last_login_at < now() - (p.retention_days || ' days')::interval))
		   OR (p.activity_field = 'updated_at'
		       AND u.updated_at < now() - (p.retention_days || ' days')::interval)
		  )
		  AND NOT EXISTS (
		      SELECT 1
		      FROM user_roles ur
		      JOIN roles ro ON ro.id = ur.role_id
		      WHERE ur.user_id = u.id
		        AND ro.org_id = u.org_id
		        AND ro.name = ANY(p.exempt_role_names)
		  )
	`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
