package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PasswordPolicyRepository manages per-org password complexity rules.
type PasswordPolicyRepository struct {
	pool *pgxpool.Pool
}

func NewPasswordPolicyRepository(pool *pgxpool.Pool) *PasswordPolicyRepository {
	return &PasswordPolicyRepository{pool: pool}
}

// Get returns the password policy for an org, or a default policy if none has been configured.
func (r *PasswordPolicyRepository) Get(ctx context.Context, orgID uuid.UUID) (*models.PasswordPolicy, error) {
	p := &models.PasswordPolicy{}
	err := r.pool.QueryRow(ctx, `
		SELECT org_id, min_length, require_uppercase, require_number, require_symbol,
		       max_age_days, prevent_reuse_count, breached_password_action, updated_at
		FROM org_password_policy WHERE org_id = $1
	`, orgID).Scan(
		&p.OrgID, &p.MinLength, &p.RequireUppercase, &p.RequireNumber, &p.RequireSymbol,
		&p.MaxAgeDays, &p.PreventReuseCount, &p.BreachedPasswordAction, &p.UpdatedAt,
	)
	if err != nil {
		return &models.PasswordPolicy{
			OrgID:     orgID,
			MinLength: 8,
		}, nil
	}
	return p, nil
}

// Upsert creates or replaces the password policy for an org.
// An entity event (policy.password_changed) is written atomically in the same transaction.
func (r *PasswordPolicyRepository) Upsert(ctx context.Context, p *models.PasswordPolicy) (*models.PasswordPolicy, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	out := &models.PasswordPolicy{}
	if err = tx.QueryRow(ctx, `
		INSERT INTO org_password_policy
			(org_id, min_length, require_uppercase, require_number, require_symbol,
			 max_age_days, prevent_reuse_count, breached_password_action, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
		ON CONFLICT (org_id) DO UPDATE SET
			min_length               = EXCLUDED.min_length,
			require_uppercase        = EXCLUDED.require_uppercase,
			require_number           = EXCLUDED.require_number,
			require_symbol           = EXCLUDED.require_symbol,
			max_age_days             = EXCLUDED.max_age_days,
			prevent_reuse_count      = EXCLUDED.prevent_reuse_count,
			breached_password_action = EXCLUDED.breached_password_action,
			updated_at               = NOW()
		RETURNING org_id, min_length, require_uppercase, require_number, require_symbol,
		          max_age_days, prevent_reuse_count, breached_password_action, updated_at
	`, p.OrgID, p.MinLength, p.RequireUppercase, p.RequireNumber, p.RequireSymbol,
		p.MaxAgeDays, p.PreventReuseCount, p.BreachedPasswordAction,
	).Scan(
		&out.OrgID, &out.MinLength, &out.RequireUppercase, &out.RequireNumber, &out.RequireSymbol,
		&out.MaxAgeDays, &out.PreventReuseCount, &out.BreachedPasswordAction, &out.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("upsert password policy: %w", err)
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      p.OrgID,
		EntityType: "policy",
		EntityID:   p.OrgID.String(),
		EventType:  "policy.password_changed",
		Payload: map[string]any{
			"min_length":               p.MinLength,
			"require_uppercase":        p.RequireUppercase,
			"require_number":           p.RequireNumber,
			"require_symbol":           p.RequireSymbol,
			"max_age_days":             p.MaxAgeDays,
			"prevent_reuse_count":      p.PreventReuseCount,
			"breached_password_action": p.BreachedPasswordAction,
		},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	return out, tx.Commit(ctx)
}
