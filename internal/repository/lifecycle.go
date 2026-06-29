package repository

import (
	"context"
	"encoding/json"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LifecycleRepository provides CRUD access to identity.lifecycle_rules.
type LifecycleRepository struct {
	pool *pgxpool.Pool
}

func NewLifecycleRepository(pool *pgxpool.Pool) *LifecycleRepository {
	return &LifecycleRepository{pool: pool}
}

const lifecycleColumns = `id, org_id, name, description, trigger, priority, conditions, actions, is_active, created_at, updated_at`

func (r *LifecycleRepository) scanRule(row interface{ Scan(...interface{}) error }) (*models.LifecycleRule, error) {
	var rule models.LifecycleRule
	var condJSON, actJSON []byte
	err := row.Scan(
		&rule.ID, &rule.OrgID, &rule.Name, &rule.Description,
		&rule.Trigger, &rule.Priority,
		&condJSON, &actJSON,
		&rule.IsActive, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(condJSON, &rule.Conditions); err != nil {
		rule.Conditions = nil
	}
	if err := json.Unmarshal(actJSON, &rule.Actions); err != nil {
		rule.Actions = nil
	}
	return &rule, nil
}

// ListByOrg returns all active rules for an org, ordered by trigger then priority.
func (r *LifecycleRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.LifecycleRule, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+lifecycleColumns+`
		 FROM identity.lifecycle_rules
		 WHERE org_id = $1
		 ORDER BY trigger, priority, created_at`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []*models.LifecycleRule
	for rows.Next() {
		rule, err := r.scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ListActiveByTrigger returns active rules for a specific trigger, ordered by priority.
func (r *LifecycleRepository) ListActiveByTrigger(ctx context.Context, orgID uuid.UUID, trigger models.LifecycleTrigger) ([]*models.LifecycleRule, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+lifecycleColumns+`
		 FROM identity.lifecycle_rules
		 WHERE org_id = $1 AND trigger = $2 AND is_active = TRUE
		 ORDER BY priority, created_at`,
		orgID, string(trigger),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []*models.LifecycleRule
	for rows.Next() {
		rule, err := r.scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// GetByID returns a single lifecycle rule (any org — caller must check org ownership).
func (r *LifecycleRepository) GetByID(ctx context.Context, orgID, id uuid.UUID) (*models.LifecycleRule, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+lifecycleColumns+`
		 FROM identity.lifecycle_rules
		 WHERE id = $1 AND org_id = $2`,
		id, orgID,
	)
	return r.scanRule(row)
}

// CreateParams holds data for creating a new lifecycle rule.
type CreateLifecycleRuleParams struct {
	OrgID       uuid.UUID
	Name        string
	Description *string
	Trigger     models.LifecycleTrigger
	Priority    int
	Conditions  []models.LifecycleCondition
	Actions     []models.LifecycleAction
	IsActive    bool
}

func (r *LifecycleRepository) Create(ctx context.Context, p CreateLifecycleRuleParams) (*models.LifecycleRule, error) {
	condJSON, err := json.Marshal(p.Conditions)
	if err != nil {
		return nil, err
	}
	actJSON, err := json.Marshal(p.Actions)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx,
		`INSERT INTO identity.lifecycle_rules
		   (org_id, name, description, trigger, priority, conditions, actions, is_active)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 RETURNING `+lifecycleColumns,
		p.OrgID, p.Name, p.Description, string(p.Trigger), p.Priority,
		condJSON, actJSON, p.IsActive,
	)
	return r.scanRule(row)
}

// UpdateLifecycleRuleParams holds data for updating a lifecycle rule.
type UpdateLifecycleRuleParams struct {
	OrgID       uuid.UUID
	ID          uuid.UUID
	Name        string
	Description *string
	Trigger     models.LifecycleTrigger
	Priority    int
	Conditions  []models.LifecycleCondition
	Actions     []models.LifecycleAction
	IsActive    bool
}

func (r *LifecycleRepository) Update(ctx context.Context, p UpdateLifecycleRuleParams) (*models.LifecycleRule, error) {
	condJSON, err := json.Marshal(p.Conditions)
	if err != nil {
		return nil, err
	}
	actJSON, err := json.Marshal(p.Actions)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx,
		`UPDATE identity.lifecycle_rules
		 SET name=$3, description=$4, trigger=$5, priority=$6,
		     conditions=$7, actions=$8, is_active=$9, updated_at=NOW()
		 WHERE id=$1 AND org_id=$2
		 RETURNING `+lifecycleColumns,
		p.ID, p.OrgID, p.Name, p.Description, string(p.Trigger), p.Priority,
		condJSON, actJSON, p.IsActive,
	)
	return r.scanRule(row)
}

func (r *LifecycleRepository) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM identity.lifecycle_rules WHERE id=$1 AND org_id=$2`,
		id, orgID,
	)
	return err
}
