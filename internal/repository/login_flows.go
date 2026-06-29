package repository

import (
	"context"
	"encoding/json"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LoginFlowRepository manages login flow definitions and their steps.
type LoginFlowRepository struct {
	pool *pgxpool.Pool
}

func NewLoginFlowRepository(pool *pgxpool.Pool) *LoginFlowRepository {
	return &LoginFlowRepository{pool: pool}
}

// ── Flows ─────────────────────────────────────────────────────────────────────

const flowCols = `id, org_id, name, description, is_default, is_active, created_at, updated_at`

func (r *LoginFlowRepository) scanFlow(row interface{ Scan(...interface{}) error }) (*models.LoginFlow, error) {
	f := &models.LoginFlow{}
	return f, row.Scan(&f.ID, &f.OrgID, &f.Name, &f.Description, &f.IsDefault, &f.IsActive, &f.CreatedAt, &f.UpdatedAt)
}

func (r *LoginFlowRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.LoginFlow, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+flowCols+` FROM identity.login_flows WHERE org_id = $1 ORDER BY is_default DESC, name`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var flows []*models.LoginFlow
	for rows.Next() {
		f, err := r.scanFlow(rows)
		if err != nil {
			return nil, err
		}
		flows = append(flows, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, f := range flows {
		steps, _ := r.ListSteps(ctx, f.ID)
		f.Steps = stepsOrEmpty(steps)
	}
	return flows, nil
}

func (r *LoginFlowRepository) GetByID(ctx context.Context, orgID, id uuid.UUID) (*models.LoginFlow, error) {
	f, err := r.scanFlow(r.pool.QueryRow(ctx,
		`SELECT `+flowCols+` FROM identity.login_flows WHERE id = $1 AND org_id = $2`,
		id, orgID,
	))
	if err != nil {
		return nil, err
	}
	steps, _ := r.ListSteps(ctx, f.ID)
	f.Steps = stepsOrEmpty(steps)
	return f, nil
}

// GetActiveForClient returns the flow to use for a given client login.
// Priority: client-specific assignment > org default.
// Returns nil (no flow) if neither exists.
func (r *LoginFlowRepository) GetActiveForClient(ctx context.Context, orgID uuid.UUID, clientID string) (*models.LoginFlow, error) {
	// 1. Try client-specific assignment
	var flowID uuid.UUID
	err := r.pool.QueryRow(ctx,
		`SELECT a.flow_id FROM identity.login_flow_client_assignments a
		 JOIN identity.login_flows f ON f.id = a.flow_id
		 WHERE a.client_id = $1 AND a.org_id = $2 AND f.is_active = TRUE`,
		clientID, orgID,
	).Scan(&flowID)
	if err != nil {
		// 2. Fall back to org default
		err = r.pool.QueryRow(ctx,
			`SELECT id FROM identity.login_flows WHERE org_id = $1 AND is_default = TRUE AND is_active = TRUE`,
			orgID,
		).Scan(&flowID)
		if err != nil {
			return nil, nil // No flow configured — nothing to run
		}
	}
	return r.GetByID(ctx, orgID, flowID)
}

type CreateFlowParams struct {
	OrgID       uuid.UUID
	Name        string
	Description *string
	IsDefault   bool
}

func (r *LoginFlowRepository) Create(ctx context.Context, p CreateFlowParams) (*models.LoginFlow, error) {
	// If marking as default, clear any existing default first.
	if p.IsDefault {
		_, _ = r.pool.Exec(ctx,
			`UPDATE identity.login_flows SET is_default = FALSE WHERE org_id = $1 AND is_default = TRUE`,
			p.OrgID,
		)
	}
	return r.scanFlow(r.pool.QueryRow(ctx,
		`INSERT INTO identity.login_flows (org_id, name, description, is_default)
		 VALUES ($1,$2,$3,$4)
		 RETURNING `+flowCols,
		p.OrgID, p.Name, p.Description, p.IsDefault,
	))
}

type UpdateFlowParams struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	Name        string
	Description *string
	IsDefault   bool
	IsActive    bool
}

func (r *LoginFlowRepository) Update(ctx context.Context, p UpdateFlowParams) (*models.LoginFlow, error) {
	if p.IsDefault {
		_, _ = r.pool.Exec(ctx,
			`UPDATE identity.login_flows SET is_default = FALSE WHERE org_id = $1 AND is_default = TRUE AND id <> $2`,
			p.OrgID, p.ID,
		)
	}
	return r.scanFlow(r.pool.QueryRow(ctx,
		`UPDATE identity.login_flows
		 SET name=$3, description=$4, is_default=$5, is_active=$6, updated_at=NOW()
		 WHERE id=$1 AND org_id=$2
		 RETURNING `+flowCols,
		p.ID, p.OrgID, p.Name, p.Description, p.IsDefault, p.IsActive,
	))
}

func (r *LoginFlowRepository) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM identity.login_flows WHERE id = $1 AND org_id = $2`,
		id, orgID,
	)
	return err
}

// ── Steps ─────────────────────────────────────────────────────────────────────

func (r *LoginFlowRepository) ListSteps(ctx context.Context, flowID uuid.UUID) ([]models.LoginFlowStep, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, flow_id, org_id, step_type, position, config, is_active, created_at, updated_at
		 FROM identity.login_flow_steps
		 WHERE flow_id = $1
		 ORDER BY position`,
		flowID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var steps []models.LoginFlowStep
	for rows.Next() {
		var s models.LoginFlowStep
		var cfg []byte
		if err := rows.Scan(&s.ID, &s.FlowID, &s.OrgID, &s.StepType, &s.Position, &cfg, &s.IsActive, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		if len(cfg) > 0 {
			s.Config = json.RawMessage(cfg)
		} else {
			s.Config = json.RawMessage("{}")
		}
		steps = append(steps, s)
	}
	return steps, rows.Err()
}

type UpsertStepsParams struct {
	FlowID uuid.UUID
	OrgID  uuid.UUID
	Steps  []StepInput
}

type StepInput struct {
	StepType string
	Position int
	Config   json.RawMessage
	IsActive bool
}

// ReplaceSteps deletes all existing steps for a flow and inserts the provided set.
// This is the simplest correct way to handle reordering + add/remove in one call.
func (r *LoginFlowRepository) ReplaceSteps(ctx context.Context, p UpsertStepsParams) ([]models.LoginFlowStep, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx,
		`DELETE FROM identity.login_flow_steps WHERE flow_id = $1`,
		p.FlowID,
	)
	if err != nil {
		return nil, err
	}

	var out []models.LoginFlowStep
	for _, si := range p.Steps {
		cfg := si.Config
		if len(cfg) == 0 {
			cfg = json.RawMessage("{}")
		}
		var s models.LoginFlowStep
		var cfgBytes []byte
		err := tx.QueryRow(ctx,
			`INSERT INTO identity.login_flow_steps (flow_id, org_id, step_type, position, config, is_active)
			 VALUES ($1,$2,$3,$4,$5,$6)
			 RETURNING id, flow_id, org_id, step_type, position, config, is_active, created_at, updated_at`,
			p.FlowID, p.OrgID, si.StepType, si.Position, cfg, si.IsActive,
		).Scan(&s.ID, &s.FlowID, &s.OrgID, &s.StepType, &s.Position, &cfgBytes, &s.IsActive, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, err
		}
		s.Config = json.RawMessage(cfgBytes)
		out = append(out, s)
	}

	return out, tx.Commit(ctx)
}

// ── Client assignments ────────────────────────────────────────────────────────

func (r *LoginFlowRepository) AssignClient(ctx context.Context, orgID uuid.UUID, flowID uuid.UUID, clientID string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO identity.login_flow_client_assignments (flow_id, client_id, org_id)
		 VALUES ($1,$2,$3)
		 ON CONFLICT (client_id, org_id) DO UPDATE SET flow_id = $1`,
		flowID, clientID, orgID,
	)
	return err
}

func (r *LoginFlowRepository) UnassignClient(ctx context.Context, orgID uuid.UUID, clientID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM identity.login_flow_client_assignments WHERE client_id = $1 AND org_id = $2`,
		clientID, orgID,
	)
	return err
}

func (r *LoginFlowRepository) ListClientAssignments(ctx context.Context, orgID, flowID uuid.UUID) ([]string, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT client_id FROM identity.login_flow_client_assignments WHERE flow_id = $1 AND org_id = $2`,
		flowID, orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func stepsOrEmpty(steps []models.LoginFlowStep) []models.LoginFlowStep {
	if steps == nil {
		return []models.LoginFlowStep{}
	}
	return steps
}
