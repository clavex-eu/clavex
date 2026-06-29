package repository

import (
	"context"
	"encoding/json"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ActionsRepository provides CRUD access to action_targets and action_executions.
type ActionsRepository struct {
	pool *pgxpool.Pool
}

func NewActionsRepository(pool *pgxpool.Pool) *ActionsRepository {
	return &ActionsRepository{pool: pool}
}

// ── Targets ───────────────────────────────────────────────────────────────────

const targetCols = `id, org_id, name, target_type, url, sandbox_code, timeout_ms, signing_secret, is_active, created_at, updated_at`

func (r *ActionsRepository) scanTarget(row interface{ Scan(...any) error }) (*models.ActionTarget, error) {
	var t models.ActionTarget
	err := row.Scan(&t.ID, &t.OrgID, &t.Name, &t.TargetType, &t.URL, &t.SandboxCode, &t.TimeoutMs, &t.SigningSecret, &t.IsActive, &t.CreatedAt, &t.UpdatedAt)
	return &t, err
}

func (r *ActionsRepository) ListTargets(ctx context.Context, orgID uuid.UUID) ([]*models.ActionTarget, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+targetCols+` FROM action_targets WHERE org_id=$1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.ActionTarget
	for rows.Next() {
		t, err := r.scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *ActionsRepository) GetTarget(ctx context.Context, orgID, id uuid.UUID) (*models.ActionTarget, error) {
	return r.scanTarget(r.pool.QueryRow(ctx,
		`SELECT `+targetCols+` FROM action_targets WHERE id=$1 AND org_id=$2`, id, orgID))
}

type UpsertTargetParams struct {
	OrgID         uuid.UUID
	Name          string
	TargetType    string   // "http" | "sandbox"
	URL           string
	SandboxCode   *string
	TimeoutMs     int
	SigningSecret *string
	IsActive      bool
}

func (r *ActionsRepository) UpsertTarget(ctx context.Context, p UpsertTargetParams) (*models.ActionTarget, error) {
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 3000
	}
	if p.TargetType == "" {
		p.TargetType = "http"
	}
	return r.scanTarget(r.pool.QueryRow(ctx,
		`INSERT INTO action_targets (org_id, name, target_type, url, sandbox_code, timeout_ms, signing_secret, is_active)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (org_id, name) DO UPDATE
		   SET target_type=$3, url=$4, sandbox_code=$5, timeout_ms=$6,
		       signing_secret = CASE WHEN $7::text IS NULL THEN action_targets.signing_secret ELSE $7 END,
		       is_active=$8, updated_at=NOW()
		 RETURNING `+targetCols,
		p.OrgID, p.Name, p.TargetType, p.URL, p.SandboxCode, p.TimeoutMs, p.SigningSecret, p.IsActive,
	))
}

func (r *ActionsRepository) DeleteTarget(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM action_targets WHERE id=$1 AND org_id=$2`, id, orgID)
	return err
}

// ── Executions ────────────────────────────────────────────────────────────────

const execCols = `e.id, e.org_id, e.target_id, e.name, e.event_type, e.condition, e.mode, e.is_active,
	e.created_at, e.updated_at, COALESCE(t.name,'') AS target_name, COALESCE(t.url,'') AS target_url`

const execJoin = ` FROM action_executions e LEFT JOIN action_targets t ON t.id = e.target_id `

func (r *ActionsRepository) scanExec(row interface{ Scan(...any) error }) (*models.ActionExecution, error) {
	var e models.ActionExecution
	var condJSON []byte
	err := row.Scan(&e.ID, &e.OrgID, &e.TargetID, &e.Name, &e.EventType, &condJSON,
		&e.Mode, &e.IsActive, &e.CreatedAt, &e.UpdatedAt, &e.TargetName, &e.TargetURL)
	if err != nil {
		return nil, err
	}
	if len(condJSON) > 0 {
		e.Condition = condJSON
	} else {
		e.Condition = json.RawMessage("{}")
	}
	return &e, nil
}

func (r *ActionsRepository) ListExecutions(ctx context.Context, orgID uuid.UUID) ([]*models.ActionExecution, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+execCols+execJoin+`WHERE e.org_id=$1 ORDER BY e.event_type, e.name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.ActionExecution
	for rows.Next() {
		ex, err := r.scanExec(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ex)
	}
	return out, rows.Err()
}

func (r *ActionsRepository) GetExecution(ctx context.Context, orgID, id uuid.UUID) (*models.ActionExecution, error) {
	return r.scanExec(r.pool.QueryRow(ctx,
		`SELECT `+execCols+execJoin+`WHERE e.id=$1 AND e.org_id=$2`, id, orgID))
}

// ListActiveByOrgAndEvent returns all active executions for a given org and event type,
// including the target URL and signing secret.
func (r *ActionsRepository) ListActiveByOrgAndEvent(ctx context.Context, orgID uuid.UUID, eventType string) ([]*models.ActionExecution, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+execCols+execJoin+`WHERE e.org_id=$1 AND e.event_type=$2 AND e.is_active=TRUE AND t.is_active=TRUE
		 ORDER BY e.created_at ASC`, orgID, eventType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.ActionExecution
	for rows.Next() {
		ex, err := r.scanExec(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ex)
	}
	return out, rows.Err()
}

type UpsertExecutionParams struct {
	OrgID     uuid.UUID
	TargetID  uuid.UUID
	Name      string
	EventType string
	Condition json.RawMessage
	// Mode: "fire_and_forget" (default) or "mutation".
	Mode     string
	IsActive bool
}

func (r *ActionsRepository) CreateExecution(ctx context.Context, p UpsertExecutionParams) (*models.ActionExecution, error) {
	cond := p.Condition
	if len(cond) == 0 {
		cond = json.RawMessage("{}")
	}
	if p.Mode == "" {
		p.Mode = "fire_and_forget"
	}
	return r.scanExec(r.pool.QueryRow(ctx,
		`INSERT INTO action_executions (org_id, target_id, name, event_type, condition, mode, is_active)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING `+execCols+execJoin+`WHERE e.id = (SELECT lastval())`,
		p.OrgID, p.TargetID, p.Name, p.EventType, cond, p.Mode, p.IsActive,
	))
}

func (r *ActionsRepository) UpdateExecution(ctx context.Context, orgID, id uuid.UUID, p UpsertExecutionParams) (*models.ActionExecution, error) {
	cond := p.Condition
	if len(cond) == 0 {
		cond = json.RawMessage("{}")
	}
	if p.Mode == "" {
		p.Mode = "fire_and_forget"
	}
	return r.scanExec(r.pool.QueryRow(ctx,
		`UPDATE action_executions
		 SET target_id=$3, name=$4, event_type=$5, condition=$6, mode=$7, is_active=$8, updated_at=NOW()
		 WHERE id=$1 AND org_id=$2
		 RETURNING `+execCols+execJoin+`WHERE e.id=$1`,
		id, orgID, p.TargetID, p.Name, p.EventType, cond, p.Mode, p.IsActive,
	))
}

func (r *ActionsRepository) DeleteExecution(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM action_executions WHERE id=$1 AND org_id=$2`, id, orgID)
	return err
}
