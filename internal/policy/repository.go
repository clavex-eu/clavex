package policy

import (
	"context"
	"encoding/json"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PolicyRow is a single row from org_auth_policies.
type PolicyRow struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	Name       string
	Priority   int
	Enabled    bool
	Action     Action
	Conditions Conditions
	CreatedAt  time.Time
	UpdatedAt  time.Time
	// Declarative-management marker (migration 000179). Nil when hand-managed.
	ManagedBy  *string `json:"managed_by,omitempty"`
	ManagedRef *string `json:"managed_ref,omitempty"`
}

// SetManagedMarker adopts, refreshes, or releases the declarative-management
// marker on an auth-policy rule. See repository.ApplyManagedMarker.
func (r *Repository) SetManagedMarker(ctx context.Context, id, orgID uuid.UUID, m repository.ManagedMarkerInput) error {
	return repository.ApplyManagedMarker(ctx, r.pool, "org_auth_policies", "id", id, orgID, m)
}

// Repository loads and persists per-org policy rules.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository creates a Repository backed by the given pool.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// LoadPolicy returns the Policy for the given org, combining DB rows with
// the supplied default rules.  DB rows take precedence over defaults.
// If there are no DB rows and no defaults, returns an empty (allow-all) policy.
func (r *Repository) LoadPolicy(ctx context.Context, orgID uuid.UUID, defaults []Rule) (*Policy, error) {
	rows, err := r.List(ctx, orgID)
	if err != nil {
		return nil, err
	}
	// If the org has no custom rules, fall back to the global defaults.
	rules := make([]Rule, 0, len(rows)+len(defaults))
	if len(rows) > 0 {
		for _, row := range rows {
			rules = append(rules, Rule{
				Name:       row.Name,
				Priority:   row.Priority,
				Enabled:    row.Enabled,
				Action:     row.Action,
				Conditions: row.Conditions,
			})
		}
	} else {
		rules = append(rules, defaults...)
	}
	return &Policy{Rules: rules}, nil
}

// List returns all policy rules for an org, ordered by priority.
func (r *Repository) List(ctx context.Context, orgID uuid.UUID) ([]*PolicyRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, name, priority, enabled, action, conditions, created_at, updated_at, managed_by, managed_ref
		FROM org_auth_policies
		WHERE org_id = $1
		ORDER BY priority ASC, created_at ASC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*PolicyRow
	for rows.Next() {
		row := &PolicyRow{}
		var condJSON []byte
		if err := rows.Scan(
			&row.ID, &row.OrgID, &row.Name, &row.Priority,
			&row.Enabled, &row.Action, &condJSON,
			&row.CreatedAt, &row.UpdatedAt, &row.ManagedBy, &row.ManagedRef,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(condJSON, &row.Conditions); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// Create inserts a new policy rule and returns the created row.
// An entity event (policy.upserted) is written atomically in the same transaction.
func (r *Repository) Create(ctx context.Context, orgID uuid.UUID, name string, priority int, action Action, cond Conditions) (*PolicyRow, error) {
	condJSON, err := json.Marshal(cond)
	if err != nil {
		return nil, err
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row := &PolicyRow{}
	var condBytes []byte
	if err := tx.QueryRow(ctx, `
		INSERT INTO org_auth_policies (org_id, name, priority, action, conditions)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, org_id, name, priority, enabled, action, conditions, created_at, updated_at, managed_by, managed_ref
	`, orgID, name, priority, string(action), condJSON).Scan(
		&row.ID, &row.OrgID, &row.Name, &row.Priority,
		&row.Enabled, &row.Action, &condBytes,
		&row.CreatedAt, &row.UpdatedAt, &row.ManagedBy, &row.ManagedRef,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(condBytes, &row.Conditions)

	evRepo := repository.NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, repository.AppendParams{
		OrgID:      orgID,
		EntityType: "policy",
		EntityID:   row.ID.String(),
		EventType:  "policy.upserted",
		Payload:    map[string]any{"name": name, "priority": priority, "action": string(action)},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	return row, tx.Commit(ctx)
}

// Update modifies an existing policy rule.
// An entity event (policy.upserted) is written atomically in the same transaction.
// Update mutates a policy rule, scoped to orgID so a cross-tenant rule_id cannot
// be modified; a mismatch yields pgx.ErrNoRows.
func (r *Repository) Update(ctx context.Context, id, orgID uuid.UUID, name string, priority int, enabled bool, action Action, cond Conditions) (*PolicyRow, error) {
	condJSON, err := json.Marshal(cond)
	if err != nil {
		return nil, err
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row := &PolicyRow{}
	var condBytes []byte
	if err := tx.QueryRow(ctx, `
		UPDATE org_auth_policies
		SET name=$2, priority=$3, enabled=$4, action=$5, conditions=$6, updated_at=NOW()
		WHERE id=$1 AND org_id=$7
		RETURNING id, org_id, name, priority, enabled, action, conditions, created_at, updated_at, managed_by, managed_ref
	`, id, name, priority, enabled, string(action), condJSON, orgID).Scan(
		&row.ID, &row.OrgID, &row.Name, &row.Priority,
		&row.Enabled, &row.Action, &condBytes,
		&row.CreatedAt, &row.UpdatedAt, &row.ManagedBy, &row.ManagedRef,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(condBytes, &row.Conditions)

	evRepo := repository.NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, repository.AppendParams{
		OrgID:      row.OrgID,
		EntityType: "policy",
		EntityID:   row.ID.String(),
		EventType:  "policy.upserted",
		Payload:    map[string]any{"name": name, "priority": priority, "enabled": enabled, "action": string(action)},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	return row, tx.Commit(ctx)
}

// Delete removes a policy rule by ID.
// An entity event (policy.deleted) is written atomically in the same transaction.
func (r *Repository) Delete(ctx context.Context, id, wantOrgID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Scope the delete to the owning org so a cross-tenant rule_id cannot be
	// removed; no row → pgx.ErrNoRows.
	var orgID uuid.UUID
	if err = tx.QueryRow(ctx,
		`DELETE FROM org_auth_policies WHERE id=$1 AND org_id=$2 RETURNING org_id`, id, wantOrgID,
	).Scan(&orgID); err != nil {
		return err
	}

	evRepo := repository.NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, repository.AppendParams{
		OrgID:      orgID,
		EntityType: "policy",
		EntityID:   id.String(),
		EventType:  "policy.deleted",
		Payload:    map[string]any{"deleted": true},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
