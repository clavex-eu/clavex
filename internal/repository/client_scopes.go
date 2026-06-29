package repository

import (
	"context"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ClientScopeRepository handles persistence for reusable org-level client scopes.
type ClientScopeRepository struct {
	pool *pgxpool.Pool
}

func NewClientScopeRepository(pool *pgxpool.Pool) *ClientScopeRepository {
	return &ClientScopeRepository{pool: pool}
}

const scopeCols = `id, org_id, name, description, protocol, is_default, created_at, updated_at`

func scanScope(row pgx.Row) (*models.ClientScope, error) {
	s := &models.ClientScope{}
	return s, row.Scan(&s.ID, &s.OrgID, &s.Name, &s.Description, &s.Protocol, &s.IsDefault, &s.CreatedAt, &s.UpdatedAt)
}

// Create inserts a new client scope for the given org.
func (r *ClientScopeRepository) Create(ctx context.Context, orgID uuid.UUID, name string, description *string, protocol string, isDefault bool) (*models.ClientScope, error) {
	row := r.pool.QueryRow(ctx,
		`INSERT INTO client_scopes (org_id, name, description, protocol, is_default)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING `+scopeCols,
		orgID, name, description, protocol, isDefault,
	)
	return scanScope(row)
}

// ListByOrg returns all scopes for an org.
func (r *ClientScopeRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.ClientScope, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+scopeCols+` FROM client_scopes WHERE org_id = $1 ORDER BY name`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.ClientScope
	for rows.Next() {
		s := &models.ClientScope{}
		if err := rows.Scan(&s.ID, &s.OrgID, &s.Name, &s.Description, &s.Protocol, &s.IsDefault, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetByID returns a single scope.
func (r *ClientScopeRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ClientScope, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+scopeCols+` FROM client_scopes WHERE id = $1`, id)
	return scanScope(row)
}

// GetForOrg loads a scope only when it belongs to orgID (ErrNoRows otherwise).
func (r *ClientScopeRepository) GetForOrg(ctx context.Context, id, orgID uuid.UUID) (*models.ClientScope, error) {
	s, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.OrgID != orgID {
		return nil, pgx.ErrNoRows
	}
	return s, nil
}

// ClientInOrg reports whether the OIDC client belongs to orgID. Used to reject
// assigning/unassigning a scope to a cross-tenant client.
func (r *ClientScopeRepository) ClientInOrg(ctx context.Context, clientID string, orgID uuid.UUID) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oidc_clients WHERE client_id=$1 AND org_id=$2)`, clientID, orgID).Scan(&ok)
	return ok, err
}

// Update changes the mutable fields of a scope.
func (r *ClientScopeRepository) Update(ctx context.Context, id uuid.UUID, name string, description *string, isDefault bool) (*models.ClientScope, error) {
	row := r.pool.QueryRow(ctx,
		`UPDATE client_scopes SET name=$1, description=$2, is_default=$3, updated_at=NOW()
		 WHERE id=$4 RETURNING `+scopeCols,
		name, description, isDefault, id,
	)
	return scanScope(row)
}

// Delete removes a scope (cascade also removes assignments).
func (r *ClientScopeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM client_scopes WHERE id = $1`, id)
	return err
}

// AssignToClient adds a scope to a client.
func (r *ClientScopeRepository) AssignToClient(ctx context.Context, clientID string, scopeID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO client_scope_assignments (client_id, scope_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		clientID, scopeID,
	)
	return err
}

// UnassignFromClient removes a scope from a client.
func (r *ClientScopeRepository) UnassignFromClient(ctx context.Context, clientID string, scopeID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM client_scope_assignments WHERE client_id=$1 AND scope_id=$2`,
		clientID, scopeID,
	)
	return err
}

// ListByClient returns all scopes assigned to a client.
func (r *ClientScopeRepository) ListByClient(ctx context.Context, clientID string) ([]*models.ClientScope, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+scopeCols+`
		 FROM client_scopes cs
		 JOIN client_scope_assignments csa ON csa.scope_id = cs.id
		 WHERE csa.client_id = $1
		 ORDER BY cs.name`,
		clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.ClientScope
	for rows.Next() {
		s := &models.ClientScope{}
		if err := rows.Scan(&s.ID, &s.OrgID, &s.Name, &s.Description, &s.Protocol, &s.IsDefault, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
