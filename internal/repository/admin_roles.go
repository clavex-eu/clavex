package repository

import (
	"context"
	"errors"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AdminRoleRepository manages delegated admin roles and their assignments.
type AdminRoleRepository struct {
	pool *pgxpool.Pool
}

// NewAdminRoleRepository creates a new AdminRoleRepository.
func NewAdminRoleRepository(pool *pgxpool.Pool) *AdminRoleRepository {
	return &AdminRoleRepository{pool: pool}
}

// ── Role CRUD ─────────────────────────────────────────────────────────────────

// Create inserts a new admin role and returns the created record.
// An entity event (admin.role_created) is written atomically in the same transaction.
func (r *AdminRoleRepository) Create(ctx context.Context, orgID uuid.UUID, name string, description *string, permissions []string, createdBy *uuid.UUID) (*models.AdminRole, error) {
	if permissions == nil {
		permissions = []string{}
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	role := &models.AdminRole{}
	if err = tx.QueryRow(ctx, `
		INSERT INTO admin_roles (org_id, name, description, permissions, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, org_id, name, description, permissions, is_system, created_by, created_at, updated_at
	`, orgID, name, description, permissions, createdBy).Scan(
		&role.ID, &role.OrgID, &role.Name, &role.Description,
		&role.Permissions, &role.IsSystem, &role.CreatedBy, &role.CreatedAt, &role.UpdatedAt,
	); err != nil {
		return nil, err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "admin_role",
		EntityID:   role.ID.String(),
		EventType:  "admin.role_created",
		Payload:    map[string]any{"name": name, "permissions": permissions},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return role, nil
}

// List returns all admin roles for an org.
func (r *AdminRoleRepository) List(ctx context.Context, orgID uuid.UUID) ([]*models.AdminRole, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, name, description, permissions, is_system, created_by, created_at, updated_at
		FROM admin_roles
		WHERE org_id = $1
		ORDER BY name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*models.AdminRole
	for rows.Next() {
		role := &models.AdminRole{}
		if err := rows.Scan(
			&role.ID, &role.OrgID, &role.Name, &role.Description,
			&role.Permissions, &role.IsSystem, &role.CreatedBy, &role.CreatedAt, &role.UpdatedAt,
		); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// GetByID returns a single admin role, scoped to orgID.
func (r *AdminRoleRepository) GetByID(ctx context.Context, orgID, roleID uuid.UUID) (*models.AdminRole, error) {
	role := &models.AdminRole{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, name, description, permissions, is_system, created_by, created_at, updated_at
		FROM admin_roles
		WHERE id = $1 AND org_id = $2
	`, roleID, orgID).Scan(
		&role.ID, &role.OrgID, &role.Name, &role.Description,
		&role.Permissions, &role.IsSystem, &role.CreatedBy, &role.CreatedAt, &role.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return role, nil
}

// Update patches name, description, and permissions on an existing admin role.
// System roles (is_system=true) may have permissions updated but not renamed.
// An entity event (admin.role_permissions_changed) is written atomically in the same transaction.
func (r *AdminRoleRepository) Update(ctx context.Context, orgID, roleID uuid.UUID, name string, description *string, permissions []string) (*models.AdminRole, error) {
	if permissions == nil {
		permissions = []string{}
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	role := &models.AdminRole{}
	if err = tx.QueryRow(ctx, `
		UPDATE admin_roles
		SET name        = CASE WHEN is_system THEN name ELSE $3 END,
		    description = $4,
		    permissions = $5,
		    updated_at  = NOW()
		WHERE id = $1 AND org_id = $2
		RETURNING id, org_id, name, description, permissions, is_system, created_by, created_at, updated_at
	`, roleID, orgID, name, description, permissions).Scan(
		&role.ID, &role.OrgID, &role.Name, &role.Description,
		&role.Permissions, &role.IsSystem, &role.CreatedBy, &role.CreatedAt, &role.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "admin_role",
		EntityID:   roleID.String(),
		EventType:  "admin.role_permissions_changed",
		Payload:    map[string]any{"name": name, "permissions": permissions},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	return role, tx.Commit(ctx)
}

// Delete removes an admin role. Returns an error if the role is a system role.
// An entity event (admin.role_deleted) is written atomically in the same transaction.
func (r *AdminRoleRepository) Delete(ctx context.Context, orgID, roleID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		DELETE FROM admin_roles
		WHERE id = $1 AND org_id = $2 AND is_system = FALSE
	`, roleID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows // not found or is_system
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "admin_role",
		EntityID:   roleID.String(),
		EventType:  "admin.role_deleted",
		Payload:    map[string]any{"deleted": true},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ── Assignment CRUD ───────────────────────────────────────────────────────────

// Assign grants an admin role to a user within an org.
// An entity event (admin.role_assigned) is written atomically in the same transaction.
func (r *AdminRoleRepository) Assign(ctx context.Context, orgID, userID, roleID uuid.UUID, createdBy *uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO admin_role_assignments (org_id, user_id, role_id, created_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, orgID, userID, roleID, createdBy)
	if err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "user",
		EntityID:   userID.String(),
		EventType:  "admin.role_assigned",
		Payload:    map[string]any{"role_id": roleID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Unassign removes an admin role from a user.
// An entity event (admin.role_revoked) is written atomically in the same transaction.
func (r *AdminRoleRepository) Unassign(ctx context.Context, orgID, userID, roleID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		DELETE FROM admin_role_assignments
		WHERE org_id = $1 AND user_id = $2 AND role_id = $3
	`, orgID, userID, roleID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "user",
		EntityID:   userID.String(),
		EventType:  "admin.role_revoked",
		Payload:    map[string]any{"role_id": roleID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListByUser returns all admin role assignments for a user within an org.
func (r *AdminRoleRepository) ListByUser(ctx context.Context, orgID, userID uuid.UUID) ([]*models.AdminRoleAssignment, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT ara.id, ara.org_id, ara.user_id, ara.role_id, ar.name AS role_name,
		       ara.created_by, ara.created_at
		FROM admin_role_assignments ara
		JOIN admin_roles ar ON ar.id = ara.role_id
		WHERE ara.org_id = $1 AND ara.user_id = $2
		ORDER BY ar.name
	`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assignments []*models.AdminRoleAssignment
	for rows.Next() {
		a := &models.AdminRoleAssignment{}
		if err := rows.Scan(
			&a.ID, &a.OrgID, &a.UserID, &a.RoleID, &a.RoleName,
			&a.CreatedBy, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		assignments = append(assignments, a)
	}
	return assignments, rows.Err()
}

// ── Permission resolution ─────────────────────────────────────────────────────

// GetPermissionsForUser returns the union of all permissions from admin roles
// assigned to the user within the given org.
//
// Returns (nil, nil) when the user has no admin role assignments — this signals
// the caller that the user is a legacy full-access org admin. Returns
// ([]string{}, nil) when the user has assignments but all roles have empty
// permission sets (no access to anything beyond what RequireAdminJWT already grants).
func (r *AdminRoleRepository) GetPermissionsForUser(ctx context.Context, userID, orgID uuid.UUID) ([]string, error) {
	// First check whether any assignments exist at all.
	var count int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM admin_role_assignments
		WHERE user_id = $1 AND org_id = $2
	`, userID, orgID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil // no delegated roles → legacy full-access
	}

	// Collect the distinct union of permissions across all assigned roles.
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT UNNEST(ar.permissions) AS perm
		FROM admin_role_assignments ara
		JOIN admin_roles ar ON ar.id = ara.role_id
		WHERE ara.user_id = $1 AND ara.org_id = $2
		ORDER BY 1
	`, userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	if perms == nil {
		perms = []string{} // assignments exist but roles have empty permission sets
	}
	return perms, rows.Err()
}

// EnsureSystemRoles upserts the built-in system roles for an org.
// Call this when a new org is created or when running migrations that add new
// built-in roles.  Uses ON CONFLICT DO UPDATE to keep permissions in sync.
func (r *AdminRoleRepository) EnsureSystemRoles(ctx context.Context, orgID uuid.UUID) error {
	type systemRole struct {
		name        string
		description string
		permissions []string
	}
	roles := []systemRole{
		{
			name:        "user_admin",
			description: "Can manage users, groups, roles, invitations, and user sessions.",
			permissions: []string{
				"users:read", "users:write",
				"roles:read", "roles:write",
				"groups:read", "groups:write",
				"sessions:read", "sessions:write",
			},
		},
		{
			name:        "security_admin",
			description: "Can manage security policies, MFA, IdPs, and audit logs.",
			permissions: []string{
				"security:read", "security:write",
				"identity_providers:read", "identity_providers:write",
				"audit:read",
			},
		},
		{
			name:        "audit_viewer",
			description: "Read-only access to audit logs and compliance reports.",
			permissions: []string{
				"audit:read",
				"compliance:read",
				"sessions:read",
			},
		},
		{
			name:        "readonly",
			description: "Read-only access to all org resources.",
			permissions: allReadPermissions(),
		},
	}

	for _, sr := range roles {
		desc := sr.description
		_, err := r.pool.Exec(ctx, `
			INSERT INTO admin_roles (org_id, name, description, permissions, is_system)
			VALUES ($1, $2, $3, $4, TRUE)
			ON CONFLICT (org_id, name) DO UPDATE
			    SET description = EXCLUDED.description,
			        permissions = EXCLUDED.permissions,
			        is_system   = TRUE,
			        updated_at  = NOW()
		`, orgID, sr.name, desc, sr.permissions)
		if err != nil {
			return err
		}
	}
	return nil
}

// allReadPermissions returns the set of :read tokens for every resource.
func allReadPermissions() []string {
	return []string{
		"audit:read",
		"branding:read",
		"clients:read",
		"compliance:read",
		"delegated_admins:read",
		"groups:read",
		"identity_providers:read",
		"roles:read",
		"security:read",
		"sessions:read",
		"smtp:read",
		"users:read",
		"webhooks:read",
	}
}

// LastAssignmentTime returns the most recent created_at for any admin role
// assignment in an org. Used to invalidate cached permission sets.
func (r *AdminRoleRepository) LastAssignmentTime(ctx context.Context, orgID uuid.UUID) (time.Time, error) {
	var t time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(created_at), '1970-01-01') FROM admin_role_assignments WHERE org_id = $1
	`, orgID).Scan(&t)
	return t, err
}
