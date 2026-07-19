package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GroupRepository handles group persistence.
type GroupRepository struct {
	pool *pgxpool.Pool
}

func NewGroupRepository(pool *pgxpool.Pool) *GroupRepository {
	return &GroupRepository{pool: pool}
}

// ListByOrg returns all groups for an org, including member count.
func (r *GroupRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.Group, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT g.id, g.org_id, g.name, g.description, g.is_system, g.created_at, g.updated_at,
		       g.managed_by, g.managed_ref,
		       COUNT(gm.user_id) AS member_count
		FROM groups g
		LEFT JOIN group_members gm ON gm.group_id = g.id
		WHERE g.org_id = $1
		GROUP BY g.id
		ORDER BY g.name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := make([]*models.Group, 0)
	for rows.Next() {
		g := &models.Group{}
		if err := rows.Scan(&g.ID, &g.OrgID, &g.Name, &g.Description, &g.IsSystem,
			&g.CreatedAt, &g.UpdatedAt, &g.ManagedBy, &g.ManagedRef, &g.MemberCount); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// ListByOrgPage returns a cursor-paginated slice of groups for an org.
func (r *GroupRepository) ListByOrgPage(ctx context.Context, orgID uuid.UUID, p models.PageParams) (*models.Page[*models.Group], error) {
	limit := p.Limit
	if limit <= 0 {
		limit = models.DefaultPageSize
	}
	if limit > models.MaxPageSize {
		limit = models.MaxPageSize
	}
	fetchLimit := limit + 1

	const cols = `g.id, g.org_id, g.name, g.description, g.is_system, g.created_at, g.updated_at, g.managed_by, g.managed_ref, COUNT(gm.user_id) AS member_count`
	const from = `FROM groups g LEFT JOIN group_members gm ON gm.group_id = g.id`

	var rows pgx.Rows
	var err error

	if p.After == nil {
		rows, err = r.pool.Query(ctx, `SELECT `+cols+` `+from+`
			WHERE g.org_id = $1
			GROUP BY g.id ORDER BY g.name ASC, g.id ASC LIMIT $2`, orgID, fetchLimit)
	} else {
		var cursorName string
		if e := r.pool.QueryRow(ctx, `SELECT name FROM groups WHERE id = $1`, *p.After).Scan(&cursorName); e != nil {
			return nil, fmt.Errorf("invalid cursor: %w", e)
		}
		rows, err = r.pool.Query(ctx, `SELECT `+cols+` `+from+`
			WHERE g.org_id = $1
			  AND (g.name > $2 OR (g.name = $2 AND g.id > $3))
			GROUP BY g.id ORDER BY g.name ASC, g.id ASC LIMIT $4`,
			orgID, cursorName, *p.After, fetchLimit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := make([]*models.Group, 0, limit)
	for rows.Next() {
		g := &models.Group{}
		if err := rows.Scan(&g.ID, &g.OrgID, &g.Name, &g.Description, &g.IsSystem,
			&g.CreatedAt, &g.UpdatedAt, &g.ManagedBy, &g.ManagedRef, &g.MemberCount); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	hasMore := len(groups) > limit
	if hasMore {
		groups = groups[:limit]
	}
	page := &models.Page[*models.Group]{
		Items:   groups,
		HasMore: hasMore,
	}
	if hasMore {
		last := groups[len(groups)-1].ID.String()
		page.NextCursor = &last
	}
	return page, nil
}

// GetByID returns a single group.
func (r *GroupRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Group, error) {
	g := &models.Group{}
	err := r.pool.QueryRow(ctx, `
		SELECT g.id, g.org_id, g.name, g.description, g.is_system, g.created_at, g.updated_at,
		       g.managed_by, g.managed_ref,
		       COUNT(gm.user_id) AS member_count
		FROM groups g
		LEFT JOIN group_members gm ON gm.group_id = g.id
		WHERE g.id = $1
		GROUP BY g.id
	`, id).Scan(&g.ID, &g.OrgID, &g.Name, &g.Description, &g.IsSystem,
		&g.CreatedAt, &g.UpdatedAt, &g.ManagedBy, &g.ManagedRef, &g.MemberCount)
	return g, err
}

// SetManagedMarker adopts, refreshes, or releases the declarative-management
// marker on a group. See ApplyManagedMarker.
func (r *GroupRepository) SetManagedMarker(ctx context.Context, id, orgID uuid.UUID, m ManagedMarkerInput) error {
	return ApplyManagedMarker(ctx, r.pool, "groups", "id", id, orgID, m)
}

// GetForOrg loads a group only when it belongs to orgID, returning ErrNoRows on a
// cross-tenant or missing id. Admin handlers MUST guard on this before any
// group operation performed by group id.
func (r *GroupRepository) GetForOrg(ctx context.Context, id, orgID uuid.UUID) (*models.Group, error) {
	g, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if g.OrgID != orgID {
		return nil, pgx.ErrNoRows
	}
	return g, nil
}

// UserInOrg reports whether userID belongs to orgID. Used to reject adding a
// cross-tenant user to a group.
func (r *GroupRepository) UserInOrg(ctx context.Context, userID, orgID uuid.UUID) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND org_id=$2)`, userID, orgID).Scan(&ok)
	return ok, err
}

// RoleInOrg reports whether roleID belongs to orgID. Used to reject assigning a
// cross-tenant role to a group.
func (r *GroupRepository) RoleInOrg(ctx context.Context, roleID, orgID uuid.UUID) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE id=$1 AND org_id=$2)`, roleID, orgID).Scan(&ok)
	return ok, err
}

// Create inserts a new group.
// An entity event (group.created) is written atomically in the same transaction.
func (r *GroupRepository) Create(ctx context.Context, orgID uuid.UUID, name, description string) (*models.Group, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	g := &models.Group{}
	var desc *string
	if description != "" {
		desc = &description
	}
	if err = tx.QueryRow(ctx, `
		INSERT INTO groups (org_id, name, description)
		VALUES ($1, $2, $3)
		RETURNING id, org_id, name, description, is_system, created_at, updated_at
	`, orgID, name, desc).Scan(
		&g.ID, &g.OrgID, &g.Name, &g.Description, &g.IsSystem, &g.CreatedAt, &g.UpdatedAt,
	); err != nil {
		return nil, err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "group",
		EntityID:   g.ID.String(),
		EventType:  "group.created",
		Payload:    map[string]any{"name": name},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	return g, tx.Commit(ctx)
}

// Delete removes a group (system groups are protected at handler level).
// An entity event (group.deleted) is written atomically in the same transaction.
func (r *GroupRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx,
		`DELETE FROM groups WHERE id=$1 AND is_system=FALSE RETURNING org_id`, id,
	).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "group",
		EntityID:   id.String(),
		EventType:  "group.deleted",
		Payload:    map[string]any{"deleted": true},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ListMembers returns users that belong to a group.
func (r *GroupRepository) ListMembers(ctx context.Context, groupID uuid.UUID) ([]*models.User, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT u.id, u.org_id, u.email, u.first_name, u.last_name, u.is_active, u.created_at
		FROM users u
		JOIN group_members gm ON gm.user_id = u.id
		WHERE gm.group_id = $1
		ORDER BY u.email
	`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]*models.User, 0)
	for rows.Next() {
		u := &models.User{}
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.FirstName, &u.LastName,
			&u.IsActive, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// AddMember adds a user to a group (idempotent).
// An entity event (group.member_added) is written atomically in the same transaction.
func (r *GroupRepository) AddMember(ctx context.Context, groupID, userID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `
		INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, groupID, userID); err != nil {
		return err
	}

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT org_id FROM groups WHERE id=$1`, groupID).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "group",
		EntityID:   groupID.String(),
		EventType:  "group.member_added",
		Payload:    map[string]any{"user_id": userID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// RemoveMember removes a user from a group.
// An entity event (group.member_removed) is written atomically in the same transaction.
func (r *GroupRepository) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `DELETE FROM group_members WHERE group_id=$1 AND user_id=$2`, groupID, userID); err != nil {
		return err
	}

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT org_id FROM groups WHERE id=$1`, groupID).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "group",
		EntityID:   groupID.String(),
		EventType:  "group.member_removed",
		Payload:    map[string]any{"user_id": userID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ListRoles returns roles assigned to a group.
func (r *GroupRepository) ListRoles(ctx context.Context, groupID uuid.UUID) ([]*models.Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT r.id, r.org_id, r.name, r.description, r.is_system, r.created_at
		FROM roles r
		JOIN group_roles gr ON gr.role_id = r.id
		WHERE gr.group_id = $1
		ORDER BY r.name
	`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]*models.Role, 0)
	for rows.Next() {
		ro := &models.Role{}
		if err := rows.Scan(&ro.ID, &ro.OrgID, &ro.Name, &ro.Description, &ro.IsSystem, &ro.CreatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, ro)
	}
	return roles, rows.Err()
}

// AssignRole assigns a role to a group (idempotent).
// An entity event (group.role_assigned) is written atomically in the same transaction.
func (r *GroupRepository) AssignRole(ctx context.Context, groupID, roleID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `
		INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, groupID, roleID); err != nil {
		return err
	}

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT org_id FROM groups WHERE id=$1`, groupID).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "group",
		EntityID:   groupID.String(),
		EventType:  "group.role_assigned",
		Payload:    map[string]any{"role_id": roleID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// RemoveRole removes a role from a group.
// An entity event (group.role_removed) is written atomically in the same transaction.
func (r *GroupRepository) RemoveRole(ctx context.Context, groupID, roleID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `DELETE FROM group_roles WHERE group_id=$1 AND role_id=$2`, groupID, roleID); err != nil {
		return err
	}

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT org_id FROM groups WHERE id=$1`, groupID).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "group",
		EntityID:   groupID.String(),
		EventType:  "group.role_removed",
		Payload:    map[string]any{"role_id": roleID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// GroupsForUser returns group names for a user (used in OIDC claims).
func (r *GroupRepository) GroupsForUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT g.name FROM groups g
		JOIN group_members gm ON gm.group_id = g.id
		WHERE gm.user_id = $1
		ORDER BY g.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// GroupIDsForUser returns the UUIDs of all groups the user belongs to.
// Used for scoped attestation policy lookup.
func (r *GroupRepository) GroupIDsForUser(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT group_id FROM group_members WHERE user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetByName returns a group by name within an org.
// Returns (nil, nil) if not found.
func (r *GroupRepository) GetByName(ctx context.Context, orgID uuid.UUID, name string) (*models.Group, error) {
	g := &models.Group{}
	err := r.pool.QueryRow(ctx, `
		SELECT g.id, g.org_id, g.name, g.description, g.is_system, g.created_at, g.updated_at,
		       COUNT(gm.user_id) AS member_count
		FROM groups g
		LEFT JOIN group_members gm ON gm.group_id = g.id
		WHERE g.org_id = $1 AND g.name = $2
		GROUP BY g.id
	`, orgID, name).Scan(&g.ID, &g.OrgID, &g.Name, &g.Description, &g.IsSystem,
		&g.CreatedAt, &g.UpdatedAt, &g.MemberCount)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return g, nil
}

// IsMember reports whether userID is a direct member of groupID.
func (r *GroupRepository) IsMember(ctx context.Context, groupID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2
		)
	`, groupID, userID).Scan(&exists)
	return exists, err
}
