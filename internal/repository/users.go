package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// UserRepository handles user and role persistence.
type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, orgID uuid.UUID, email string, firstName, lastName *string) (*models.User, error) {
	u := &models.User{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO users (org_id, email, first_name, last_name)
		VALUES ($1, $2, $3, $4)
		RETURNING id, org_id, email, first_name, last_name, avatar_url, is_active, is_email_verified, metadata, created_at, updated_at, last_login_at
	`, orgID, email, firstName, lastName).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.FirstName, &u.LastName, &u.AvatarURL,
		&u.IsActive, &u.IsEmailVerified, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	return u, err
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	u := &models.User{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, email, first_name, last_name, avatar_url, is_active, is_email_verified, mfa_required, required_actions, metadata, created_at, updated_at, last_login_at
		FROM users WHERE id = $1
	`, id).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.FirstName, &u.LastName, &u.AvatarURL,
		&u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	return u, err
}

// GetForOrg loads a user only when it belongs to orgID, returning ErrNoRows on a
// cross-tenant or missing id. Admin (tenant-scoped) handlers MUST use this (or
// guard on the returned OrgID) before mutating a user by its id; GetByID is left
// global because the OIDC/login runtime resolves users without an org context.
func (r *UserRepository) GetForOrg(ctx context.Context, id, orgID uuid.UUID) (*models.User, error) {
	u, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if u.OrgID != orgID {
		return nil, pgx.ErrNoRows
	}
	return u, nil
}

// GetByIDWithHash fetches the user including the password_hash (needed for ChangePassword).
func (r *UserRepository) GetByIDWithHash(ctx context.Context, id uuid.UUID) (*models.User, error) {
	u := &models.User{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, email, password_hash, first_name, last_name, avatar_url, is_active, is_email_verified, mfa_required, required_actions, metadata, created_at, updated_at, last_login_at
		FROM users WHERE id = $1
	`, id).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName, &u.AvatarURL,
		&u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	return u, err
}

func (r *UserRepository) GetByEmail(ctx context.Context, orgID uuid.UUID, email string) (*models.User, error) {
	u := &models.User{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, email, password_hash, first_name, last_name, avatar_url, is_active, is_email_verified, mfa_required, required_actions, metadata, created_at, updated_at, last_login_at
		FROM users WHERE org_id = $1 AND email = $2
	`, orgID, email).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName, &u.AvatarURL,
		&u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	return u, err
}

// GetByPhone looks up a user via their verified phone number in user_phone_numbers.
// phone should be in E.164 format as stored at registration/verification time.
func (r *UserRepository) GetByPhone(ctx context.Context, orgID uuid.UUID, phone string) (*models.User, error) {
	u := &models.User{}
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, u.org_id, u.email, u.password_hash, u.first_name, u.last_name, u.avatar_url,
		       u.is_active, u.is_email_verified, u.mfa_required, u.required_actions, u.metadata, u.created_at, u.updated_at, u.last_login_at
		FROM users u
		JOIN user_phone_numbers p ON p.user_id = u.id
		WHERE u.org_id = $1 AND p.phone = $2
	`, orgID, phone).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName, &u.AvatarURL,
		&u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	return u, err
}

// GetByExternalID looks up a user via a user_idp_links row.
// providerType is e.g. "franceconnect" or "itsme"; externalSub is the IdP's sub claim.
func (r *UserRepository) GetByExternalID(ctx context.Context, orgID uuid.UUID, providerType, externalSub string) (*models.User, error) {
	u := &models.User{}
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, u.org_id, u.email, u.password_hash, u.first_name, u.last_name, u.avatar_url,
		       u.is_active, u.is_email_verified, u.mfa_required, u.required_actions, u.metadata, u.created_at, u.updated_at, u.last_login_at
		FROM users u
		JOIN user_idp_links l ON l.user_id = u.id
		WHERE u.org_id = $1 AND l.provider_type = $2 AND l.external_sub = $3
	`, orgID, providerType, externalSub).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.FirstName, &u.LastName, &u.AvatarURL,
		&u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	return u, err
}

// CreateWithExternalID creates a user and atomically inserts a user_idp_links row.
func (r *UserRepository) CreateWithExternalID(
	ctx context.Context,
	orgID uuid.UUID,
	email string,
	firstName, lastName *string,
	providerType, externalSub string,
) (*models.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	u := &models.User{}
	err = tx.QueryRow(ctx, `
		INSERT INTO users (org_id, email, first_name, last_name)
		VALUES ($1, $2, $3, $4)
		RETURNING id, org_id, email, first_name, last_name, avatar_url, is_active, is_email_verified, metadata, created_at, updated_at, last_login_at
	`, orgID, email, firstName, lastName).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.FirstName, &u.LastName, &u.AvatarURL,
		&u.IsActive, &u.IsEmailVerified, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO user_idp_links (user_id, provider_type, external_sub)
		VALUES ($1, $2, $3)
	`, u.ID, providerType, externalSub)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// LinkExternalID inserts or updates a user_idp_links row for an existing user.
func (r *UserRepository) LinkExternalID(ctx context.Context, userID uuid.UUID, providerType, externalSub string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO user_idp_links (user_id, provider_type, external_sub)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, provider_type) DO UPDATE SET external_sub = EXCLUDED.external_sub
	`, userID, providerType, externalSub)
	return err
}

func (r *UserRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.User, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, email, first_name, last_name, avatar_url, is_active, is_email_verified, mfa_required, required_actions, metadata, created_at, updated_at, last_login_at
		FROM users WHERE org_id = $1 ORDER BY email
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]*models.User, 0)
	for rows.Next() {
		u := &models.User{}
		if err := rows.Scan(
			&u.ID, &u.OrgID, &u.Email, &u.FirstName, &u.LastName, &u.AvatarURL,
			&u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ListByOrgPage returns a cursor-paginated page of users for an organisation.
//
// Cursor is the UUID of the last user seen (via the "after" param). Items are
// sorted by (email ASC, id ASC), which gives a stable insert-order-independent
// ordering. The caller receives up to p.Limit+1 rows so it can detect HasMore.
func (r *UserRepository) ListByOrgPage(ctx context.Context, orgID uuid.UUID, p models.PageParams) (*models.Page[*models.User], error) {
	limit := p.Limit
	if limit <= 0 {
		limit = models.DefaultPageSize
	}
	if limit > models.MaxPageSize {
		limit = models.MaxPageSize
	}

	// We fetch limit+1 to know whether there is a next page.
	fetchLimit := limit + 1

	const scanCols = `id, org_id, email, first_name, last_name, avatar_url, is_active, is_email_verified, mfa_required, required_actions, metadata, created_at, updated_at, last_login_at`
	const scanFields = `&u.ID, &u.OrgID, &u.Email, &u.FirstName, &u.LastName, &u.AvatarURL, &u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt`
	_ = scanFields

	var (
		rows pgx.Rows
		err  error
	)

	if p.After == nil && p.Query == "" {
		// Simple case: first page, no filter.
		rows, err = r.pool.Query(ctx, `
			SELECT `+scanCols+`
			FROM users
			WHERE org_id = $1
			ORDER BY email ASC, id ASC
			LIMIT $2
		`, orgID, fetchLimit)
	} else if p.After != nil && p.Query == "" {
		// Cursor case: get the cursor row's email first so we can do a keyset seek.
		var cursorEmail string
		if e := r.pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, *p.After).Scan(&cursorEmail); e != nil {
			return nil, fmt.Errorf("invalid cursor: %w", e)
		}
		rows, err = r.pool.Query(ctx, `
			SELECT `+scanCols+`
			FROM users
			WHERE org_id = $1
			  AND (email > $2 OR (email = $2 AND id > $3))
			ORDER BY email ASC, id ASC
			LIMIT $4
		`, orgID, cursorEmail, *p.After, fetchLimit)
	} else if p.Query != "" && p.After == nil {
		// Search first page.
		pattern := "%" + p.Query + "%"
		rows, err = r.pool.Query(ctx, `
			SELECT `+scanCols+`
			FROM users
			WHERE org_id = $1
			  AND (email ILIKE $2 OR first_name ILIKE $2 OR last_name ILIKE $2)
			ORDER BY email ASC, id ASC
			LIMIT $3
		`, orgID, pattern, fetchLimit)
	} else {
		// Search with cursor.
		var cursorEmail string
		if e := r.pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, *p.After).Scan(&cursorEmail); e != nil {
			return nil, fmt.Errorf("invalid cursor: %w", e)
		}
		pattern := "%" + p.Query + "%"
		rows, err = r.pool.Query(ctx, `
			SELECT `+scanCols+`
			FROM users
			WHERE org_id = $1
			  AND (email ILIKE $2 OR first_name ILIKE $2 OR last_name ILIKE $2)
			  AND (email > $3 OR (email = $3 AND id > $4))
			ORDER BY email ASC, id ASC
			LIMIT $5
		`, orgID, pattern, cursorEmail, *p.After, fetchLimit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]*models.User, 0, limit)
	for rows.Next() {
		u := &models.User{}
		if e := rows.Scan(
			&u.ID, &u.OrgID, &u.Email, &u.FirstName, &u.LastName, &u.AvatarURL,
			&u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions,
			&u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		); e != nil {
			return nil, e
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	hasMore := len(users) == fetchLimit
	if hasMore {
		users = users[:limit]
	}

	page := &models.Page[*models.User]{
		Items:   users,
		HasMore: hasMore,
	}
	if hasMore && len(users) > 0 {
		last := users[len(users)-1].ID.String()
		page.NextCursor = &last
	}
	return page, nil
}

func (r *UserRepository) Update(ctx context.Context, id uuid.UUID, firstName, lastName *string, isActive, mfaRequired *bool) (*models.User, error) {
	u := &models.User{}
	err := r.pool.QueryRow(ctx, `
		UPDATE users SET
			first_name   = COALESCE($2, first_name),
			last_name    = COALESCE($3, last_name),
			is_active    = COALESCE($4, is_active),
			mfa_required = COALESCE($5, mfa_required),
			updated_at   = NOW()
		WHERE id = $1
		RETURNING id, org_id, email, first_name, last_name, avatar_url, is_active, is_email_verified, mfa_required, required_actions, metadata, created_at, updated_at, last_login_at
	`, id, firstName, lastName, isActive, mfaRequired).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.FirstName, &u.LastName, &u.AvatarURL,
		&u.IsActive, &u.IsEmailVerified, &u.MFARequired, &u.RequiredActions, &u.Metadata, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	return u, err
}

// SetRequiredActions replaces the required_actions array for a user.
// Pass an empty slice to clear all pending actions.
func (r *UserRepository) SetRequiredActions(ctx context.Context, id uuid.UUID, actions []string) error {
	if actions == nil {
		actions = []string{}
	}
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET required_actions = $2, updated_at = NOW() WHERE id = $1`,
		id, actions,
	)
	return err
}

// SetEmailVerified marks the user's email as verified.
func (r *UserRepository) SetEmailVerified(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET is_email_verified = TRUE, updated_at = NOW() WHERE id = $1`, id,
	)
	return err
}

// SetPassword hashes and stores a new password for the user.
// An entity event is written atomically in the same transaction so the change
// is always reflected in the entity_events log even if the server crashes
// immediately after — closing the audit gap vs. the audit_logs approach.
func (r *UserRepository) SetPassword(ctx context.Context, id uuid.UUID, plaintext string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), 12)
	if err != nil {
		return err
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// UPDATE returns org_id so we can write the entity event in the same tx.
	var orgID uuid.UUID
	if err = tx.QueryRow(ctx,
		`UPDATE users SET password_hash=$2, updated_at=NOW() WHERE id=$1 RETURNING org_id`,
		id, string(hash),
	).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "user",
		EntityID:   id.String(),
		EventType:  "user.password_changed",
		Payload:    map[string]any{"password_hash_updated": true},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// CheckPassword verifies a plaintext password against the stored bcrypt hash.
func (r *UserRepository) CheckPassword(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// ── Role management ───────────────────────────────────────────────────────────

func (r *UserRepository) CreateRole(ctx context.Context, orgID uuid.UUID, name string, description *string) (*models.Role, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	role := &models.Role{}
	if err = tx.QueryRow(ctx, `
		INSERT INTO roles (org_id, name, description)
		VALUES ($1, $2, $3)
		RETURNING id, org_id, name, description, is_system, created_at
	`, orgID, name, description).Scan(
		&role.ID, &role.OrgID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt,
	); err != nil {
		return nil, err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "role",
		EntityID:   role.ID.String(),
		EventType:  "role.created",
		Payload:    map[string]any{"name": name},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return nil, err
	}

	return role, tx.Commit(ctx)
}

func (r *UserRepository) ListRoles(ctx context.Context, orgID uuid.UUID) ([]*models.Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, name, description, is_system, created_at, managed_by, managed_ref
		FROM roles WHERE org_id = $1 ORDER BY name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]*models.Role, 0)
	for rows.Next() {
		role := &models.Role{}
		if err := rows.Scan(&role.ID, &role.OrgID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt, &role.ManagedBy, &role.ManagedRef); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// SetRoleManagedMarker adopts, refreshes, or releases the declarative-management
// marker on a role (roles table). See ApplyManagedMarker.
func (r *UserRepository) SetRoleManagedMarker(ctx context.Context, roleID, orgID uuid.UUID, m ManagedMarkerInput) error {
	return ApplyManagedMarker(ctx, r.pool, "roles", "id", roleID, orgID, m)
}

func (r *UserRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx,
		`DELETE FROM roles WHERE id=$1 AND is_system=false RETURNING org_id`, id,
	).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "role",
		EntityID:   id.String(),
		EventType:  "role.deleted",
		Payload:    map[string]any{"deleted": true},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *UserRepository) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, userID, roleID)
	if err != nil {
		return err
	}

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx,
		`SELECT org_id FROM users WHERE id=$1`, userID,
	).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "user",
		EntityID:   userID.String(),
		EventType:  "user.role_assigned",
		Payload:    map[string]any{"role_id": roleID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *UserRepository) UnassignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`,
		userID, roleID,
	)
	if err != nil {
		return err
	}

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx,
		`SELECT org_id FROM users WHERE id=$1`, userID,
	).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "user",
		EntityID:   userID.String(),
		EventType:  "user.role_removed",
		Payload:    map[string]any{"role_id": roleID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ListRolesByUser returns all roles directly assigned to a specific user.
func (r *UserRepository) ListRolesByUser(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT r.id, r.org_id, r.name, r.description, r.is_system, r.created_at
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1
	`, userID)
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

// FlattenRoleNames returns all effective role names for a user, including inherited
// roles from composite roles. Uses a recursive CTE so a single DB round-trip suffices.
func (r *UserRepository) FlattenRoleNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		WITH RECURSIVE role_tree AS (
			SELECT r.id, r.name
			FROM roles r
			JOIN user_roles ur ON ur.role_id = r.id
			WHERE ur.user_id = $1
			UNION
			SELECT r.id, r.name
			FROM roles r
			JOIN role_members rm ON rm.child_role_id = r.id
			JOIN role_tree rt ON rt.id = rm.parent_role_id
		)
		SELECT DISTINCT name FROM role_tree ORDER BY name
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("flatten roles: %w", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// SetMetadata replaces the entire metadata JSONB object for a user.
func (r *UserRepository) SetMetadata(ctx context.Context, id uuid.UUID, metadata map[string]interface{}) error {
	b, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	_, err = r.pool.Exec(ctx,
		`UPDATE users SET metadata = $2::jsonb, updated_at = NOW() WHERE id = $1`,
		id, b,
	)
	return err
}

// MergeMetadata merges a partial metadata map into the existing user metadata
// using PostgreSQL's JSONB concatenation operator (||). Existing top-level keys
// not present in patch are preserved; keys present in patch overwrite existing values.
func (r *UserRepository) MergeMetadata(ctx context.Context, id uuid.UUID, patch map[string]interface{}) error {
	b, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal metadata patch: %w", err)
	}
	_, err = r.pool.Exec(ctx,
		`UPDATE users SET metadata = COALESCE(metadata, '{}'::jsonb) || $2::jsonb, updated_at = NOW() WHERE id = $1`,
		id, b,
	)
	return err
}

// RecordIdentityImport stamps the identity_source_issuer and identity_imported_at
// fields on the user, and merges the supplied verified claims into the user's
// metadata.  Called by the identity continuity endpoint after a successful VP
// verification from a remote Clavex installation.
func (r *UserRepository) RecordIdentityImport(
	ctx context.Context,
	userID uuid.UUID,
	sourceIssuer string,
	verifiedClaims map[string]interface{},
) error {
	// Merge verified claims into metadata under the "identity_import" namespace
	// so they don't collide with other metadata keys.
	ns := map[string]interface{}{
		"identity_import": verifiedClaims,
	}
	b, err := json.Marshal(ns)
	if err != nil {
		return fmt.Errorf("marshal identity import claims: %w", err)
	}
	_, err = r.pool.Exec(ctx, `
		UPDATE users
		SET identity_source_issuer = $2,
		    identity_imported_at   = NOW(),
		    metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb,
		    updated_at = NOW()
		WHERE id = $1
	`, userID, sourceIssuer, b)
	return err
}

// GetRoleByName fetches a single role by its name within an org.
// Returns (nil, nil) if not found.
func (r *UserRepository) GetRoleByName(ctx context.Context, orgID uuid.UUID, name string) (*models.Role, error) {
	role := &models.Role{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, name, description, is_system, created_at
		FROM roles WHERE org_id = $1 AND name = $2
	`, orgID, name).Scan(&role.ID, &role.OrgID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return role, err
}

// GetRoleByID fetches a single role by UUID.
// Returns (nil, nil) if not found.
func (r *UserRepository) GetRoleByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	role := &models.Role{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, name, description, is_system, created_at
		FROM roles WHERE id = $1
	`, id).Scan(&role.ID, &role.OrgID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return role, err
}

// HasRoleFlattened reports whether userID holds the named role within orgID,
// either directly or through composite role inheritance (recursive CTE).
// Returns (false, nil) if the role does not exist in the org.
func (r *UserRepository) HasRoleFlattened(ctx context.Context, orgID uuid.UUID, userID uuid.UUID, roleName string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		WITH RECURSIVE role_tree AS (
			SELECT r.id, r.name
			FROM roles r
			JOIN user_roles ur ON ur.role_id = r.id
			WHERE ur.user_id = $1
			UNION
			SELECT r.id, r.name
			FROM roles r
			JOIN role_members rm ON rm.child_role_id = r.id
			JOIN role_tree rt ON rt.id = rm.parent_role_id
		)
		SELECT EXISTS (
			SELECT 1 FROM role_tree rt
			JOIN roles rr ON rr.id = rt.id
			WHERE rr.org_id = $2 AND rt.name = $3
		)
	`, userID, orgID, roleName).Scan(&exists)
	return exists, err
}

// ── Composite role management ─────────────────────────────────────────────────

// AddChildRole makes childID a member of parentID (composite role).
// An entity event (role.child_added) is written atomically in the same transaction.
func (r *UserRepository) AddChildRole(ctx context.Context, parentID, childID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `
		INSERT INTO role_members (parent_role_id, child_role_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, parentID, childID); err != nil {
		return err
	}

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT org_id FROM roles WHERE id=$1`, parentID).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "role",
		EntityID:   parentID.String(),
		EventType:  "role.child_added",
		Payload:    map[string]any{"child_role_id": childID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// RemoveChildRole removes the composite membership.
// An entity event (role.child_removed) is written atomically in the same transaction.
func (r *UserRepository) RemoveChildRole(ctx context.Context, parentID, childID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx,
		`DELETE FROM role_members WHERE parent_role_id = $1 AND child_role_id = $2`,
		parentID, childID,
	); err != nil {
		return err
	}

	var orgID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT org_id FROM roles WHERE id=$1`, parentID).Scan(&orgID); err != nil {
		return err
	}

	evRepo := NewEntityEventsRepository(r.pool)
	if err = evRepo.AppendTx(ctx, tx, AppendParams{
		OrgID:      orgID,
		EntityType: "role",
		EntityID:   parentID.String(),
		EventType:  "role.child_removed",
		Payload:    map[string]any{"child_role_id": childID.String()},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ListChildRoles returns direct child roles of a composite role.
func (r *UserRepository) ListChildRoles(ctx context.Context, parentID uuid.UUID) ([]*models.Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT r.id, r.org_id, r.name, r.description, r.is_system, r.created_at
		FROM roles r
		JOIN role_members rm ON rm.child_role_id = r.id
		WHERE rm.parent_role_id = $1
		ORDER BY r.name
	`, parentID)
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

// GetPrimaryPhone returns the user's primary (first inserted) verified phone number.
// Returns ("", nil) when the user has no phone number on record.
func (r *UserRepository) GetPrimaryPhone(ctx context.Context, userID uuid.UUID) (string, error) {
	var phone string
	err := r.pool.QueryRow(ctx, `
		SELECT phone FROM user_phone_numbers WHERE user_id = $1 ORDER BY created_at ASC LIMIT 1
	`, userID).Scan(&phone)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return phone, nil
}
