package repository

import (
	"context"
	"fmt"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CreateLDAPParams holds the fields needed to create an LDAP connection.
type CreateLDAPParams struct {
	Name       string
	Host       string
	Port       int
	UseTLS     bool
	BindDN     *string
	BindPass   *string
	BaseDN     string
	UserFilter string
}

// LDAPRepository handles LDAP connection persistence.
type LDAPRepository struct {
	pool *pgxpool.Pool
	enc  *crypto.Encryptor // may be nil (no encryption configured)
}

func NewLDAPRepository(pool *pgxpool.Pool) *LDAPRepository {
	return &LDAPRepository{pool: pool}
}

// NewLDAPRepositoryWithEnc creates a repository that encrypts bind_password at rest.
func NewLDAPRepositoryWithEnc(pool *pgxpool.Pool, enc *crypto.Encryptor) *LDAPRepository {
	return &LDAPRepository{pool: pool, enc: enc}
}

func (r *LDAPRepository) encryptPass(pass *string) (*string, error) {
	if r.enc == nil || pass == nil || *pass == "" {
		return pass, nil
	}
	ct, err := r.enc.Encrypt(*pass)
	if err != nil {
		return nil, err
	}
	return &ct, nil
}

func (r *LDAPRepository) decryptPass(stored *string) *string {
	if r.enc == nil || stored == nil {
		return stored
	}
	plain, err := r.enc.Decrypt(*stored)
	if err != nil {
		return stored // best-effort; caller should handle dial failures
	}
	return &plain
}

func (r *LDAPRepository) Create(ctx context.Context, orgID uuid.UUID, req CreateLDAPParams) (*models.LDAPConnection, error) {
	filter := req.UserFilter
	if filter == "" {
		filter = "(objectClass=person)"
	}
	encPass, err := r.encryptPass(req.BindPass)
	if err != nil {
		return nil, fmt.Errorf("encrypt bind_password: %w", err)
	}
	conn := &models.LDAPConnection{}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO ldap_connections (org_id, name, host, port, use_tls, bind_dn, bind_password, base_dn, user_filter)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, org_id, name, host, port, use_tls, bind_dn, base_dn, user_filter, user_attr_map, is_active, last_sync_at, created_at, updated_at
	`, orgID, req.Name, req.Host, req.Port, req.UseTLS, req.BindDN, encPass, req.BaseDN, filter).Scan(
		&conn.ID, &conn.OrgID, &conn.Name, &conn.Host, &conn.Port, &conn.UseTLS,
		&conn.BindDN, &conn.BaseDN, &conn.UserFilter, &conn.UserAttrMap,
		&conn.IsActive, &conn.LastSyncAt, &conn.CreatedAt, &conn.UpdatedAt,
	)
	return conn, err
}

// GetForOrg loads an LDAP connection only when it belongs to orgID (ErrNoRows
// otherwise). Admin handlers MUST guard on this before operating by id.
func (r *LDAPRepository) GetForOrg(ctx context.Context, id, orgID uuid.UUID) (*models.LDAPConnection, error) {
	conn, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if conn.OrgID != orgID {
		return nil, pgx.ErrNoRows
	}
	return conn, nil
}

func (r *LDAPRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.LDAPConnection, error) {
	conn := &models.LDAPConnection{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, name, host, port, use_tls, bind_dn, base_dn, user_filter, user_attr_map, is_active, last_sync_at, created_at, updated_at
		FROM ldap_connections WHERE id = $1
	`, id).Scan(
		&conn.ID, &conn.OrgID, &conn.Name, &conn.Host, &conn.Port, &conn.UseTLS,
		&conn.BindDN, &conn.BaseDN, &conn.UserFilter, &conn.UserAttrMap,
		&conn.IsActive, &conn.LastSyncAt, &conn.CreatedAt, &conn.UpdatedAt,
	)
	return conn, err
}

func (r *LDAPRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.LDAPConnection, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, name, host, port, use_tls, bind_dn, base_dn, user_filter, user_attr_map, is_active, last_sync_at, created_at, updated_at
		FROM ldap_connections WHERE org_id = $1 ORDER BY name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	conns := make([]*models.LDAPConnection, 0)
	for rows.Next() {
		c := &models.LDAPConnection{}
		if err := rows.Scan(
			&c.ID, &c.OrgID, &c.Name, &c.Host, &c.Port, &c.UseTLS,
			&c.BindDN, &c.BaseDN, &c.UserFilter, &c.UserAttrMap,
			&c.IsActive, &c.LastSyncAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		conns = append(conns, c)
	}
	return conns, rows.Err()
}

// ListByOrgPage returns a cursor-paginated slice of LDAP connections for an org.
func (r *LDAPRepository) ListByOrgPage(ctx context.Context, orgID uuid.UUID, p models.PageParams) (*models.Page[*models.LDAPConnection], error) {
	limit := p.Limit
	if limit <= 0 {
		limit = models.DefaultPageSize
	}
	if limit > models.MaxPageSize {
		limit = models.MaxPageSize
	}
	fetchLimit := limit + 1

	const cols = `id, org_id, name, host, port, use_tls, bind_dn, base_dn, user_filter, user_attr_map, is_active, last_sync_at, created_at, updated_at`

	var rows pgx.Rows
	var err error

	if p.After == nil {
		rows, err = r.pool.Query(ctx, `SELECT `+cols+`
			FROM ldap_connections WHERE org_id = $1
			ORDER BY name ASC, id ASC LIMIT $2`, orgID, fetchLimit)
	} else {
		var cursorName string
		if e := r.pool.QueryRow(ctx, `SELECT name FROM ldap_connections WHERE id = $1`, *p.After).Scan(&cursorName); e != nil {
			return nil, fmt.Errorf("invalid cursor: %w", e)
		}
		rows, err = r.pool.Query(ctx, `SELECT `+cols+`
			FROM ldap_connections WHERE org_id = $1
			  AND (name > $2 OR (name = $2 AND id > $3))
			ORDER BY name ASC, id ASC LIMIT $4`,
			orgID, cursorName, *p.After, fetchLimit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	conns := make([]*models.LDAPConnection, 0, limit)
	for rows.Next() {
		c := &models.LDAPConnection{}
		if err := rows.Scan(
			&c.ID, &c.OrgID, &c.Name, &c.Host, &c.Port, &c.UseTLS,
			&c.BindDN, &c.BaseDN, &c.UserFilter, &c.UserAttrMap,
			&c.IsActive, &c.LastSyncAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		conns = append(conns, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	hasMore := len(conns) > limit
	if hasMore {
		conns = conns[:limit]
	}
	page := &models.Page[*models.LDAPConnection]{
		Items:   conns,
		HasMore: hasMore,
	}
	if hasMore {
		last := conns[len(conns)-1].ID.String()
		page.NextCursor = &last
	}
	return page, nil
}

func (r *LDAPRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM ldap_connections WHERE id = $1`, id)
	return err
}

// UpdateLDAPParams holds the fields that can be changed after creation.
type UpdateLDAPParams struct {
	Name       string
	Host       string
	Port       int
	UseTLS     bool
	BindDN     *string
	BindPass   *string // nil = leave existing password unchanged
	BaseDN     string
	UserFilter string
	IsActive   bool
}

// Update modifies an existing LDAP connection.
// When BindPass is nil the stored password is left unchanged.
func (r *LDAPRepository) Update(ctx context.Context, id uuid.UUID, p UpdateLDAPParams) (*models.LDAPConnection, error) {
	filter := p.UserFilter
	if filter == "" {
		filter = "(objectClass=person)"
	}
	conn := &models.LDAPConnection{}
	var err error
	var encPass *string
	if p.BindPass != nil {
		var encErr error
		encPass, encErr = r.encryptPass(p.BindPass)
		if encErr != nil {
			return nil, fmt.Errorf("encrypt bind_password: %w", encErr)
		}
	}
	if p.BindPass != nil {
		err = r.pool.QueryRow(ctx, `
			UPDATE ldap_connections
			SET name=$2, host=$3, port=$4, use_tls=$5, bind_dn=$6, bind_password=$7,
			    base_dn=$8, user_filter=$9, is_active=$10, updated_at=now()
			WHERE id=$1
			RETURNING id, org_id, name, host, port, use_tls, bind_dn, base_dn,
			          user_filter, user_attr_map, is_active, last_sync_at, created_at, updated_at
		`, id, p.Name, p.Host, p.Port, p.UseTLS, p.BindDN, encPass,
			p.BaseDN, filter, p.IsActive).Scan(
			&conn.ID, &conn.OrgID, &conn.Name, &conn.Host, &conn.Port, &conn.UseTLS,
			&conn.BindDN, &conn.BaseDN, &conn.UserFilter, &conn.UserAttrMap,
			&conn.IsActive, &conn.LastSyncAt, &conn.CreatedAt, &conn.UpdatedAt,
		)
	} else {
		err = r.pool.QueryRow(ctx, `
			UPDATE ldap_connections
			SET name=$2, host=$3, port=$4, use_tls=$5, bind_dn=$6,
			    base_dn=$7, user_filter=$8, is_active=$9, updated_at=now()
			WHERE id=$1
			RETURNING id, org_id, name, host, port, use_tls, bind_dn, base_dn,
			          user_filter, user_attr_map, is_active, last_sync_at, created_at, updated_at
		`, id, p.Name, p.Host, p.Port, p.UseTLS, p.BindDN,
			p.BaseDN, filter, p.IsActive).Scan(
			&conn.ID, &conn.OrgID, &conn.Name, &conn.Host, &conn.Port, &conn.UseTLS,
			&conn.BindDN, &conn.BaseDN, &conn.UserFilter, &conn.UserAttrMap,
			&conn.IsActive, &conn.LastSyncAt, &conn.CreatedAt, &conn.UpdatedAt,
		)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// GetByIDFull fetches the connection including the bind_password field, decrypted.
// Use this only for dial/sync operations — never expose BindPassword in API responses.
func (r *LDAPRepository) GetByIDFull(ctx context.Context, id uuid.UUID) (*models.LDAPConnection, error) {
	conn := &models.LDAPConnection{}
	var storedPass *string
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, name, host, port, use_tls, bind_dn, bind_password, base_dn, user_filter, user_attr_map, is_active, last_sync_at, created_at, updated_at
		FROM ldap_connections WHERE id = $1
	`, id).Scan(
		&conn.ID, &conn.OrgID, &conn.Name, &conn.Host, &conn.Port, &conn.UseTLS,
		&conn.BindDN, &storedPass, &conn.BaseDN, &conn.UserFilter, &conn.UserAttrMap,
		&conn.IsActive, &conn.LastSyncAt, &conn.CreatedAt, &conn.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	conn.BindPassword = r.decryptPass(storedPass)
	return conn, nil
}

// TouchLastSyncAt updates the last_sync_at timestamp for the given connection.
func (r *LDAPRepository) TouchLastSyncAt(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE ldap_connections SET last_sync_at = now() WHERE id = $1`, id)
	return err
}
