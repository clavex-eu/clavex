package repository

import (
	"context"
	"errors"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppFamilyRepository manages application families (cross-app SSO groups).
type AppFamilyRepository struct{ pool *pgxpool.Pool }

func NewAppFamilyRepository(pool *pgxpool.Pool) *AppFamilyRepository {
	return &AppFamilyRepository{pool: pool}
}

const familyCols = `id, org_id, name, description, created_at, updated_at`

func (r *AppFamilyRepository) scan(row interface{ Scan(...any) error }) (*models.AppFamily, error) {
	f := &models.AppFamily{}
	err := row.Scan(&f.ID, &f.OrgID, &f.Name, &f.Description, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

func (r *AppFamilyRepository) List(ctx context.Context, orgID uuid.UUID) ([]*models.AppFamily, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+familyCols+`
		FROM app_families WHERE org_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.AppFamily
	for rows.Next() {
		f, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r *AppFamilyRepository) GetByID(ctx context.Context, orgID, id uuid.UUID) (*models.AppFamily, error) {
	f, err := r.scan(r.pool.QueryRow(ctx, `SELECT `+familyCols+`
		FROM app_families WHERE id = $1 AND org_id = $2`, id, orgID))
	if err != nil {
		return nil, err
	}
	members, err := r.ListMembers(ctx, id)
	if err != nil {
		return nil, err
	}
	f.Members = members
	return f, nil
}

func (r *AppFamilyRepository) ListMembers(ctx context.Context, familyID uuid.UUID) ([]models.AppFamilyMember, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT family_id, client_id, backchannel_logout_uri, created_at
		FROM app_family_members WHERE family_id = $1`, familyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AppFamilyMember
	for rows.Next() {
		m := models.AppFamilyMember{}
		if err := rows.Scan(&m.FamilyID, &m.ClientID, &m.BackchannelLogoutURI, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetFamilyByClientID returns the first family that contains the given OIDC client.
func (r *AppFamilyRepository) GetFamilyByClientID(ctx context.Context, clientID string) (*models.AppFamily, error) {
	var familyID uuid.UUID
	err := r.pool.QueryRow(ctx, `SELECT family_id FROM app_family_members WHERE client_id = $1 LIMIT 1`, clientID).Scan(&familyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// We don't have orgID here; use a separate query.
	f := &models.AppFamily{}
	err = r.pool.QueryRow(ctx, `SELECT `+familyCols+` FROM app_families WHERE id = $1`, familyID).
		Scan(&f.ID, &f.OrgID, &f.Name, &f.Description, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, err
	}
	members, err := r.ListMembers(ctx, familyID)
	if err != nil {
		return nil, err
	}
	f.Members = members
	return f, nil
}

type CreateAppFamilyParams struct {
	OrgID       uuid.UUID
	Name        string
	Description *string
}

func (r *AppFamilyRepository) Create(ctx context.Context, p CreateAppFamilyParams) (*models.AppFamily, error) {
	return r.scan(r.pool.QueryRow(ctx, `
		INSERT INTO app_families (org_id, name, description) VALUES ($1,$2,$3)
		RETURNING `+familyCols,
		p.OrgID, p.Name, p.Description))
}

type UpdateAppFamilyParams struct {
	Name        string
	Description *string
}

func (r *AppFamilyRepository) Update(ctx context.Context, orgID, id uuid.UUID, p UpdateAppFamilyParams) (*models.AppFamily, error) {
	return r.scan(r.pool.QueryRow(ctx, `
		UPDATE app_families SET name=$1, description=$2, updated_at=now()
		WHERE id=$3 AND org_id=$4
		RETURNING `+familyCols,
		p.Name, p.Description, id, orgID))
}

func (r *AppFamilyRepository) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM app_families WHERE id=$1 AND org_id=$2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *AppFamilyRepository) AddMember(ctx context.Context, familyID uuid.UUID, clientID string, backchannelURI *string) (*models.AppFamilyMember, error) {
	m := models.AppFamilyMember{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO app_family_members (family_id, client_id, backchannel_logout_uri)
		VALUES ($1,$2,$3)
		ON CONFLICT (family_id, client_id) DO UPDATE SET backchannel_logout_uri = EXCLUDED.backchannel_logout_uri
		RETURNING family_id, client_id, backchannel_logout_uri, created_at`,
		familyID, clientID, backchannelURI).
		Scan(&m.FamilyID, &m.ClientID, &m.BackchannelLogoutURI, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *AppFamilyRepository) RemoveMember(ctx context.Context, familyID uuid.UUID, clientID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM app_family_members WHERE family_id=$1 AND client_id=$2`, familyID, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
