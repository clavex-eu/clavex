package repository

import (
	"context"
	"fmt"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MapperRepository manages protocol_mappers persistence.
type MapperRepository struct {
	pool *pgxpool.Pool
}

func NewMapperRepository(pool *pgxpool.Pool) *MapperRepository {
	return &MapperRepository{pool: pool}
}

const mapperColumns = `id, org_id, client_id, name, mapper_type, claim_name, claim_value, attribute_name,
	add_to_access_token, add_to_id_token, add_to_userinfo, created_at`

func scanMapper(row interface {
	Scan(...any) error
}) (*models.ProtocolMapper, error) {
	m := &models.ProtocolMapper{}
	err := row.Scan(
		&m.ID, &m.OrgID, &m.ClientID, &m.Name, &m.MapperType,
		&m.ClaimName, &m.ClaimValue, &m.AttributeName,
		&m.AddToAccessToken, &m.AddToIDToken, &m.AddToUserinfo, &m.CreatedAt,
	)
	return m, err
}

// Create inserts a new protocol mapper and returns the created record.
func (r *MapperRepository) Create(ctx context.Context, m *models.ProtocolMapper) (*models.ProtocolMapper, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO protocol_mappers
			(org_id, client_id, name, mapper_type, claim_name, claim_value, attribute_name,
			 add_to_access_token, add_to_id_token, add_to_userinfo)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING `+mapperColumns,
		m.OrgID, m.ClientID, m.Name, m.MapperType, m.ClaimName, m.ClaimValue, m.AttributeName,
		m.AddToAccessToken, m.AddToIDToken, m.AddToUserinfo,
	)
	created, err := scanMapper(row)
	if err != nil {
		return nil, fmt.Errorf("create mapper: %w", err)
	}
	return created, nil
}

// ListByClient returns all mappers for a given client.
func (r *MapperRepository) ListByClient(ctx context.Context, clientID string) ([]*models.ProtocolMapper, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+mapperColumns+` FROM protocol_mappers WHERE client_id = $1 ORDER BY name`,
		clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("list mappers: %w", err)
	}
	defer rows.Close()
	var out []*models.ProtocolMapper
	for rows.Next() {
		m, err := scanMapper(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if out == nil {
		out = []*models.ProtocolMapper{}
	}
	return out, rows.Err()
}

// GetByID returns a single mapper.
func (r *MapperRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProtocolMapper, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+mapperColumns+` FROM protocol_mappers WHERE id = $1`, id,
	)
	return scanMapper(row)
}

// GetForOrg loads a mapper only when it belongs to orgID (ErrNoRows otherwise).
func (r *MapperRepository) GetForOrg(ctx context.Context, id, orgID uuid.UUID) (*models.ProtocolMapper, error) {
	m, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if m.OrgID != orgID {
		return nil, pgx.ErrNoRows
	}
	return m, nil
}

// Update patches the mutable fields of a protocol mapper.
func (r *MapperRepository) Update(ctx context.Context, id uuid.UUID, name, claimName string,
	claimValue, attributeName *string,
	addToAT, addToIT, addToUI bool) (*models.ProtocolMapper, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE protocol_mappers SET
			name                = $2,
			claim_name          = $3,
			claim_value         = $4,
			attribute_name      = $5,
			add_to_access_token = $6,
			add_to_id_token     = $7,
			add_to_userinfo     = $8
		WHERE id = $1
		RETURNING `+mapperColumns,
		id, name, claimName, claimValue, attributeName, addToAT, addToIT, addToUI,
	)
	updated, err := scanMapper(row)
	if err != nil {
		return nil, fmt.Errorf("update mapper: %w", err)
	}
	return updated, nil
}

// Delete removes a protocol mapper by ID.
func (r *MapperRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM protocol_mappers WHERE id = $1`, id)
	return err
}
