package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WSFedRepository manages WS-Federation relying party records.
type WSFedRepository struct{ pool *pgxpool.Pool }

func NewWSFedRepository(pool *pgxpool.Pool) *WSFedRepository {
	return &WSFedRepository{pool: pool}
}

const wsfedCols = `id, org_id, name, realm, wreply_uris, token_lifetime_seconds, claims_mapping, is_active, created_at, updated_at`

func (r *WSFedRepository) scanRP(row interface{ Scan(...any) error }) (*models.WSFedRelyingParty, error) {
	p := &models.WSFedRelyingParty{}
	var raw []byte
	err := row.Scan(&p.ID, &p.OrgID, &p.Name, &p.Realm, &p.WreplyURIs,
		&p.TokenLifetimeSeconds, &raw, &p.IsActive, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(raw, &p.ClaimsMapping)
	return p, nil
}

func (r *WSFedRepository) List(ctx context.Context, orgID uuid.UUID) ([]*models.WSFedRelyingParty, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+wsfedCols+`
		FROM wsfed_relying_parties WHERE org_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.WSFedRelyingParty
	for rows.Next() {
		p, err := r.scanRP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *WSFedRepository) GetByID(ctx context.Context, orgID, id uuid.UUID) (*models.WSFedRelyingParty, error) {
	return r.scanRP(r.pool.QueryRow(ctx, `SELECT `+wsfedCols+`
		FROM wsfed_relying_parties WHERE id = $1 AND org_id = $2`, id, orgID))
}

func (r *WSFedRepository) GetByRealm(ctx context.Context, orgID uuid.UUID, realm string) (*models.WSFedRelyingParty, error) {
	return r.scanRP(r.pool.QueryRow(ctx, `SELECT `+wsfedCols+`
		FROM wsfed_relying_parties WHERE org_id = $1 AND realm = $2 AND is_active = TRUE`, orgID, realm))
}

type CreateWSFedRPParams struct {
	OrgID                uuid.UUID
	Name                 string
	Realm                string
	WreplyURIs           []string
	TokenLifetimeSeconds int
	ClaimsMapping        map[string]string
}

func (r *WSFedRepository) Create(ctx context.Context, p CreateWSFedRPParams) (*models.WSFedRelyingParty, error) {
	raw, _ := json.Marshal(p.ClaimsMapping)
	if p.TokenLifetimeSeconds == 0 {
		p.TokenLifetimeSeconds = 3600
	}
	return r.scanRP(r.pool.QueryRow(ctx, `
		INSERT INTO wsfed_relying_parties
			(org_id, name, realm, wreply_uris, token_lifetime_seconds, claims_mapping)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING `+wsfedCols,
		p.OrgID, p.Name, p.Realm, p.WreplyURIs, p.TokenLifetimeSeconds, raw))
}

func (r *WSFedRepository) Update(ctx context.Context, orgID, id uuid.UUID, p CreateWSFedRPParams) (*models.WSFedRelyingParty, error) {
	raw, _ := json.Marshal(p.ClaimsMapping)
	return r.scanRP(r.pool.QueryRow(ctx, `
		UPDATE wsfed_relying_parties SET
			name = $1, wreply_uris = $2, token_lifetime_seconds = $3,
			claims_mapping = $4, updated_at = now()
		WHERE id = $5 AND org_id = $6
		RETURNING `+wsfedCols,
		p.Name, p.WreplyURIs, p.TokenLifetimeSeconds, raw, id, orgID))
}

func (r *WSFedRepository) SetActive(ctx context.Context, orgID, id uuid.UUID, active bool) error {
	tag, err := r.pool.Exec(ctx, `UPDATE wsfed_relying_parties SET is_active=$1, updated_at=now()
		WHERE id=$2 AND org_id=$3`, active, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *WSFedRepository) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM wsfed_relying_parties WHERE id=$1 AND org_id=$2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastUsed is a no-op placeholder; relying parties don't track last_used_at.
var _ = time.Now
