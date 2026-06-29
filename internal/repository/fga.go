package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FGAStoreRecord maps a Clavex organization to an OpenFGA store.
// One store per org — provides full tenant isolation of authorization models
// and relationship tuples in OpenFGA.
type FGAStoreRecord struct {
	OrgID     uuid.UUID
	StoreID   string
	ModelID   *string   // nil until an authorization model has been pushed
	CreatedAt time.Time
	UpdatedAt time.Time
}

// FGARepository manages persistence for the fga_stores table.
type FGARepository struct {
	pool *pgxpool.Pool
}

// NewFGARepository creates a new FGARepository backed by pool.
func NewFGARepository(pool *pgxpool.Pool) *FGARepository {
	return &FGARepository{pool: pool}
}

// Get returns the FGA store record for orgID, or nil when the org has not
// initialised a store yet.
func (r *FGARepository) Get(ctx context.Context, orgID uuid.UUID) (*FGAStoreRecord, error) {
	const q = `
		SELECT org_id, store_id, model_id, created_at, updated_at
		FROM fga_stores
		WHERE org_id = $1`

	row := r.pool.QueryRow(ctx, q, orgID)
	rec := &FGAStoreRecord{}
	err := row.Scan(&rec.OrgID, &rec.StoreID, &rec.ModelID, &rec.CreatedAt, &rec.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// Upsert inserts or updates the store record for orgID.
// modelID may be empty; when empty the existing model_id is preserved.
func (r *FGARepository) Upsert(ctx context.Context, orgID uuid.UUID, storeID, modelID string) error {
	var mid *string
	if modelID != "" {
		mid = &modelID
	}

	const q = `
		INSERT INTO fga_stores (org_id, store_id, model_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id) DO UPDATE
		SET store_id   = EXCLUDED.store_id,
		    model_id   = COALESCE(EXCLUDED.model_id, fga_stores.model_id),
		    updated_at = NOW()`

	_, err := r.pool.Exec(ctx, q, orgID, storeID, mid)
	return err
}

// UpdateModelID updates only the cached authorization_model_id for an existing store.
// Used after WriteModel (e.g. template import) to keep our DB in sync with OpenFGA.
func (r *FGARepository) UpdateModelID(ctx context.Context, orgID uuid.UUID, modelID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE fga_stores SET model_id = $2, updated_at = NOW() WHERE org_id = $1`,
		orgID, modelID,
	)
	return err
}
