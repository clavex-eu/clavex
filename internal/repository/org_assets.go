package repository

import (
	"context"
	"errors"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OrgAssetRepository manages uploaded org assets records.
type OrgAssetRepository struct{ pool *pgxpool.Pool }

func NewOrgAssetRepository(pool *pgxpool.Pool) *OrgAssetRepository {
	return &OrgAssetRepository{pool: pool}
}

const assetCols = `id, org_id, asset_type, s3_key, content_type, size_bytes, url, created_at, updated_at`

func (r *OrgAssetRepository) scanAsset(row interface{ Scan(...any) error }) (*models.OrgAsset, error) {
	a := &models.OrgAsset{}
	err := row.Scan(&a.ID, &a.OrgID, &a.AssetType, &a.S3Key, &a.ContentType, &a.SizeBytes, &a.URL, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return a, nil
}

func (r *OrgAssetRepository) List(ctx context.Context, orgID uuid.UUID) ([]*models.OrgAsset, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+assetCols+`
		FROM org_assets WHERE org_id = $1 ORDER BY asset_type`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.OrgAsset
	for rows.Next() {
		a, err := r.scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *OrgAssetRepository) GetByType(ctx context.Context, orgID uuid.UUID, assetType string) (*models.OrgAsset, error) {
	return r.scanAsset(r.pool.QueryRow(ctx, `SELECT `+assetCols+`
		FROM org_assets WHERE org_id = $1 AND asset_type = $2`, orgID, assetType))
}

type UpsertAssetParams struct {
	OrgID       uuid.UUID
	AssetType   string
	S3Key       string
	ContentType string
	SizeBytes   int64
	URL         string
}

func (r *OrgAssetRepository) Upsert(ctx context.Context, p UpsertAssetParams) (*models.OrgAsset, error) {
	return r.scanAsset(r.pool.QueryRow(ctx, `
		INSERT INTO org_assets (org_id, asset_type, s3_key, content_type, size_bytes, url)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (org_id, asset_type) DO UPDATE SET
			s3_key = EXCLUDED.s3_key, content_type = EXCLUDED.content_type,
			size_bytes = EXCLUDED.size_bytes, url = EXCLUDED.url, updated_at = now()
		RETURNING `+assetCols,
		p.OrgID, p.AssetType, p.S3Key, p.ContentType, p.SizeBytes, p.URL))
}

func (r *OrgAssetRepository) Delete(ctx context.Context, orgID uuid.UUID, assetType string) (string, error) {
	var s3Key string
	err := r.pool.QueryRow(ctx, `DELETE FROM org_assets WHERE org_id=$1 AND asset_type=$2 RETURNING s3_key`,
		orgID, assetType).Scan(&s3Key)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return s3Key, err
}
