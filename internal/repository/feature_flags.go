package repository

import (
	"context"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FeatureFlagRepository provides CRUD for feature flags and their per-user/role
// overrides.  See migration 000124 for the schema.
type FeatureFlagRepository struct {
	pool *pgxpool.Pool
}

func NewFeatureFlagRepository(pool *pgxpool.Pool) *FeatureFlagRepository {
	return &FeatureFlagRepository{pool: pool}
}

// List returns all flags defined for an organisation, ordered by key.
func (r *FeatureFlagRepository) List(ctx context.Context, orgID uuid.UUID) ([]*models.FeatureFlag, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, key, description, value, created_at, updated_at
		  FROM feature_flags
		 WHERE org_id = $1
		 ORDER BY key
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.FeatureFlag
	for rows.Next() {
		f := &models.FeatureFlag{}
		if err := rows.Scan(&f.ID, &f.OrgID, &f.Key, &f.Description, &f.Value, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Upsert creates or updates a feature flag by (org_id, key).
func (r *FeatureFlagRepository) Upsert(ctx context.Context, orgID uuid.UUID, key, description string, value bool) (*models.FeatureFlag, error) {
	f := &models.FeatureFlag{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO feature_flags (org_id, key, description, value)
		     VALUES ($1, $2, $3, $4)
		ON CONFLICT (org_id, key) DO UPDATE
		        SET description = EXCLUDED.description,
		            value       = EXCLUDED.value,
		            updated_at  = NOW()
		  RETURNING id, org_id, key, description, value, created_at, updated_at
	`, orgID, key, description, value).Scan(
		&f.ID, &f.OrgID, &f.Key, &f.Description, &f.Value, &f.CreatedAt, &f.UpdatedAt,
	)
	return f, err
}

// Delete removes a flag and all its overrides (via ON DELETE CASCADE).
func (r *FeatureFlagRepository) Delete(ctx context.Context, orgID uuid.UUID, key string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM feature_flags WHERE org_id = $1 AND key = $2`, orgID, key)
	return err
}

// GetFlagID returns the UUID of a flag by (orgID, key).
// Returns pgx.ErrNoRows if not found.
func (r *FeatureFlagRepository) GetFlagID(ctx context.Context, orgID uuid.UUID, key string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `SELECT id FROM feature_flags WHERE org_id = $1 AND key = $2`, orgID, key).Scan(&id)
	return id, err
}

// SetOverride upserts a per-user or per-role override for a flag.
// targetType must be "user" or "role".
func (r *FeatureFlagRepository) SetOverride(ctx context.Context, flagID uuid.UUID, targetType string, targetID uuid.UUID, value bool) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO feature_flag_overrides (flag_id, target_type, target_id, value)
		     VALUES ($1, $2, $3, $4)
		ON CONFLICT (flag_id, target_type, target_id) DO UPDATE SET value = EXCLUDED.value
	`, flagID, targetType, targetID, value)
	return err
}

// DeleteOverride removes a specific override.
func (r *FeatureFlagRepository) DeleteOverride(ctx context.Context, flagID uuid.UUID, targetType string, targetID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		DELETE FROM feature_flag_overrides
		 WHERE flag_id = $1 AND target_type = $2 AND target_id = $3
	`, flagID, targetType, targetID)
	return err
}

// ListOverrides returns all overrides for a flag.
func (r *FeatureFlagRepository) ListOverrides(ctx context.Context, flagID uuid.UUID) ([]*models.FeatureFlagOverride, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, flag_id, target_type, target_id, value
		  FROM feature_flag_overrides
		 WHERE flag_id = $1
	`, flagID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.FeatureFlagOverride
	for rows.Next() {
		ov := &models.FeatureFlagOverride{}
		if err := rows.Scan(&ov.ID, &ov.FlagID, &ov.TargetType, &ov.TargetID, &ov.Value); err != nil {
			return nil, err
		}
		out = append(out, ov)
	}
	return out, rows.Err()
}

// ResolveForUser computes the effective flag map for a user at token issuance.
//
// Resolution order (highest priority first):
//  1. Per-user override (target_type = 'user', target_id = userID)
//  2. Per-role override (target_type = 'role', target_id ∈ roleIDs) — first match wins
//  3. Flag default value
//
// Only flags that are defined for the org are returned; the map is nil if the org
// has no flags.
func (r *FeatureFlagRepository) ResolveForUser(ctx context.Context, orgID, userID uuid.UUID, roleIDs []uuid.UUID) (map[string]bool, error) {
	// Fetch all flags + applicable overrides in one query.
	// We LEFT JOIN overrides for (user) then (role) and pick by priority in Go.
	rows, err := r.pool.Query(ctx, `
		SELECT ff.key,
		       ff.value                                         AS default_value,
		       MAX(CASE WHEN ffo.target_type = 'user' AND ffo.target_id = $2
		                THEN ffo.value::int END)               AS user_override,
		       MAX(CASE WHEN ffo.target_type = 'role' AND ffo.target_id = ANY($3)
		                THEN ffo.value::int END)               AS role_override
		  FROM feature_flags ff
		  LEFT JOIN feature_flag_overrides ffo ON ffo.flag_id = ff.id
		 WHERE ff.org_id = $1
		 GROUP BY ff.key, ff.value
		 ORDER BY ff.key
	`, orgID, userID, roleIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[string]bool{}
	for rows.Next() {
		var key string
		var defVal bool
		var userOverride, roleOverride *int
		if err := rows.Scan(&key, &defVal, &userOverride, &roleOverride); err != nil {
			return nil, err
		}
		switch {
		case userOverride != nil:
			result[key] = *userOverride != 0
		case roleOverride != nil:
			result[key] = *roleOverride != 0
		default:
			result[key] = defVal
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}
