package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DeviceFact holds the last-known posture facts for a single device.
type DeviceFact struct {
	ID         uuid.UUID              `db:"id"          json:"id"`
	OrgID      uuid.UUID              `db:"org_id"      json:"org_id"`
	DeviceID   string                 `db:"device_id"   json:"device_id"`
	UserID     *uuid.UUID             `db:"user_id"     json:"user_id,omitempty"`
	Platform   string                 `db:"platform"    json:"platform"`
	Facts      map[string]interface{} `db:"facts"       json:"facts"`
	LastSeenAt time.Time              `db:"last_seen_at" json:"last_seen_at"`
	CreatedAt  time.Time              `db:"created_at"  json:"created_at"`
}

// DeviceFactsRepository provides persistence for fleet-agent device facts.
type DeviceFactsRepository struct {
	pool *pgxpool.Pool
}

// NewDeviceFactsRepository creates a new DeviceFactsRepository.
func NewDeviceFactsRepository(pool *pgxpool.Pool) *DeviceFactsRepository {
	return &DeviceFactsRepository{pool: pool}
}

// Upsert inserts or updates device facts for the given (orgID, deviceID) pair.
// The facts map is merged with existing facts (JSONB ||) at the DB level so that
// partial updates from lightweight heartbeats do not wipe unrelated keys.
func (r *DeviceFactsRepository) Upsert(ctx context.Context, orgID uuid.UUID, deviceID string, userID *uuid.UUID, platform string, facts map[string]interface{}) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO device_facts (org_id, device_id, user_id, platform, facts, last_seen_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, NOW())
		ON CONFLICT (org_id, device_id) DO UPDATE
		  SET user_id     = EXCLUDED.user_id,
		      platform    = EXCLUDED.platform,
		      facts       = device_facts.facts || EXCLUDED.facts,
		      last_seen_at = NOW()`,
		orgID, deviceID, userID, platform, facts,
	)
	return err
}

// GetByDeviceID returns the current posture record for a specific device.
// Returns nil, nil when the device is unknown.
func (r *DeviceFactsRepository) GetByDeviceID(ctx context.Context, orgID uuid.UUID, deviceID string) (*DeviceFact, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, org_id, device_id, user_id, platform, facts, last_seen_at, created_at
		  FROM device_facts
		 WHERE org_id = $1 AND device_id = $2`,
		orgID, deviceID,
	)
	df := &DeviceFact{}
	if err := row.Scan(&df.ID, &df.OrgID, &df.DeviceID, &df.UserID, &df.Platform, &df.Facts, &df.LastSeenAt, &df.CreatedAt); err != nil {
		return nil, nil // not found
	}
	return df, nil
}

// GetByUserID returns all devices last seen for a user in the org.
func (r *DeviceFactsRepository) GetByUserID(ctx context.Context, orgID, userID uuid.UUID) ([]*DeviceFact, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, device_id, user_id, platform, facts, last_seen_at, created_at
		  FROM device_facts
		 WHERE org_id = $1 AND user_id = $2
		 ORDER BY last_seen_at DESC`,
		orgID, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*DeviceFact
	for rows.Next() {
		df := &DeviceFact{}
		if err := rows.Scan(&df.ID, &df.OrgID, &df.DeviceID, &df.UserID, &df.Platform, &df.Facts, &df.LastSeenAt, &df.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, df)
	}
	return out, rows.Err()
}
