package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CIBADeviceToken is a push token registered by a user's mobile device.
type CIBADeviceToken struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	UserID      uuid.UUID
	Platform    string // "apns" or "fcm"
	DeviceToken string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CIBAPushTokenRepository manages the ciba_device_tokens table.
type CIBAPushTokenRepository struct {
	pool *pgxpool.Pool
}

// NewCIBAPushTokenRepository creates a new CIBAPushTokenRepository.
func NewCIBAPushTokenRepository(pool *pgxpool.Pool) *CIBAPushTokenRepository {
	return &CIBAPushTokenRepository{pool: pool}
}

// Register inserts a new device token (or refreshes updated_at on conflict).
// Returns the stored token row.
func (r *CIBAPushTokenRepository) Register(ctx context.Context, orgID, userID uuid.UUID, platform, deviceToken string) (*CIBADeviceToken, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO ciba_device_tokens (org_id, user_id, platform, device_token)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (org_id, user_id, platform, device_token)
		DO UPDATE SET updated_at = NOW()
		RETURNING id, org_id, user_id, platform, device_token, created_at, updated_at
	`, orgID, userID, platform, deviceToken)

	dt := &CIBADeviceToken{}
	err := row.Scan(&dt.ID, &dt.OrgID, &dt.UserID, &dt.Platform, &dt.DeviceToken, &dt.CreatedAt, &dt.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return dt, nil
}

// ListForUser returns all registered push tokens for a user within an org.
func (r *CIBAPushTokenRepository) ListForUser(ctx context.Context, orgID, userID uuid.UUID) ([]*CIBADeviceToken, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, user_id, platform, device_token, created_at, updated_at
		FROM ciba_device_tokens
		WHERE org_id = $1 AND user_id = $2
		ORDER BY updated_at DESC
	`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*CIBADeviceToken
	for rows.Next() {
		dt := &CIBADeviceToken{}
		if err := rows.Scan(&dt.ID, &dt.OrgID, &dt.UserID, &dt.Platform, &dt.DeviceToken, &dt.CreatedAt, &dt.UpdatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, dt)
	}
	return tokens, rows.Err()
}

// ListForOrg returns all registered push tokens for an entire org (admin use).
func (r *CIBAPushTokenRepository) ListForOrg(ctx context.Context, orgID uuid.UUID) ([]*CIBADeviceToken, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, user_id, platform, device_token, created_at, updated_at
		FROM ciba_device_tokens
		WHERE org_id = $1
		ORDER BY updated_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*CIBADeviceToken
	for rows.Next() {
		dt := &CIBADeviceToken{}
		if err := rows.Scan(&dt.ID, &dt.OrgID, &dt.UserID, &dt.Platform, &dt.DeviceToken, &dt.CreatedAt, &dt.UpdatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, dt)
	}
	return tokens, rows.Err()
}

// GetByID retrieves a single token by its UUID.
func (r *CIBAPushTokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*CIBADeviceToken, error) {
	dt := &CIBADeviceToken{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, user_id, platform, device_token, created_at, updated_at
		FROM ciba_device_tokens WHERE id = $1
	`, id).Scan(&dt.ID, &dt.OrgID, &dt.UserID, &dt.Platform, &dt.DeviceToken, &dt.CreatedAt, &dt.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return dt, nil
}

// DeleteByID deletes a token by its UUID. Returns (true, nil) if deleted.
func (r *CIBAPushTokenRepository) DeleteByID(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM ciba_device_tokens WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteByToken deletes a specific device token string for a user.
func (r *CIBAPushTokenRepository) DeleteByToken(ctx context.Context, orgID, userID uuid.UUID, platform, deviceToken string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM ciba_device_tokens
		WHERE org_id = $1 AND user_id = $2 AND platform = $3 AND device_token = $4
	`, orgID, userID, platform, deviceToken)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
