package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DeviceCode represents a pending RFC 8628 device authorization.
type DeviceCode struct {
	ID           uuid.UUID  `db:"id"              json:"id"`
	OrgID        uuid.UUID  `db:"org_id"          json:"org_id"`
	ClientID     string     `db:"client_id"       json:"client_id"`
	UserCode     string     `db:"user_code"       json:"user_code"`
	Scope        string     `db:"scope"           json:"scope"`
	IsAuthorized *bool      `db:"is_authorized"   json:"is_authorized"`
	UserID       *uuid.UUID `db:"user_id"         json:"user_id,omitempty"`
	ExpiresAt    time.Time  `db:"expires_at"      json:"expires_at"`
	LastPolledAt *time.Time `db:"last_polled_at"  json:"last_polled_at,omitempty"`
	PollInterval int        `db:"poll_interval"   json:"poll_interval"`
	CreatedAt    time.Time  `db:"created_at"      json:"created_at"`
}

// DeviceCodeRepository manages RFC 8628 device codes.
type DeviceCodeRepository struct {
	pool *pgxpool.Pool
}

func NewDeviceCodeRepository(pool *pgxpool.Pool) *DeviceCodeRepository {
	return &DeviceCodeRepository{pool: pool}
}

// Create issues a new device+user code pair and returns (record, rawDeviceCode).
func (r *DeviceCodeRepository) Create(ctx context.Context, orgID uuid.UUID, clientID, scope string, ttl time.Duration) (*DeviceCode, string, error) {
	rawDevice, err := generateDeviceCode()
	if err != nil {
		return nil, "", err
	}
	deviceHash := hashDeviceCode(rawDevice)
	userCode, err := generateUserCode()
	if err != nil {
		return nil, "", err
	}
	dc := &DeviceCode{}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO device_codes (org_id, client_id, device_code_hash, user_code, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, NOW() + $6::interval)
		RETURNING id, org_id, client_id, user_code, scope, is_authorized, user_id,
		          expires_at, last_polled_at, poll_interval, created_at
	`, orgID, clientID, deviceHash, userCode, scope, ttl.String()).Scan(
		&dc.ID, &dc.OrgID, &dc.ClientID, &dc.UserCode, &dc.Scope,
		&dc.IsAuthorized, &dc.UserID, &dc.ExpiresAt, &dc.LastPolledAt, &dc.PollInterval, &dc.CreatedAt,
	)
	return dc, rawDevice, err
}

// GetByDeviceCode fetches a device code record by raw device code.
func (r *DeviceCodeRepository) GetByDeviceCode(ctx context.Context, rawDevice string) (*DeviceCode, error) {
	hash := hashDeviceCode(rawDevice)
	dc := &DeviceCode{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, client_id, user_code, scope, is_authorized, user_id,
		       expires_at, last_polled_at, poll_interval, created_at
		FROM device_codes WHERE device_code_hash = $1
	`, hash).Scan(
		&dc.ID, &dc.OrgID, &dc.ClientID, &dc.UserCode, &dc.Scope,
		&dc.IsAuthorized, &dc.UserID, &dc.ExpiresAt, &dc.LastPolledAt, &dc.PollInterval, &dc.CreatedAt,
	)
	return dc, err
}

// GetByID fetches a device code record by its primary key.
func (r *DeviceCodeRepository) GetByID(ctx context.Context, id uuid.UUID) (*DeviceCode, error) {
	dc := &DeviceCode{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, client_id, user_code, scope, is_authorized, user_id,
		       expires_at, last_polled_at, poll_interval, created_at
		FROM device_codes WHERE id = $1
	`, id).Scan(
		&dc.ID, &dc.OrgID, &dc.ClientID, &dc.UserCode, &dc.Scope,
		&dc.IsAuthorized, &dc.UserID, &dc.ExpiresAt, &dc.LastPolledAt, &dc.PollInterval, &dc.CreatedAt,
	)
	return dc, err
}

// GetByUserCode fetches a device code record by user code (what the user types in the browser).
func (r *DeviceCodeRepository) GetByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	dc := &DeviceCode{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, client_id, user_code, scope, is_authorized, user_id,
		       expires_at, last_polled_at, poll_interval, created_at
		FROM device_codes WHERE user_code = $1
	`, strings.ToUpper(userCode)).Scan(
		&dc.ID, &dc.OrgID, &dc.ClientID, &dc.UserCode, &dc.Scope,
		&dc.IsAuthorized, &dc.UserID, &dc.ExpiresAt, &dc.LastPolledAt, &dc.PollInterval, &dc.CreatedAt,
	)
	return dc, err
}

// Authorize marks the device code as authorized by a user.
func (r *DeviceCodeRepository) Authorize(ctx context.Context, id, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE device_codes SET is_authorized = TRUE, user_id = $2 WHERE id = $1
	`, id, userID)
	return err
}

// Deny marks the device code as denied.
func (r *DeviceCodeRepository) Deny(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE device_codes SET is_authorized = FALSE WHERE id = $1`, id)
	return err
}

// TouchPoll updates last_polled_at and enforces the minimum poll interval.
// Returns (tooFast bool, err error).  When tooFast is true, the caller MUST
// return slow_down to the client and call SlowDown to increase the interval.
func (r *DeviceCodeRepository) TouchPoll(ctx context.Context, id uuid.UUID, interval int) (tooFast bool, err error) {
	var last *time.Time
	err = r.pool.QueryRow(ctx, `
		UPDATE device_codes SET last_polled_at = NOW() WHERE id = $1
		RETURNING (SELECT last_polled_at FROM device_codes WHERE id = $1)
	`, id).Scan(&last)
	if err != nil {
		return false, err
	}
	if last != nil && time.Since(*last) < time.Duration(interval)*time.Second {
		return true, nil
	}
	return false, nil
}

// SlowDown increases poll_interval by 5 seconds for the given device code.
// Called when the client polls too fast (RFC 8628 §3.5).
func (r *DeviceCodeRepository) SlowDown(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE device_codes SET poll_interval = poll_interval + 5 WHERE id = $1
	`, id)
	return err
}

// Delete removes a device code record (after successful exchange).
func (r *DeviceCodeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM device_codes WHERE id = $1`, id)
	return err
}

func generateDeviceCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashDeviceCode(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// generateUserCode generates an 8-char uppercase alphanumeric user code (e.g. "BCDF-GHJK").
func generateUserCode() (string, error) {
	const chars = "BCDFGHJKLMNPQRSTVWXZ" // consonants only — easier to read
	const length = 8
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", fmt.Errorf("generateUserCode: %w", err)
		}
		b[i] = chars[n.Int64()]
	}
	return string(b[:4]) + "-" + string(b[4:]), nil
}
