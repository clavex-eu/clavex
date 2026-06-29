package repository

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TrustedDeviceRepository manages device trust records.
type TrustedDeviceRepository struct {
	pool *pgxpool.Pool
}

func NewTrustedDeviceRepository(pool *pgxpool.Pool) *TrustedDeviceRepository {
	return &TrustedDeviceRepository{pool: pool}
}

// FingerprintHash computes HMAC-SHA256(secret, deviceToken+":"+userID).
// The secret comes from config.Auth.DeviceTrustSecret.
func FingerprintHash(secret, deviceToken string, userID uuid.UUID) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(deviceToken + ":" + userID.String()))
	return hex.EncodeToString(mac.Sum(nil))
}

// IsTrusted returns true if the given fingerprint is registered as trusted for
// this user in this org.  Also bumps last_seen_at on a hit.
func (r *TrustedDeviceRepository) IsTrusted(ctx context.Context, orgID, userID uuid.UUID, fingerprintHash string) bool {
	tag, err := r.pool.Exec(ctx, `
		UPDATE trusted_devices
		   SET last_seen_at = NOW()
		 WHERE org_id = $1 AND user_id = $2 AND fingerprint_hash = $3
	`, orgID, userID, fingerprintHash)
	return err == nil && tag.RowsAffected() > 0
}

// Trust registers a device as trusted.  Idempotent — upserts on conflict.
func (r *TrustedDeviceRepository) Trust(ctx context.Context, orgID, userID uuid.UUID, fingerprintHash, displayName, userAgent, ipAddr string) error {
	var dn *string
	if displayName != "" {
		dn = &displayName
	}
	var ua *string
	if userAgent != "" {
		ua = &userAgent
	}
	var ip *string
	if ipAddr != "" {
		ip = &ipAddr
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO trusted_devices (org_id, user_id, fingerprint_hash, display_name, user_agent, last_ip)
		VALUES ($1, $2, $3, $4, $5, $6::inet)
		ON CONFLICT (org_id, user_id, fingerprint_hash)
		DO UPDATE SET last_seen_at = NOW(), display_name = EXCLUDED.display_name,
		              user_agent = EXCLUDED.user_agent, last_ip = EXCLUDED.last_ip
	`, orgID, userID, fingerprintHash, dn, ua, ip)
	return err
}

// ListByUser returns all trusted devices for a user.
func (r *TrustedDeviceRepository) ListByUser(ctx context.Context, orgID, userID uuid.UUID) ([]*models.TrustedDevice, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, user_id, fingerprint_hash, display_name, user_agent, last_ip::text, last_seen_at, created_at
		  FROM trusted_devices
		 WHERE org_id = $1 AND user_id = $2
		 ORDER BY last_seen_at DESC
	`, orgID, userID)
	if err != nil {
		return nil, fmt.Errorf("list trusted devices: %w", err)
	}
	defer rows.Close()
	var out []*models.TrustedDevice
	for rows.Next() {
		d := &models.TrustedDevice{}
		if err := rows.Scan(&d.ID, &d.OrgID, &d.UserID, &d.FingerprintHash, &d.DisplayName, &d.UserAgent, &d.LastIP, &d.LastSeenAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Revoke removes a specific trusted device by ID.
func (r *TrustedDeviceRepository) Revoke(ctx context.Context, orgID, userID, deviceID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM trusted_devices WHERE id = $1 AND org_id = $2 AND user_id = $3
	`, deviceID, orgID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("device not found")
	}
	return nil
}

// RevokeAllForUser removes all trusted devices for a user (e.g., on password reset).
func (r *TrustedDeviceRepository) RevokeAllForUser(ctx context.Context, orgID, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		DELETE FROM trusted_devices WHERE org_id = $1 AND user_id = $2
	`, orgID, userID)
	return err
}

// DeviceTrustCookieName is the name of the cookie that holds the device token.
const DeviceTrustCookieName = "clavex_dtrust"

// DeviceTrustCookieTTL is how long the device trust cookie lasts.
const DeviceTrustCookieTTL = 90 * 24 * time.Hour
