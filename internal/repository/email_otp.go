package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EmailOTPRepository manages short-lived email OTP codes.
type EmailOTPRepository struct {
	pool *pgxpool.Pool
}

// NewEmailOTPRepository creates a new EmailOTPRepository.
func NewEmailOTPRepository(pool *pgxpool.Pool) *EmailOTPRepository {
	return &EmailOTPRepository{pool: pool}
}

// Create generates a new 6-digit OTP, stores its hash, and returns the plaintext code.
// Any previous unused codes for the same org+email are deleted first (rate limiting
// must be enforced by the caller before invoking Create).
func (r *EmailOTPRepository) Create(ctx context.Context, orgID uuid.UUID, email, loginSessionID string, userID *uuid.UUID, ttl time.Duration) (string, error) {
	code, err := generateSixDigitCode()
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}
	hash := hashEmailOTP(code)

	// Invalidate existing codes for this org+email to prevent accumulation.
	_, _ = r.pool.Exec(ctx, `
		DELETE FROM email_otp_codes
		WHERE org_id = $1 AND email = $2 AND used_at IS NULL
	`, orgID, email)

	_, err = r.pool.Exec(ctx, `
		INSERT INTO email_otp_codes (org_id, email, user_id, code_hash, purpose, login_session_id, expires_at)
		VALUES ($1, $2, $3, $4, 'login', $5, NOW() + $6::interval)
	`, orgID, email, userID, hash, loginSessionID, ttl.String())
	if err != nil {
		return "", fmt.Errorf("insert email otp: %w", err)
	}
	return code, nil
}

// Consume checks the code for the given org+email and marks it as used.
// Returns the login_session_id on success, or an empty string if invalid/expired.
// loginSessionID binds the code to the exact login session it was issued for,
// so a code cannot be consumed by a different concurrent session for the same
// address.
func (r *EmailOTPRepository) Consume(ctx context.Context, orgID uuid.UUID, email, code, loginSessionID string) (string, error) {
	hash := hashEmailOTP(code)
	var sessionID string
	err := r.pool.QueryRow(ctx, `
		UPDATE email_otp_codes
		SET    used_at = NOW()
		WHERE  org_id  = $1
		  AND  email   = $2
		  AND  code_hash = $3
		  AND  login_session_id = $4
		  AND  used_at IS NULL
		  AND  expires_at > NOW()
		RETURNING login_session_id
	`, orgID, email, hash, loginSessionID).Scan(&sessionID)
	if err != nil {
		return "", nil // treat any error as invalid code
	}
	return sessionID, nil
}

// generateSixDigitCode returns a cryptographically random 6-digit string (000000–999999).
func generateSixDigitCode() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Use only 20 bits to stay evenly distributed in [0, 1_000_000).
	n := (uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])) % 1_000_000
	return fmt.Sprintf("%06d", n), nil
}

// hashEmailOTP returns the SHA-256 hex digest of a plaintext OTP code.
func hashEmailOTP(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
