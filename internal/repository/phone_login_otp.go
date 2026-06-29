package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PhoneLoginOTPRepository manages short-lived OTP codes for first-factor
// phone number login.  It mirrors the design of EmailOTPRepository but keys
// records on (org_id, phone) instead of (org_id, email) and stores the code
// in the phone_login_otps table so as not to conflict with the MFA flow that
// uses phone_otp_codes.
type PhoneLoginOTPRepository struct {
	pool *pgxpool.Pool
}

// NewPhoneLoginOTPRepository creates a new PhoneLoginOTPRepository.
func NewPhoneLoginOTPRepository(pool *pgxpool.Pool) *PhoneLoginOTPRepository {
	return &PhoneLoginOTPRepository{pool: pool}
}

// Create generates a new 6-digit OTP for the given phone number, stores its
// SHA-256 hash, and returns the plaintext code.  Any previous unused codes
// for the same org+phone are invalidated first.
func (r *PhoneLoginOTPRepository) Create(
	ctx context.Context,
	orgID uuid.UUID,
	phone, loginSessionID string,
	ttl time.Duration,
) (string, error) {
	code, err := generateSixDigitCode() // reused from email_otp.go
	if err != nil {
		return "", fmt.Errorf("generate phone otp: %w", err)
	}
	hash := hashPhoneLoginOTP(code)

	// Invalidate old unused codes for this org+phone to limit accumulation.
	_, _ = r.pool.Exec(ctx, `
		DELETE FROM phone_login_otps
		WHERE org_id = $1 AND phone = $2 AND used_at IS NULL
	`, orgID, phone)

	_, err = r.pool.Exec(ctx, `
		INSERT INTO phone_login_otps (org_id, phone, code_hash, login_session_id, expires_at)
		VALUES ($1, $2, $3, $4, NOW() + $5::interval)
	`, orgID, phone, hash, loginSessionID, ttl.String())
	if err != nil {
		return "", fmt.Errorf("insert phone login otp: %w", err)
	}
	return code, nil
}

// Consume validates the plaintext code for the given org+phone and marks it
// used (one-time consumption).  Returns the login_session_id on success, or
// an empty string if the code is invalid or expired.
func (r *PhoneLoginOTPRepository) Consume(
	ctx context.Context,
	orgID uuid.UUID,
	phone, code, loginSessionID string,
) (string, error) {
	hash := hashPhoneLoginOTP(code)
	var sessionID string
	err := r.pool.QueryRow(ctx, `
		UPDATE phone_login_otps
		SET    used_at = NOW()
		WHERE  org_id    = $1
		  AND  phone     = $2
		  AND  code_hash = $3
		  AND  login_session_id = $4
		  AND  used_at   IS NULL
		  AND  expires_at > NOW()
		RETURNING login_session_id
	`, orgID, phone, hash, loginSessionID).Scan(&sessionID)
	if err != nil {
		return "", nil // treat any DB error as invalid code
	}
	return sessionID, nil
}

func hashPhoneLoginOTP(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
