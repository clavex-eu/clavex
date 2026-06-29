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

// UserPhone holds a verified phone number for a user.
type UserPhone struct {
	ID         uuid.UUID `db:"id"          json:"id"`
	UserID     uuid.UUID `db:"user_id"     json:"user_id"`
	Phone      string    `db:"phone"       json:"phone"`
	IsVerified bool      `db:"is_verified" json:"is_verified"`
	CreatedAt  time.Time `db:"created_at"  json:"created_at"`
}

// PhoneRepository manages phone numbers and OTP codes.
type PhoneRepository struct {
	pool *pgxpool.Pool
}

func NewPhoneRepository(pool *pgxpool.Pool) *PhoneRepository {
	return &PhoneRepository{pool: pool}
}

func (r *PhoneRepository) UpsertPhone(ctx context.Context, userID uuid.UUID, phone string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO user_phone_numbers (user_id, phone)
		VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET phone = $2, is_verified = FALSE, updated_at = NOW()
	`, userID, phone)
	return err
}

func (r *PhoneRepository) GetPhone(ctx context.Context, userID uuid.UUID) (*UserPhone, error) {
	p := &UserPhone{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, phone, is_verified, created_at
		FROM user_phone_numbers WHERE user_id = $1
	`, userID).Scan(&p.ID, &p.UserID, &p.Phone, &p.IsVerified, &p.CreatedAt)
	return p, err
}

func (r *PhoneRepository) MarkVerified(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE user_phone_numbers SET is_verified = TRUE WHERE user_id = $1`, userID)
	return err
}

// CreateOTP issues a new OTP code. Returns (rawCode, error).
func (r *PhoneRepository) CreateOTP(ctx context.Context, userID uuid.UUID, purpose string, ttl time.Duration) (string, error) {
	raw, err := generateNumericOTP(6)
	if err != nil {
		return "", err
	}
	hash := hashOTP(raw)
	// Invalidate previous OTPs of same purpose
	_, _ = r.pool.Exec(ctx, `
		UPDATE phone_otp_codes SET used_at = NOW()
		WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL
	`, userID, purpose)
	_, err = r.pool.Exec(ctx, `
		INSERT INTO phone_otp_codes (user_id, code_hash, purpose, expires_at)
		VALUES ($1, $2, $3, NOW() + $4::interval)
	`, userID, hash, purpose, ttl.String())
	return raw, err
}

// VerifyOTP checks an OTP and marks it used if valid.
func (r *PhoneRepository) VerifyOTP(ctx context.Context, userID uuid.UUID, rawCode, purpose string) (bool, error) {
	hash := hashOTP(rawCode)
	tag, err := r.pool.Exec(ctx, `
		UPDATE phone_otp_codes
		SET used_at = NOW()
		WHERE user_id = $1 AND code_hash = $2 AND purpose = $3
		  AND used_at IS NULL AND expires_at > NOW()
	`, userID, hash, purpose)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func generateNumericOTP(digits int) (string, error) {
	const digs = "0123456789"
	out := make([]byte, digits)
	for i := range out {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		out[i] = digs[int(b[0])%10]
	}
	return string(out), nil
}

func hashOTP(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// OrgSMSSettings holds per-org SMS provider configuration.
type OrgSMSSettings struct {
	OrgID    uuid.UUID              `db:"org_id"    json:"org_id"`
	Provider string                 `db:"provider"  json:"provider"`
	Config   map[string]interface{} `db:"config"    json:"config"`
	IsActive bool                   `db:"is_active" json:"is_active"`
}

// SMSSettingsRepository manages org SMS settings.
type SMSSettingsRepository struct {
	pool *pgxpool.Pool
}

func NewSMSSettingsRepository(pool *pgxpool.Pool) *SMSSettingsRepository {
	return &SMSSettingsRepository{pool: pool}
}

func (r *SMSSettingsRepository) Get(ctx context.Context, orgID uuid.UUID) (*OrgSMSSettings, error) {
	s := &OrgSMSSettings{}
	err := r.pool.QueryRow(ctx, `
		SELECT org_id, provider, config, is_active FROM org_sms_settings WHERE org_id = $1
	`, orgID).Scan(&s.OrgID, &s.Provider, &s.Config, &s.IsActive)
	return s, err
}

func (r *SMSSettingsRepository) Upsert(ctx context.Context, orgID uuid.UUID, provider string, config map[string]interface{}, active bool) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO org_sms_settings (org_id, provider, config, is_active)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (org_id) DO UPDATE
		  SET provider = $2, config = $3, is_active = $4, updated_at = NOW()
	`, orgID, provider, config, active)
	return err
}

// SMSSettingsError is returned when SMS is not configured for an org.
type SMSSettingsError struct{ OrgID uuid.UUID }

func (e *SMSSettingsError) Error() string {
	return fmt.Sprintf("sms not configured for org %s", e.OrgID)
}
