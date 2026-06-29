package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MFACredentialWithMeta is like models.MFACredential but includes the
// is_imported column added in migration 000086.
type MFACredentialWithMeta struct {
	ID         uuid.UUID              `db:"id"`
	UserID     uuid.UUID              `db:"user_id"`
	Type       string                 `db:"type"`
	Name       string                 `db:"name"`
	Data       map[string]interface{} `db:"data"`
	IsPrimary  bool                   `db:"is_primary"`
	IsImported bool                   `db:"is_imported"`
	CreatedAt  time.Time              `db:"created_at"`
	LastUsedAt *time.Time             `db:"last_used_at"`
}

// MFARepository handles MFA credential persistence.
type MFARepository struct {
	pool *pgxpool.Pool
}

func NewMFARepository(pool *pgxpool.Pool) *MFARepository {
	return &MFARepository{pool: pool}
}

func (r *MFARepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.MFACredential, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, type, name, is_primary, created_at, last_used_at
		FROM mfa_credentials WHERE user_id = $1 ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []*models.MFACredential
	for rows.Next() {
		cr := &models.MFACredential{}
		if err := rows.Scan(&cr.ID, &cr.UserID, &cr.Type, &cr.Name, &cr.IsPrimary, &cr.CreatedAt, &cr.LastUsedAt); err != nil {
			return nil, err
		}
		creds = append(creds, cr)
	}
	return creds, rows.Err()
}

func (r *MFARepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM mfa_credentials WHERE id = $1`, id)
	return err
}

// DeleteForUserInOrg removes a credential only when it belongs to userID and that
// user belongs to orgID. mfa_credentials has no org_id column, so the tenant
// boundary is enforced via the users table. Returns pgx.ErrNoRows on mismatch —
// admin handlers MUST use this instead of Delete to avoid cross-tenant deletion.
func (r *MFARepository) DeleteForUserInOrg(ctx context.Context, credID, userID, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM mfa_credentials
		WHERE id = $1 AND user_id = $2
		  AND EXISTS (SELECT 1 FROM users WHERE id = $2 AND org_id = $3)`,
		credID, userID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// UpdateLastUsed stamps the current time on the credential. Called after a
// successful WebAuthn login so the self-service device list shows "last used".
func (r *MFARepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE mfa_credentials SET last_used_at = NOW() WHERE id = $1
	`, id)
	return err
}

// CountConfirmedByUser returns the number of confirmed MFA credentials for a user.
// Used to enforce MFA policy: prevent deletion of the last credential when MFA is required.
func (r *MFARepository) CountConfirmedByUser(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM mfa_credentials
		WHERE user_id = $1
		  AND (type != 'totp' OR (data->>'confirmed')::boolean = TRUE)
	`, userID).Scan(&n)
	return n, err
}

// CreateTOTP stores a new (unconfirmed) TOTP credential.
// data must contain at least {"secret": "<base32>"}.
func (r *MFARepository) CreateTOTP(ctx context.Context, userID uuid.UUID, name string, data map[string]interface{}) (*models.MFACredential, error) {
	cr := &models.MFACredential{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO mfa_credentials (user_id, type, name, data)
		VALUES ($1, 'totp', $2, $3)
		RETURNING id, user_id, type, name, is_primary, created_at
	`, userID, name, data).Scan(&cr.ID, &cr.UserID, &cr.Type, &cr.Name, &cr.IsPrimary, &cr.CreatedAt)
	return cr, err
}

// GetWithData loads a credential including the sensitive data field (for verification).
func (r *MFARepository) GetWithData(ctx context.Context, id uuid.UUID) (*models.MFACredential, error) {
	cr := &models.MFACredential{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, type, name, data, is_primary, created_at
		FROM mfa_credentials WHERE id = $1
	`, id).Scan(&cr.ID, &cr.UserID, &cr.Type, &cr.Name, &cr.Data, &cr.IsPrimary, &cr.CreatedAt)
	return cr, err
}

// SetTOTPConfirmed marks a pending TOTP credential as confirmed.
// If the user has no primary credential yet, this one becomes primary.
func (r *MFARepository) SetTOTPConfirmed(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE mfa_credentials SET
			data       = data || '{"confirmed": true}'::jsonb,
			is_primary = CASE
				WHEN NOT EXISTS (
					SELECT 1 FROM mfa_credentials
					WHERE user_id = (SELECT user_id FROM mfa_credentials WHERE id = $1)
					  AND is_primary = TRUE
				) THEN TRUE
				ELSE FALSE
			END
		WHERE id = $1 AND type = 'totp'
	`, id)
	return err
}

// DeletePendingTOTP removes any unconfirmed TOTP credentials for a user,
// allowing a clean re-enroll.
func (r *MFARepository) DeletePendingTOTP(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		DELETE FROM mfa_credentials
		WHERE user_id = $1 AND type = 'totp'
		  AND (data->>'confirmed')::boolean IS NOT TRUE
	`, userID)
	return err
}

// CreateWebAuthn stores a confirmed WebAuthn credential.
func (r *MFARepository) CreateWebAuthn(ctx context.Context, userID uuid.UUID, name string, data map[string]interface{}) (*models.MFACredential, error) {
	// Mark as primary if the user has no primary credential yet.
	cr := &models.MFACredential{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO mfa_credentials (user_id, type, name, data, is_primary)
		VALUES (
			$1, 'webauthn', $2, $3,
			NOT EXISTS (
				SELECT 1 FROM mfa_credentials WHERE user_id = $1 AND is_primary = TRUE
			)
		)
		RETURNING id, user_id, type, name, is_primary, created_at
	`, userID, name, data).Scan(&cr.ID, &cr.UserID, &cr.Type, &cr.Name, &cr.IsPrimary, &cr.CreatedAt)
	return cr, err
}

// ListWebAuthnByUser returns all WebAuthn credentials for a user, including raw data,
// needed to build the exclusion list during BeginRegistration.
func (r *MFARepository) ListWebAuthnByUser(ctx context.Context, userID uuid.UUID) ([]*models.MFACredential, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, type, name, data, is_primary, created_at
		FROM mfa_credentials WHERE user_id = $1 AND type = 'webauthn' ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []*models.MFACredential
	for rows.Next() {
		cr := &models.MFACredential{}
		if err := rows.Scan(&cr.ID, &cr.UserID, &cr.Type, &cr.Name, &cr.Data, &cr.IsPrimary, &cr.CreatedAt); err != nil {
			return nil, err
		}
		creds = append(creds, cr)
	}
	return creds, rows.Err()
}

// GetWebAuthnByCredentialID finds the WebAuthn credential whose JSON data contains
// the given base64url-encoded credential ID. Used during discoverable (passkey) login
// when the user identity is not known up-front.
func (r *MFARepository) GetWebAuthnByCredentialID(ctx context.Context, rawID []byte) (*models.MFACredential, error) {
	b64id := base64.RawURLEncoding.EncodeToString(rawID)
	cr := &models.MFACredential{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, type, name, data, is_primary, created_at
		FROM mfa_credentials
		WHERE type = 'webauthn' AND data->>'id' = $1
		LIMIT 1
	`, b64id).Scan(&cr.ID, &cr.UserID, &cr.Type, &cr.Name, &cr.Data, &cr.IsPrimary, &cr.CreatedAt)
	return cr, err
}

// ListPasskeysByUser returns credentials where is_passkey=true for CXF export.
// It also returns last_used_at for the export metadata.
func (r *MFARepository) ListPasskeysByUser(ctx context.Context, userID uuid.UUID) ([]*models.MFACredential, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, type, name, data, is_primary, created_at, last_used_at
		FROM mfa_credentials
		WHERE user_id = $1 AND type = 'webauthn' AND (data->>'is_passkey')::boolean = true
		ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []*models.MFACredential
	for rows.Next() {
		cr := &models.MFACredential{}
		if err := rows.Scan(&cr.ID, &cr.UserID, &cr.Type, &cr.Name, &cr.Data, &cr.IsPrimary, &cr.CreatedAt, &cr.LastUsedAt); err != nil {
			return nil, err
		}
		creds = append(creds, cr)
	}
	return creds, rows.Err()
}

// ImportWebAuthn stores a passkey credential that was imported via CXF (no live ceremony).
// The is_imported column is set to TRUE to distinguish it from ceremony-registered passkeys.
func (r *MFARepository) ImportWebAuthn(ctx context.Context, userID uuid.UUID, name string, data map[string]interface{}) (*models.MFACredential, error) {
	cr := &models.MFACredential{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO mfa_credentials (user_id, type, name, data, is_primary, is_imported)
		VALUES (
			$1, 'webauthn', $2, $3,
			NOT EXISTS (
				SELECT 1 FROM mfa_credentials WHERE user_id = $1 AND is_primary = TRUE
			),
			TRUE
		)
		RETURNING id, user_id, type, name, is_primary, created_at
	`, userID, name, data).Scan(&cr.ID, &cr.UserID, &cr.Type, &cr.Name, &cr.IsPrimary, &cr.CreatedAt)
	return cr, err
}

// ListPasskeysByUserWithMeta returns all passkeys for a user including the
// is_imported flag and last_used_at, used for CXF export and the UI list.
func (r *MFARepository) ListPasskeysByUserWithMeta(ctx context.Context, userID uuid.UUID) ([]*MFACredentialWithMeta, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, type, name, data, is_primary, is_imported, created_at, last_used_at
		FROM mfa_credentials
		WHERE user_id = $1 AND type = 'webauthn' AND (data->>'is_passkey')::boolean = true
		ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []*MFACredentialWithMeta
	for rows.Next() {
		cr := &MFACredentialWithMeta{}
		if err := rows.Scan(&cr.ID, &cr.UserID, &cr.Type, &cr.Name, &cr.Data,
			&cr.IsPrimary, &cr.IsImported, &cr.CreatedAt, &cr.LastUsedAt); err != nil {
			return nil, err
		}
		creds = append(creds, cr)
	}
	return creds, rows.Err()
}

// DeletePasskeyByIDAndUser deletes a passkey credential only if it belongs to userID,
// preventing users from deleting other users' credentials.
func (r *MFARepository) DeletePasskeyByIDAndUser(ctx context.Context, credID, userID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM mfa_credentials
		WHERE id = $1 AND user_id = $2 AND type = 'webauthn'
	`, credID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("passkey not found")
	}
	return nil
}

// ── TOTP backup codes ─────────────────────────────────────────────────────────

const backupCodeCount = 10

// GenerateBackupCodes creates 10 fresh one-time recovery codes for userID,
// replacing any previous ones. Returns the plain-text codes (shown once only).
func (r *MFARepository) GenerateBackupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	// Revoke all existing codes for the user (re-enrollment).
	if _, err := r.pool.Exec(ctx, `DELETE FROM totp_backup_codes WHERE user_id = $1`, userID); err != nil {
		return nil, err
	}

	plains := make([]string, backupCodeCount)
	for i := range plains {
		buf := make([]byte, 6) // 48 bits → 8-char base32ish
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("generate backup code: %w", err)
		}
		// Format as XXXX-XXXX using hex for easy readability.
		h := hex.EncodeToString(buf) // 12 hex chars
		plains[i] = h[:6] + "-" + h[6:] // e.g. "a3f9c1-7d4e82"
	}

	// Bulk insert hashes.
	batch := &pgx.Batch{}
	for _, p := range plains {
		hash := sha256sum(p)
		batch.Queue(`INSERT INTO totp_backup_codes (user_id, code_hash) VALUES ($1, $2)`, userID, hash)
	}
	br := r.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range plains {
		if _, err := br.Exec(); err != nil {
			return nil, err
		}
	}
	return plains, nil
}

// ConsumeBackupCode checks whether plain matches a stored backup code for userID
// and, if so, marks it used and returns true. Returns false when no match is found.
func (r *MFARepository) ConsumeBackupCode(ctx context.Context, userID uuid.UUID, plain string) (bool, error) {
	hash := sha256sum(plain)
	tag, err := r.pool.Exec(ctx, `
		UPDATE totp_backup_codes
		SET used_at = NOW()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
	`, userID, hash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func sha256sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
