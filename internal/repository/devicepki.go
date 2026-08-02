package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Errors ──────────────────────────────────────────────────────────────────

var (
	// ErrDeviceCANotConfigured is returned when the org has no Device CA config.
	ErrDeviceCANotConfigured = errors.New("device CA not configured")
	// ErrEnrollmentSecretNotFound is returned when no pending enrollment secret
	// exists for the given device.
	ErrEnrollmentSecretNotFound = errors.New("no pending enrollment secret for this device")
	// ErrEnrollmentSecretExpired is returned when the secret row exists but its
	// expiry has passed.
	ErrEnrollmentSecretExpired = errors.New("enrollment secret expired")
	// ErrEnrollmentSecretMismatch is returned when the presented secret does not
	// match the stored hash.
	ErrEnrollmentSecretMismatch = errors.New("enrollment secret does not match")
	// ErrDeviceNotFound is returned when a device row does not exist for the org.
	ErrDeviceNotFound = errors.New("device not found")
)

// ── Models ──────────────────────────────────────────────────────────────────

// DeviceCAConfig holds the Vault PKI Device CA configuration for an org.
// vault_addr and vault_role are required; encrypted_vault_token is stored
// encrypted and never returned in API responses.
type DeviceCAConfig struct {
	OrgID                     uuid.UUID `json:"org_id"`
	VaultAddr                 string    `json:"vault_addr"`
	VaultMount                string    `json:"vault_mount"`
	VaultRole                 string    `json:"vault_role"`
	CACertificatePEM          *string   `json:"ca_certificate_pem,omitempty"`
	CertTTLSeconds            int       `json:"cert_ttl_seconds"`
	RenewalWindowSeconds      int       `json:"renewal_window_seconds"`
	BootstrapSecretTTLSeconds int       `json:"bootstrap_secret_ttl_seconds"`
	RotationPolicy            string    `json:"rotation_policy"`
	RotationIntervalDays      *int      `json:"rotation_interval_days,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

// Device is a single IoT device identity, independent of any one certificate.
type Device struct {
	ID             uuid.UUID  `json:"id"`
	OrgID          uuid.UUID  `json:"org_id"`
	DeviceID       string     `json:"device_id"`
	FleetID        *string    `json:"fleet_id,omitempty"`
	Status         string     `json:"status"`
	LastEnrolledAt *time.Time `json:"last_enrolled_at,omitempty"`
	LastRenewedAt  *time.Time `json:"last_renewed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// DeviceCertificate is one issued (or once-issued) leaf certificate.
type DeviceCertificate struct {
	ID            uuid.UUID  `json:"id"`
	OrgID         uuid.UUID  `json:"org_id"`
	DeviceID      uuid.UUID  `json:"device_id"`
	SerialNumber  string     `json:"serial_number"`
	CN            string     `json:"cn"`
	NotBefore     time.Time  `json:"not_before"`
	NotAfter      time.Time  `json:"not_after"`
	Status        string     `json:"status"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason *string    `json:"revoked_reason,omitempty"`
	RevokedBy     *string    `json:"revoked_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// DeviceEnrollmentSecret is a one-time, per-device bootstrap secret. The raw
// value is never stored — only secret_hash (sha256 hex, looked up by exact
// match, same pattern as org_invitations.token_hash).
type DeviceEnrollmentSecret struct {
	ID        uuid.UUID  `json:"id"`
	OrgID     uuid.UUID  `json:"org_id"`
	DeviceID  uuid.UUID  `json:"device_id"`
	Status    string     `json:"status"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedBy *string    `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`

	// secretHash is populated only by LockPendingSecretForDeviceTx, for
	// VerifySecret to compare against — never marshalled to JSON.
	secretHash string
}

// Enrollment secret states.
const (
	EnrollmentSecretPending = "pending"
	EnrollmentSecretUsed    = "used"
	EnrollmentSecretRevoked = "revoked"
	EnrollmentSecretExpired = "expired"
)

// Device certificate states.
const (
	DeviceCertActive     = "active"
	DeviceCertSuperseded = "superseded"
	DeviceCertRevoked    = "revoked"
)

// Device states.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusActive   = "active"
	DeviceStatusRevoked  = "revoked"
	DeviceStatusDisabled = "disabled"
)

// ── Repository ──────────────────────────────────────────────────────────────

// DevicePKIRepository handles all Device CA database operations.
type DevicePKIRepository struct {
	pool *pgxpool.Pool
}

// NewDevicePKIRepository creates a new DevicePKIRepository.
func NewDevicePKIRepository(pool *pgxpool.Pool) *DevicePKIRepository {
	return &DevicePKIRepository{pool: pool}
}

// BeginTx starts a transaction on the underlying pool, for callers (the
// devicepki.Service) that need to span the enrollment-secret lock and the
// certificate-issuance bookkeeping in one atomic unit.
func (r *DevicePKIRepository) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return r.pool.Begin(ctx)
}

// ── device_ca_configs ─────────────────────────────────────────────────────

// GetDeviceCAConfig returns the org's Device CA config without the token.
func (r *DevicePKIRepository) GetDeviceCAConfig(ctx context.Context, orgID uuid.UUID) (*DeviceCAConfig, error) {
	const q = `SELECT org_id, vault_addr, vault_mount, vault_role, ca_certificate_pem,
		cert_ttl_seconds, renewal_window_seconds, bootstrap_secret_ttl_seconds,
		rotation_policy, rotation_interval_days, created_at, updated_at
		FROM device_ca_configs WHERE org_id=$1`
	var c DeviceCAConfig
	err := r.pool.QueryRow(ctx, q, orgID).Scan(
		&c.OrgID, &c.VaultAddr, &c.VaultMount, &c.VaultRole, &c.CACertificatePEM,
		&c.CertTTLSeconds, &c.RenewalWindowSeconds, &c.BootstrapSecretTTLSeconds,
		&c.RotationPolicy, &c.RotationIntervalDays, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &c, err
}

// GetDeviceCAConfigWithToken returns the full config including the encrypted
// Vault token.
func (r *DevicePKIRepository) GetDeviceCAConfigWithToken(ctx context.Context, orgID uuid.UUID) (*DeviceCAConfig, string, error) {
	const q = `SELECT org_id, vault_addr, encrypted_vault_token, vault_mount, vault_role,
		ca_certificate_pem, cert_ttl_seconds, renewal_window_seconds, bootstrap_secret_ttl_seconds,
		rotation_policy, rotation_interval_days, created_at, updated_at
		FROM device_ca_configs WHERE org_id=$1`
	var c DeviceCAConfig
	var encToken string
	err := r.pool.QueryRow(ctx, q, orgID).Scan(
		&c.OrgID, &c.VaultAddr, &encToken, &c.VaultMount, &c.VaultRole,
		&c.CACertificatePEM, &c.CertTTLSeconds, &c.RenewalWindowSeconds, &c.BootstrapSecretTTLSeconds,
		&c.RotationPolicy, &c.RotationIntervalDays, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrDeviceCANotConfigured
	}
	if err != nil {
		return nil, "", err
	}
	return &c, encToken, nil
}

// UpsertDeviceCAConfig creates or updates the Vault Device CA config for an org.
func (r *DevicePKIRepository) UpsertDeviceCAConfig(ctx context.Context, orgID uuid.UUID,
	vaultAddr, encryptedToken, vaultMount, vaultRole string,
	certTTLSeconds, renewalWindowSeconds, bootstrapSecretTTLSeconds int,
) error {
	const q = `
		INSERT INTO device_ca_configs
			(org_id, vault_addr, encrypted_vault_token, vault_mount, vault_role,
			 cert_ttl_seconds, renewal_window_seconds, bootstrap_secret_ttl_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (org_id) DO UPDATE SET
			vault_addr                   = EXCLUDED.vault_addr,
			encrypted_vault_token        = EXCLUDED.encrypted_vault_token,
			vault_mount                  = EXCLUDED.vault_mount,
			vault_role                   = EXCLUDED.vault_role,
			cert_ttl_seconds             = EXCLUDED.cert_ttl_seconds,
			renewal_window_seconds       = EXCLUDED.renewal_window_seconds,
			bootstrap_secret_ttl_seconds = EXCLUDED.bootstrap_secret_ttl_seconds,
			updated_at                   = NOW()`
	_, err := r.pool.Exec(ctx, q,
		orgID, vaultAddr, encryptedToken, vaultMount, vaultRole,
		certTTLSeconds, renewalWindowSeconds, bootstrapSecretTTLSeconds,
	)
	return err
}

// UpdateDeviceCACertificate caches the CA certificate fetched from Vault.
func (r *DevicePKIRepository) UpdateDeviceCACertificate(ctx context.Context, orgID uuid.UUID, certPEM string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE device_ca_configs SET ca_certificate_pem=$2, updated_at=NOW() WHERE org_id=$1`,
		orgID, certPEM,
	)
	return err
}

// DeleteDeviceCAConfig removes the Device CA config for an org.
func (r *DevicePKIRepository) DeleteDeviceCAConfig(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM device_ca_configs WHERE org_id=$1`, orgID)
	return err
}

// ListActiveCACertificates returns every org's cached Device CA certificate
// PEM (non-null only). Used to build the dedicated renewal mTLS listener's
// tls.Config.ClientCAs pool, which must accept a presented cert from ANY
// tenant's Device CA — the handler then re-verifies the specific tenant
// named in the cert's own CN (see devicepki.Service.VerifyPresentedCertForOrg).
func (r *DevicePKIRepository) ListActiveCACertificates(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT ca_certificate_pem FROM device_ca_configs WHERE ca_certificate_pem IS NOT NULL AND ca_certificate_pem != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var pem string
		if err := rows.Scan(&pem); err != nil {
			return nil, err
		}
		out = append(out, pem)
	}
	return out, rows.Err()
}

// ── devices ───────────────────────────────────────────────────────────────

// UpsertPendingDevice creates a device row in 'pending' status if none exists
// yet for (org_id, device_id), or returns the existing row unchanged. Used
// when an operator pre-registers a device ahead of physical provisioning.
func (r *DevicePKIRepository) UpsertPendingDevice(ctx context.Context, orgID uuid.UUID, deviceID string, fleetID *string) (*Device, error) {
	const q = `
		INSERT INTO devices (org_id, device_id, fleet_id)
		VALUES ($1,$2,$3)
		ON CONFLICT (org_id, device_id) DO UPDATE SET fleet_id = COALESCE(devices.fleet_id, EXCLUDED.fleet_id)
		RETURNING id, org_id, device_id, fleet_id, status, last_enrolled_at, last_renewed_at, created_at`
	var d Device
	err := r.pool.QueryRow(ctx, q, orgID, deviceID, fleetID).Scan(
		&d.ID, &d.OrgID, &d.DeviceID, &d.FleetID, &d.Status, &d.LastEnrolledAt, &d.LastRenewedAt, &d.CreatedAt,
	)
	return &d, err
}

// GetDeviceByExternalID looks up a device by its org-scoped external ID.
func (r *DevicePKIRepository) GetDeviceByExternalID(ctx context.Context, orgID uuid.UUID, deviceID string) (*Device, error) {
	const q = `SELECT id, org_id, device_id, fleet_id, status, last_enrolled_at, last_renewed_at, created_at
		FROM devices WHERE org_id=$1 AND device_id=$2`
	var d Device
	err := r.pool.QueryRow(ctx, q, orgID, deviceID).Scan(
		&d.ID, &d.OrgID, &d.DeviceID, &d.FleetID, &d.Status, &d.LastEnrolledAt, &d.LastRenewedAt, &d.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &d, err
}

// GetDevice looks up a device by its internal ID, scoped to org.
func (r *DevicePKIRepository) GetDevice(ctx context.Context, orgID, id uuid.UUID) (*Device, error) {
	const q = `SELECT id, org_id, device_id, fleet_id, status, last_enrolled_at, last_renewed_at, created_at
		FROM devices WHERE org_id=$1 AND id=$2`
	var d Device
	err := r.pool.QueryRow(ctx, q, orgID, id).Scan(
		&d.ID, &d.OrgID, &d.DeviceID, &d.FleetID, &d.Status, &d.LastEnrolledAt, &d.LastRenewedAt, &d.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &d, err
}

// MarkDeviceEnrolledTx transitions a device to 'active' and stamps
// last_enrolled_at, within the caller's transaction.
func (r *DevicePKIRepository) MarkDeviceEnrolledTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE devices SET status='active', last_enrolled_at=NOW() WHERE id=$1`, id)
	return err
}

// MarkDeviceRenewedTx stamps last_renewed_at, within the caller's transaction.
func (r *DevicePKIRepository) MarkDeviceRenewedTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE devices SET last_renewed_at=NOW() WHERE id=$1`, id)
	return err
}

// SetDeviceStatus sets a device's status directly (revoke/disable/reactivate).
func (r *DevicePKIRepository) SetDeviceStatus(ctx context.Context, orgID, id uuid.UUID, status string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE devices SET status=$3 WHERE org_id=$1 AND id=$2`, orgID, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

// ── device_enrollment_secrets ─────────────────────────────────────────────

// CreateEnrollmentSecret generates a fresh one-time secret for a device and
// stores only its hash. Returns the row and the raw secret (displayed once).
func (r *DevicePKIRepository) CreateEnrollmentSecret(ctx context.Context, orgID, deviceID uuid.UUID, ttl time.Duration, createdBy string) (*DeviceEnrollmentSecret, string, error) {
	raw, err := generateDeviceSecret()
	if err != nil {
		return nil, "", err
	}
	hash := hashDeviceSecret(raw)
	const q = `
		INSERT INTO device_enrollment_secrets (org_id, device_id, secret_hash, expires_at, created_by)
		VALUES ($1,$2,$3,NOW()+($4 || ' seconds')::interval,$5)
		RETURNING id, org_id, device_id, status, expires_at, used_at, revoked_at, created_by, created_at`
	var s DeviceEnrollmentSecret
	err = r.pool.QueryRow(ctx, q, orgID, deviceID, hash, int(ttl.Seconds()), createdBy).Scan(
		&s.ID, &s.OrgID, &s.DeviceID, &s.Status, &s.ExpiresAt, &s.UsedAt, &s.RevokedAt, &s.CreatedBy, &s.CreatedAt,
	)
	if err != nil {
		return nil, "", err
	}
	return &s, raw, nil
}

// LockPendingSecretForDeviceTx locks (FOR UPDATE) the pending enrollment
// secret for the given device within tx, so the secret's validation and its
// "used" transition are atomic with certificate issuance. Returns
// ErrEnrollmentSecretNotFound if no pending row exists.
func (r *DevicePKIRepository) LockPendingSecretForDeviceTx(ctx context.Context, tx pgx.Tx, orgID, deviceID uuid.UUID) (*DeviceEnrollmentSecret, error) {
	const q = `SELECT id, org_id, device_id, secret_hash, status, expires_at, used_at, revoked_at, created_by, created_at
		FROM device_enrollment_secrets
		WHERE org_id=$1 AND device_id=$2 AND status='pending'
		ORDER BY created_at DESC LIMIT 1 FOR UPDATE`
	var s DeviceEnrollmentSecret
	var hash string
	err := tx.QueryRow(ctx, q, orgID, deviceID).Scan(
		&s.ID, &s.OrgID, &s.DeviceID, &hash, &s.Status, &s.ExpiresAt, &s.UsedAt, &s.RevokedAt, &s.CreatedBy, &s.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEnrollmentSecretNotFound
	}
	if err != nil {
		return nil, err
	}
	s.secretHash = hash
	return &s, nil
}

// VerifySecret does a constant-time comparison of raw against the locked
// row's stored hash.
func (s *DeviceEnrollmentSecret) VerifySecret(raw string) bool {
	want := hashDeviceSecret(raw)
	return subtle.ConstantTimeCompare([]byte(want), []byte(s.secretHash)) == 1
}

// MarkSecretUsedTx transitions a secret to 'used', within the caller's
// transaction. This is deliberately in the SAME transaction as the
// certificate-issuance insert — the secret must never be usable twice, and
// there must never be a window where it is valid in parallel with an already
// issued certificate.
func (r *DevicePKIRepository) MarkSecretUsedTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE device_enrollment_secrets SET status='used', used_at=NOW() WHERE id=$1`, id)
	return err
}

// RevokeEnrollmentSecret revokes a still-pending secret (e.g. an operator
// fat-fingered the provisioning run). Rejects if the secret is not 'pending' —
// a used secret revoking is meaningless; the issued certificate is the thing
// to revoke at that point.
func (r *DevicePKIRepository) RevokeEnrollmentSecret(ctx context.Context, orgID, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE device_enrollment_secrets SET status='revoked', revoked_at=NOW()
		WHERE org_id=$1 AND id=$2 AND status='pending'`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrEnrollmentSecretNotFound
	}
	return nil
}

func generateDeviceSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashDeviceSecret(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// ── device_certificates ───────────────────────────────────────────────────

// InsertCertParams carries the inputs for recording a newly issued cert.
type InsertCertParams struct {
	OrgID        uuid.UUID
	DeviceID     uuid.UUID
	SerialNumber string
	CN           string
	NotBefore    time.Time
	NotAfter     time.Time
}

// InsertCertificateTx records a newly issued certificate as 'active', within
// the caller's transaction.
func (r *DevicePKIRepository) InsertCertificateTx(ctx context.Context, tx pgx.Tx, p InsertCertParams) (*DeviceCertificate, error) {
	const q = `
		INSERT INTO device_certificates (org_id, device_id, serial_number, cn, not_before, not_after)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, org_id, device_id, serial_number, cn, not_before, not_after, status,
			revoked_at, revoked_reason, revoked_by, created_at`
	var c DeviceCertificate
	err := tx.QueryRow(ctx, q, p.OrgID, p.DeviceID, p.SerialNumber, p.CN, p.NotBefore, p.NotAfter).Scan(
		&c.ID, &c.OrgID, &c.DeviceID, &c.SerialNumber, &c.CN, &c.NotBefore, &c.NotAfter, &c.Status,
		&c.RevokedAt, &c.RevokedReason, &c.RevokedBy, &c.CreatedAt,
	)
	return &c, err
}

// SupersedeCertificateTx marks a certificate as superseded by a routine
// renewal (not a compromise event — kept distinct from 'revoked' so
// revocation reporting stays meaningful).
func (r *DevicePKIRepository) SupersedeCertificateTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE device_certificates SET status='superseded' WHERE id=$1 AND status='active'`, id)
	return err
}

// GetActiveCertificateBySerial returns the certificate row for a serial,
// scoped to org, regardless of status (callers check .Status themselves).
func (r *DevicePKIRepository) GetCertificateBySerial(ctx context.Context, orgID uuid.UUID, serial string) (*DeviceCertificate, error) {
	const q = `SELECT id, org_id, device_id, serial_number, cn, not_before, not_after, status,
		revoked_at, revoked_reason, revoked_by, created_at
		FROM device_certificates WHERE org_id=$1 AND serial_number=$2`
	var c DeviceCertificate
	err := r.pool.QueryRow(ctx, q, orgID, serial).Scan(
		&c.ID, &c.OrgID, &c.DeviceID, &c.SerialNumber, &c.CN, &c.NotBefore, &c.NotAfter, &c.Status,
		&c.RevokedAt, &c.RevokedReason, &c.RevokedBy, &c.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &c, err
}

// ListActiveCertificatesForDevice returns all 'active' certificates for a
// device (normally zero or one, but a device revoke must be able to catch any
// stray extras).
func (r *DevicePKIRepository) ListActiveCertificatesForDevice(ctx context.Context, orgID, deviceID uuid.UUID) ([]DeviceCertificate, error) {
	const q = `SELECT id, org_id, device_id, serial_number, cn, not_before, not_after, status,
		revoked_at, revoked_reason, revoked_by, created_at
		FROM device_certificates WHERE org_id=$1 AND device_id=$2 AND status='active'`
	rows, err := r.pool.Query(ctx, q, orgID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceCertificate
	for rows.Next() {
		var c DeviceCertificate
		if err := rows.Scan(&c.ID, &c.OrgID, &c.DeviceID, &c.SerialNumber, &c.CN, &c.NotBefore, &c.NotAfter, &c.Status,
			&c.RevokedAt, &c.RevokedReason, &c.RevokedBy, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeCertificate marks a certificate revoked. Only valid from 'active' or
// 'superseded' (a superseded cert may still be technically time-valid, so it
// can still be explicitly revoked defensively).
func (r *DevicePKIRepository) RevokeCertificate(ctx context.Context, orgID, id uuid.UUID, reason, revokedBy string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE device_certificates
		SET status='revoked', revoked_at=NOW(), revoked_reason=NULLIF($3,''), revoked_by=NULLIF($4,'')
		WHERE org_id=$1 AND id=$2 AND status IN ('active','superseded')`,
		orgID, id, reason, revokedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("certificate not found or already revoked")
	}
	return nil
}
