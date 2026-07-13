package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Rotation states.
const (
	SSHCARotationIdle         = "idle"
	SSHCARotationRotating     = "rotating"
	SSHCARotationCutoverReady = "cutover_ready"
	SSHCARotationRollback     = "rollback"
)

var (
	// ErrActiveRotationExists is returned when a start is attempted while a
	// rotation is already in flight for the org.
	ErrActiveRotationExists = errors.New("an SSH CA rotation is already in progress for this organization")
	// ErrInvalidRotationTransition is returned when a state transition is not
	// valid from the row's current state.
	ErrInvalidRotationTransition = errors.New("invalid SSH CA rotation state transition")
)

// PAMSSHCARotation is one row of the SSH CA rotation state machine.
type PAMSSHCARotation struct {
	ID                   uuid.UUID  `json:"id"`
	OrgID                uuid.UUID  `json:"org_id"`
	State                string     `json:"state"`
	OldCAFingerprint     *string    `json:"old_ca_fingerprint,omitempty"`
	NewCAFingerprint     *string    `json:"new_ca_fingerprint,omitempty"`
	OldVaultMount        *string    `json:"old_vault_mount,omitempty"`
	NewVaultMount        *string    `json:"new_vault_mount,omitempty"`
	RotationPolicy       string     `json:"rotation_policy"`
	RotationIntervalDays *int       `json:"rotation_interval_days,omitempty"`
	StartedAt            time.Time  `json:"started_at"`
	CutoverReadyAt       *time.Time `json:"cutover_ready_at,omitempty"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
	GraceExpiresAt       *time.Time `json:"grace_expires_at,omitempty"`
	OldMountRemoved      bool       `json:"old_mount_removed"`
	StartedBy            *string    `json:"started_by,omitempty"`
	Notes                *string    `json:"notes,omitempty"`
}

const sshCARotationCols = `id, org_id, state, old_ca_fingerprint, new_ca_fingerprint,
	old_vault_mount, new_vault_mount, rotation_policy, rotation_interval_days,
	started_at, cutover_ready_at, completed_at, grace_expires_at, old_mount_removed,
	started_by, notes`

func scanSSHCARotation(row interface{ Scan(...any) error }) (*PAMSSHCARotation, error) {
	r := &PAMSSHCARotation{}
	err := row.Scan(
		&r.ID, &r.OrgID, &r.State, &r.OldCAFingerprint, &r.NewCAFingerprint,
		&r.OldVaultMount, &r.NewVaultMount, &r.RotationPolicy, &r.RotationIntervalDays,
		&r.StartedAt, &r.CutoverReadyAt, &r.CompletedAt, &r.GraceExpiresAt, &r.OldMountRemoved,
		&r.StartedBy, &r.Notes,
	)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// CreateRotationParams carries the inputs for starting a rotation.
type CreateRotationParams struct {
	OrgID                uuid.UUID
	OldCAFingerprint     *string
	NewCAFingerprint     string
	OldVaultMount        string
	NewVaultMount        string
	RotationPolicy       string
	RotationIntervalDays *int
	StartedBy            string
}

// CreateRotation inserts a new rotation in the 'rotating' state. Returns
// ErrActiveRotationExists if one is already in flight (partial unique index).
func (r *PAMRepository) CreateRotation(ctx context.Context, p CreateRotationParams) (*PAMSSHCARotation, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO pam_ssh_ca_rotations
			(org_id, state, old_ca_fingerprint, new_ca_fingerprint, old_vault_mount,
			 new_vault_mount, rotation_policy, rotation_interval_days, started_by)
		VALUES ($1, 'rotating', $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+sshCARotationCols,
		p.OrgID, p.OldCAFingerprint, p.NewCAFingerprint, p.OldVaultMount,
		p.NewVaultMount, p.RotationPolicy, p.RotationIntervalDays, p.StartedBy)
	rot, err := scanSSHCARotation(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return nil, ErrActiveRotationExists
		}
		return nil, err
	}
	return rot, nil
}

// GetActiveRotation returns the in-flight rotation for an org, or nil if none.
func (r *PAMRepository) GetActiveRotation(ctx context.Context, orgID uuid.UUID) (*PAMSSHCARotation, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+sshCARotationCols+`
		FROM pam_ssh_ca_rotations
		WHERE org_id=$1 AND state IN ('rotating','cutover_ready')
		ORDER BY started_at DESC LIMIT 1`, orgID)
	rot, err := scanSSHCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return rot, err
}

// GetRotation returns a specific rotation scoped to its org.
func (r *PAMRepository) GetRotation(ctx context.Context, orgID, id uuid.UUID) (*PAMSSHCARotation, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+sshCARotationCols+`
		FROM pam_ssh_ca_rotations WHERE id=$1 AND org_id=$2`, id, orgID)
	rot, err := scanSSHCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return rot, err
}

// MarkCutoverReady transitions rotating -> cutover_ready. Only valid from
// 'rotating'; otherwise returns ErrInvalidRotationTransition.
func (r *PAMRepository) MarkCutoverReady(ctx context.Context, orgID, id uuid.UUID) (*PAMSSHCARotation, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE pam_ssh_ca_rotations
		SET state='cutover_ready', cutover_ready_at=NOW()
		WHERE id=$1 AND org_id=$2 AND state='rotating'
		RETURNING `+sshCARotationCols, id, orgID)
	rot, err := scanSSHCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidRotationTransition
	}
	return rot, err
}

// CompleteRotation transitions cutover_ready -> idle (terminal) and records the
// grace window after which the old mount may be removed. Only valid from
// 'cutover_ready'.
func (r *PAMRepository) CompleteRotation(ctx context.Context, orgID, id uuid.UUID, graceExpiresAt time.Time) (*PAMSSHCARotation, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE pam_ssh_ca_rotations
		SET state='idle', completed_at=NOW(), grace_expires_at=$3
		WHERE id=$1 AND org_id=$2 AND state='cutover_ready'
		RETURNING `+sshCARotationCols, id, orgID, graceExpiresAt)
	rot, err := scanSSHCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidRotationTransition
	}
	return rot, err
}

// AbortRotation transitions rotating|cutover_ready -> rollback (terminal).
func (r *PAMRepository) AbortRotation(ctx context.Context, orgID, id uuid.UUID) (*PAMSSHCARotation, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE pam_ssh_ca_rotations
		SET state='rollback', completed_at=NOW()
		WHERE id=$1 AND org_id=$2 AND state IN ('rotating','cutover_ready')
		RETURNING `+sshCARotationCols, id, orgID)
	rot, err := scanSSHCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidRotationTransition
	}
	return rot, err
}

// ListRotationsForGraceCleanup returns completed rotations whose grace window
// has elapsed and whose old mount has not yet been removed.
func (r *PAMRepository) ListRotationsForGraceCleanup(ctx context.Context, now time.Time) ([]PAMSSHCARotation, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+sshCARotationCols+`
		FROM pam_ssh_ca_rotations
		WHERE state='idle' AND old_mount_removed=FALSE
		  AND grace_expires_at IS NOT NULL AND grace_expires_at <= $1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMSSHCARotation
	for rows.Next() {
		rot, err := scanSSHCARotation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rot)
	}
	return out, rows.Err()
}

// MarkOldMountRemoved flags that the retired mount has been deleted from Vault.
func (r *PAMRepository) MarkOldMountRemoved(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE pam_ssh_ca_rotations SET old_mount_removed=TRUE WHERE id=$1`, id)
	return err
}

// ── pam_ssh_ca_configs rotation helpers ──────────────────────────────────────

// SetSSHCARotationPolicy sets the scheduled-rotation policy on the config.
func (r *PAMRepository) SetSSHCARotationPolicy(ctx context.Context, orgID uuid.UUID, policy string, intervalDays *int) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE pam_ssh_ca_configs
		SET rotation_policy=$2, rotation_interval_days=$3, updated_at=NOW()
		WHERE org_id=$1`, orgID, policy, intervalDays)
	return err
}

// PromoteSSHCAMount makes the new mount the primary signer and caches its CA key
// (called on Complete). signWithVaultSSHCA reads vault_mount, so this switches
// signing to the new CA.
func (r *PAMRepository) PromoteSSHCAMount(ctx context.Context, orgID uuid.UUID, newMount, caPublicKey string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE pam_ssh_ca_configs
		SET vault_mount=$2, ca_public_key=$3, updated_at=NOW()
		WHERE org_id=$1`, orgID, newMount, caPublicKey)
	return err
}

// SSHCAScheduledRow is a config due for scheduled rotation.
type SSHCAScheduledRow struct {
	OrgID          uuid.UUID
	VaultAddr      string
	VaultMount     string
	VaultRole      string
	EncryptedToken string
	CertTTLSeconds int
	IntervalDays   int
}

// ListSSHCAConfigsForScheduledRotation returns configs whose scheduled rotation
// interval has elapsed (since the last completed rotation, or config creation)
// and that have NO in-flight rotation.
func (r *PAMRepository) ListSSHCAConfigsForScheduledRotation(ctx context.Context, now time.Time) ([]SSHCAScheduledRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT c.org_id, c.vault_addr, c.vault_mount, c.vault_role,
		       c.encrypted_vault_token, c.cert_ttl_seconds, c.rotation_interval_days
		FROM pam_ssh_ca_configs c
		WHERE c.rotation_policy='scheduled'
		  AND c.rotation_interval_days IS NOT NULL
		  AND NOT EXISTS (
		      SELECT 1 FROM pam_ssh_ca_rotations r
		      WHERE r.org_id=c.org_id AND r.state IN ('rotating','cutover_ready'))
		  AND COALESCE(
		        (SELECT MAX(completed_at) FROM pam_ssh_ca_rotations d
		         WHERE d.org_id=c.org_id AND d.state='idle'),
		        c.created_at
		      ) + (c.rotation_interval_days || ' days')::interval <= $1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSHCAScheduledRow
	for rows.Next() {
		var s SSHCAScheduledRow
		if err := rows.Scan(&s.OrgID, &s.VaultAddr, &s.VaultMount, &s.VaultRole,
			&s.EncryptedToken, &s.CertTTLSeconds, &s.IntervalDays); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
