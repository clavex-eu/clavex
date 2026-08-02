package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Device CA rotation states — literal mirror of the SSH CA rotation states
// (pam_ssh_ca_rotation.go), against a separate table/mount.
const (
	DeviceCARotationIdle         = "idle"
	DeviceCARotationRotating     = "rotating"
	DeviceCARotationCutoverReady = "cutover_ready"
	DeviceCARotationRollback     = "rollback"
)

var (
	// ErrActiveDeviceCARotationExists is returned when a start is attempted
	// while a rotation is already in flight for the org.
	ErrActiveDeviceCARotationExists = errors.New("a Device CA rotation is already in progress for this organization")
	// ErrInvalidDeviceCARotationTransition is returned when a state transition
	// is not valid from the row's current state.
	ErrInvalidDeviceCARotationTransition = errors.New("invalid Device CA rotation state transition")
)

// DeviceCARotation is one row of the Device CA rotation state machine.
type DeviceCARotation struct {
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

const deviceCARotationCols = `id, org_id, state, old_ca_fingerprint, new_ca_fingerprint,
	old_vault_mount, new_vault_mount, rotation_policy, rotation_interval_days,
	started_at, cutover_ready_at, completed_at, grace_expires_at, old_mount_removed,
	started_by, notes`

func scanDeviceCARotation(row interface{ Scan(...any) error }) (*DeviceCARotation, error) {
	r := &DeviceCARotation{}
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

// CreateDeviceCARotationParams carries the inputs for starting a rotation.
type CreateDeviceCARotationParams struct {
	OrgID                uuid.UUID
	OldCAFingerprint     *string
	NewCAFingerprint     string
	OldVaultMount        string
	NewVaultMount        string
	RotationPolicy       string
	RotationIntervalDays *int
	StartedBy            string
}

// CreateDeviceCARotation inserts a new rotation in the 'rotating' state.
// Returns ErrActiveDeviceCARotationExists if one is already in flight.
func (r *DevicePKIRepository) CreateDeviceCARotation(ctx context.Context, p CreateDeviceCARotationParams) (*DeviceCARotation, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO device_ca_rotations
			(org_id, state, old_ca_fingerprint, new_ca_fingerprint, old_vault_mount,
			 new_vault_mount, rotation_policy, rotation_interval_days, started_by)
		VALUES ($1, 'rotating', $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+deviceCARotationCols,
		p.OrgID, p.OldCAFingerprint, p.NewCAFingerprint, p.OldVaultMount,
		p.NewVaultMount, p.RotationPolicy, p.RotationIntervalDays, p.StartedBy)
	rot, err := scanDeviceCARotation(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return nil, ErrActiveDeviceCARotationExists
		}
		return nil, err
	}
	return rot, nil
}

// GetActiveDeviceCARotation returns the in-flight rotation for an org, or nil.
func (r *DevicePKIRepository) GetActiveDeviceCARotation(ctx context.Context, orgID uuid.UUID) (*DeviceCARotation, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+deviceCARotationCols+`
		FROM device_ca_rotations
		WHERE org_id=$1 AND state IN ('rotating','cutover_ready')
		ORDER BY started_at DESC LIMIT 1`, orgID)
	rot, err := scanDeviceCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return rot, err
}

// GetDeviceCARotation returns a specific rotation scoped to its org.
func (r *DevicePKIRepository) GetDeviceCARotation(ctx context.Context, orgID, id uuid.UUID) (*DeviceCARotation, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+deviceCARotationCols+`
		FROM device_ca_rotations WHERE id=$1 AND org_id=$2`, id, orgID)
	rot, err := scanDeviceCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return rot, err
}

// MarkDeviceCACutoverReady transitions rotating -> cutover_ready.
func (r *DevicePKIRepository) MarkDeviceCACutoverReady(ctx context.Context, orgID, id uuid.UUID) (*DeviceCARotation, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE device_ca_rotations
		SET state='cutover_ready', cutover_ready_at=NOW()
		WHERE id=$1 AND org_id=$2 AND state='rotating'
		RETURNING `+deviceCARotationCols, id, orgID)
	rot, err := scanDeviceCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidDeviceCARotationTransition
	}
	return rot, err
}

// CompleteDeviceCARotation transitions cutover_ready -> idle (terminal) and
// records the grace window after which the old mount may be removed.
func (r *DevicePKIRepository) CompleteDeviceCARotation(ctx context.Context, orgID, id uuid.UUID, graceExpiresAt time.Time) (*DeviceCARotation, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE device_ca_rotations
		SET state='idle', completed_at=NOW(), grace_expires_at=$3
		WHERE id=$1 AND org_id=$2 AND state='cutover_ready'
		RETURNING `+deviceCARotationCols, id, orgID, graceExpiresAt)
	rot, err := scanDeviceCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidDeviceCARotationTransition
	}
	return rot, err
}

// AbortDeviceCARotation transitions rotating|cutover_ready -> rollback.
func (r *DevicePKIRepository) AbortDeviceCARotation(ctx context.Context, orgID, id uuid.UUID) (*DeviceCARotation, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE device_ca_rotations
		SET state='rollback', completed_at=NOW()
		WHERE id=$1 AND org_id=$2 AND state IN ('rotating','cutover_ready')
		RETURNING `+deviceCARotationCols, id, orgID)
	rot, err := scanDeviceCARotation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidDeviceCARotationTransition
	}
	return rot, err
}

// ListDeviceCARotationsForGraceCleanup returns completed rotations whose grace
// window has elapsed and whose old mount has not yet been removed.
func (r *DevicePKIRepository) ListDeviceCARotationsForGraceCleanup(ctx context.Context, now time.Time) ([]DeviceCARotation, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+deviceCARotationCols+`
		FROM device_ca_rotations
		WHERE state='idle' AND old_mount_removed=FALSE
		  AND grace_expires_at IS NOT NULL AND grace_expires_at <= $1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceCARotation
	for rows.Next() {
		rot, err := scanDeviceCARotation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rot)
	}
	return out, rows.Err()
}

// MarkOldDeviceMountRemoved flags that the retired mount has been deleted.
func (r *DevicePKIRepository) MarkOldDeviceMountRemoved(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE device_ca_rotations SET old_mount_removed=TRUE WHERE id=$1`, id)
	return err
}

// PromoteDeviceCAMount makes the new mount the primary signer and caches its
// CA certificate (called on Complete).
func (r *DevicePKIRepository) PromoteDeviceCAMount(ctx context.Context, orgID uuid.UUID, newMount, caCertPEM string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE device_ca_configs
		SET vault_mount=$2, ca_certificate_pem=$3, updated_at=NOW()
		WHERE org_id=$1`, orgID, newMount, caCertPEM)
	return err
}

// DeviceCAScheduledRow is a config due for scheduled rotation.
type DeviceCAScheduledRow struct {
	OrgID        uuid.UUID
	IntervalDays int
}

// ListDeviceCAConfigsForScheduledRotation returns configs whose scheduled
// rotation interval has elapsed and that have NO in-flight rotation — mirrors
// ListSSHCAConfigsForScheduledRotation.
func (r *DevicePKIRepository) ListDeviceCAConfigsForScheduledRotation(ctx context.Context, now time.Time) ([]DeviceCAScheduledRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT c.org_id, c.rotation_interval_days
		FROM device_ca_configs c
		WHERE c.rotation_policy='scheduled'
		  AND c.rotation_interval_days IS NOT NULL
		  AND NOT EXISTS (
		      SELECT 1 FROM device_ca_rotations r
		      WHERE r.org_id=c.org_id AND r.state IN ('rotating','cutover_ready'))
		  AND COALESCE(
		        (SELECT MAX(completed_at) FROM device_ca_rotations d
		         WHERE d.org_id=c.org_id AND d.state='idle'),
		        c.created_at
		      ) + (c.rotation_interval_days || ' days')::interval <= $1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceCAScheduledRow
	for rows.Next() {
		var s DeviceCAScheduledRow
		if err := rows.Scan(&s.OrgID, &s.IntervalDays); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
