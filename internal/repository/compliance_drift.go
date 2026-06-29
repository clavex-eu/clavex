package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ComplianceDriftRepository handles persistence for compliance drift detection.
type ComplianceDriftRepository struct {
	pool *pgxpool.Pool
}

func NewComplianceDriftRepository(pool *pgxpool.Pool) *ComplianceDriftRepository {
	return &ComplianceDriftRepository{pool: pool}
}

// ComplianceSnapshot is the stored security fingerprint for an org.
type ComplianceSnapshot struct {
	OrgID        uuid.UUID         `db:"org_id"`
	Snapshot     map[string]string `db:"snapshot"`
	SnapshotHash string            `db:"snapshot_hash"`
	CapturedAt   time.Time         `db:"captured_at"`
}

// ComplianceDriftEvent records a single detected control change.
type ComplianceDriftEvent struct {
	ID            uuid.UUID  `db:"id"`
	OrgID         uuid.UUID  `db:"org_id"`
	Control       string     `db:"control"`
	PreviousValue *string    `db:"previous_value"`
	CurrentValue  *string    `db:"current_value"`
	Severity      string     `db:"severity"` // critical|high|medium|low|info
	DetectedAt    time.Time  `db:"detected_at"`
}

// GetSnapshot returns the stored snapshot for an org, or nil if none exists.
func (r *ComplianceDriftRepository) GetSnapshot(ctx context.Context, orgID uuid.UUID) (*ComplianceSnapshot, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT org_id, snapshot, snapshot_hash, captured_at
		FROM compliance_snapshots
		WHERE org_id = $1
	`, orgID)

	var s ComplianceSnapshot
	var rawSnap []byte
	if err := row.Scan(&s.OrgID, &rawSnap, &s.SnapshotHash, &s.CapturedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rawSnap, &s.Snapshot); err != nil {
		return nil, err
	}
	return &s, nil
}

// UpsertSnapshot stores (or replaces) the current security snapshot for an org.
func (r *ComplianceDriftRepository) UpsertSnapshot(ctx context.Context, orgID uuid.UUID, snap map[string]string, hash string) error {
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO compliance_snapshots (org_id, snapshot, snapshot_hash, captured_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (org_id) DO UPDATE
		    SET snapshot      = EXCLUDED.snapshot,
		        snapshot_hash = EXCLUDED.snapshot_hash,
		        captured_at   = EXCLUDED.captured_at
	`, orgID, b, hash)
	return err
}

// InsertDriftEvent persists a single detected drift event.
func (r *ComplianceDriftRepository) InsertDriftEvent(ctx context.Context, e ComplianceDriftEvent) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO compliance_drift_events (org_id, control, previous_value, current_value, severity)
		VALUES ($1, $2, $3, $4, $5)
	`, e.OrgID, e.Control, e.PreviousValue, e.CurrentValue, e.Severity)
	return err
}

// ListDriftEvents returns the most recent drift events for an org.
func (r *ComplianceDriftRepository) ListDriftEvents(ctx context.Context, orgID uuid.UUID, limit int) ([]ComplianceDriftEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, control, previous_value, current_value, severity, detected_at
		FROM compliance_drift_events
		WHERE org_id = $1
		ORDER BY detected_at DESC
		LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ComplianceDriftEvent
	for rows.Next() {
		var e ComplianceDriftEvent
		if err := rows.Scan(&e.ID, &e.OrgID, &e.Control, &e.PreviousValue, &e.CurrentValue, &e.Severity, &e.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AllActiveOrgIDs returns all active organization IDs for drift scanning.
func (r *ComplianceDriftRepository) AllActiveOrgIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id FROM organizations WHERE is_active = TRUE ORDER BY created_at
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// OrgSecurityState is the raw DB view of an org's security-relevant state.
type OrgSecurityState struct {
	OrgID           uuid.UUID
	OrgName         string
	OrgSlug         string
	MFARequired     bool
	AccessTokenTTL  *int
	RefreshTokenTTL *int
	// Derived counts — filled by additional queries.
	AdminCount        int
	PasswordMinLength *int
	PasswordComplexity string
	BreachedPwdAction  string
}

// GetOrgSecurityState loads the security-relevant state for an org in a single query.
func (r *ComplianceDriftRepository) GetOrgSecurityState(ctx context.Context, orgID uuid.UUID) (*OrgSecurityState, error) {
	s := &OrgSecurityState{OrgID: orgID}
	err := r.pool.QueryRow(ctx, `
		SELECT name, slug, mfa_required, access_token_ttl, refresh_token_ttl
		FROM organizations
		WHERE id = $1 AND is_active = TRUE
	`, orgID).Scan(&s.OrgName, &s.OrgSlug, &s.MFARequired, &s.AccessTokenTTL, &s.RefreshTokenTTL)
	if err != nil {
		return nil, err
	}

	// Count users with any admin role assignment in this org.
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM admin_role_assignments
		WHERE org_id = $1
	`, orgID).Scan(&s.AdminCount)

	// Password policy (best-effort — table may not exist in older deployments).
	_ = r.pool.QueryRow(ctx, `
		SELECT min_length, complexity_required, breached_password_action
		FROM password_policies
		WHERE org_id = $1
	`, orgID).Scan(&s.PasswordMinLength, &s.PasswordComplexity, &s.BreachedPwdAction)

	return s, nil
}
