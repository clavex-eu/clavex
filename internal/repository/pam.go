package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Models ────────────────────────────────────────────────────────────────────

// PAMAccessRequest represents a JIT privileged-access request.
type PAMAccessRequest struct {
	ID                uuid.UUID  `db:"id"                 json:"id"`
	OrgID             uuid.UUID  `db:"org_id"             json:"org_id"`
	RequesterID       uuid.UUID  `db:"requester_id"       json:"requester_id"`
	ResourceType      string     `db:"resource_type"      json:"resource_type"`
	ResourceID        string     `db:"resource_id"        json:"resource_id"`
	ResourceName      string     `db:"resource_name"      json:"resource_name"`
	Justification     string     `db:"justification"      json:"justification"`
	RequestedDuration int        `db:"requested_duration" json:"requested_duration"`
	Status            string     `db:"status"             json:"status"`
	ApprovedBy        *uuid.UUID `db:"approved_by"        json:"approved_by,omitempty"`
	ApproveNote       *string    `db:"approve_note"       json:"approve_note,omitempty"`
	GrantedAt         *time.Time `db:"granted_at"         json:"granted_at,omitempty"`
	ExpiresAt         *time.Time `db:"expires_at"         json:"expires_at,omitempty"`
	RevokedAt         *time.Time `db:"revoked_at"         json:"revoked_at,omitempty"`
	RevokeReason      *string    `db:"revoke_reason"      json:"revoke_reason,omitempty"`
	CreatedAt         time.Time  `db:"created_at"         json:"created_at"`
	UpdatedAt         time.Time  `db:"updated_at"         json:"updated_at"`
	IsBreakGlass      bool       `db:"is_break_glass"     json:"is_break_glass"`
}

// BreakGlassConfig holds the per-org break-glass emergency access policy.
// If no row exists in pam_break_glass_configs the handler returns safe defaults.
type BreakGlassConfig struct {
	OrgID                uuid.UUID `db:"org_id"                json:"org_id"`
	Enabled              bool      `db:"enabled"               json:"enabled"`
	MaxUsesPerWeek       int       `db:"max_uses_per_week"     json:"max_uses_per_week"`
	RequireJustification bool      `db:"require_justification" json:"require_justification"`
	NotifyOnUse          bool      `db:"notify_on_use"         json:"notify_on_use"`
	CreatedAt            time.Time `db:"created_at"            json:"created_at"`
	UpdatedAt            time.Time `db:"updated_at"            json:"updated_at"`
}

// PAMSession represents a privileged session record.
type PAMSession struct {
	ID              uuid.UUID  `db:"id"                json:"id"`
	OrgID           uuid.UUID  `db:"org_id"            json:"org_id"`
	AccessRequestID *uuid.UUID `db:"access_request_id" json:"access_request_id,omitempty"`
	UserID          uuid.UUID  `db:"user_id"           json:"user_id"`
	SessionType     string     `db:"session_type"      json:"session_type"`
	TargetHost      *string    `db:"target_host"       json:"target_host,omitempty"`
	TargetPort      *int       `db:"target_port"       json:"target_port,omitempty"`
	TargetUser      *string    `db:"target_user"       json:"target_user,omitempty"`
	ClientIP        *string    `db:"client_ip"         json:"client_ip,omitempty"`
	EventCount      int        `db:"event_count"       json:"event_count"`
	StartedAt       time.Time  `db:"started_at"        json:"started_at"`
	EndedAt         *time.Time `db:"ended_at"          json:"ended_at,omitempty"`
}

// PAMSessionEvent is a single recorded event within a privileged session.
type PAMSessionEvent struct {
	ID        int64     `db:"id"         json:"id"`
	SessionID uuid.UUID `db:"session_id" json:"session_id"`
	EventType string    `db:"event_type" json:"event_type"`
	Payload   []byte    `db:"payload"    json:"payload"`
	Ts        time.Time `db:"ts"         json:"ts"`
}

// PAMCredential is a vault entry (secret is never returned from the API).
type PAMCredential struct {
	ID                   uuid.UUID  `db:"id"                      json:"id"`
	OrgID                uuid.UUID  `db:"org_id"                  json:"org_id"`
	Name                 string     `db:"name"                    json:"name"`
	Description          *string    `db:"description"             json:"description,omitempty"`
	CredentialType       string     `db:"credential_type"         json:"credential_type"`
	Username             *string    `db:"username"                json:"username,omitempty"`
	TargetHost           *string    `db:"target_host"             json:"target_host,omitempty"`
	CheckoutDuration     int        `db:"checkout_duration"       json:"checkout_duration"`
	RequireAccessRequest bool       `db:"require_access_request"  json:"require_access_request"`
	IsActive             bool       `db:"is_active"               json:"is_active"`
	RotationIntervalDays *int       `db:"rotation_interval_days"  json:"rotation_interval_days,omitempty"`
	LastRotatedAt        *time.Time `db:"last_rotated_at"         json:"last_rotated_at,omitempty"`
	CreatedAt            time.Time  `db:"created_at"              json:"created_at"`
	UpdatedAt            time.Time  `db:"updated_at"              json:"updated_at"`
}

// PAMCredentialRotationLog records every rotation event for a vault credential.
type PAMCredentialRotationLog struct {
	ID           int64     `db:"id"            json:"id"`
	CredentialID uuid.UUID `db:"credential_id" json:"credential_id"`
	OrgID        uuid.UUID `db:"org_id"        json:"org_id"`
	RotatedBy    string    `db:"rotated_by"    json:"rotated_by"`
	RotationType string    `db:"rotation_type" json:"rotation_type"`
	Note         *string   `db:"note"          json:"note,omitempty"`
	RotatedAt    time.Time `db:"rotated_at"    json:"rotated_at"`
}

// PAMCredentialCheckout tracks an active or past credential checkout.
type PAMCredentialCheckout struct {
	ID              uuid.UUID  `db:"id"                json:"id"`
	CredentialID    uuid.UUID  `db:"credential_id"     json:"credential_id"`
	OrgID           uuid.UUID  `db:"org_id"            json:"org_id"`
	UserID          uuid.UUID  `db:"user_id"           json:"user_id"`
	AccessRequestID *uuid.UUID `db:"access_request_id" json:"access_request_id,omitempty"`
	Reason          *string    `db:"reason"            json:"reason,omitempty"`
	CheckedOutAt    time.Time  `db:"checked_out_at"    json:"checked_out_at"`
	ExpiresAt       time.Time  `db:"expires_at"        json:"expires_at"`
	ReturnedAt      *time.Time `db:"returned_at"       json:"returned_at,omitempty"`
}

// PAMSSHCAConfig holds the Vault SSH CA configuration for an org.
// vault_addr and vault_role are required; encrypted_vault_token is stored
// encrypted and never returned in API responses.
type PAMSSHCAConfig struct {
	OrgID                uuid.UUID  `db:"org_id"                 json:"org_id"`
	VaultAddr            string     `db:"vault_addr"             json:"vault_addr"`
	VaultMount           string     `db:"vault_mount"            json:"vault_mount"`
	VaultRole            string     `db:"vault_role"             json:"vault_role"`
	CAPublicKey          *string    `db:"ca_public_key"          json:"ca_public_key,omitempty"`
	CertTTLSeconds       int        `db:"cert_ttl_seconds"       json:"cert_ttl_seconds"`
	RequireAccessRequest bool       `db:"require_access_request" json:"require_access_request"`
	CreatedAt            time.Time  `db:"created_at"             json:"created_at"`
	UpdatedAt            time.Time  `db:"updated_at"             json:"updated_at"`
}

// ── Repository ────────────────────────────────────────────────────────────────

// PAMRepository handles all PAM database operations.
type PAMRepository struct {
	pool *pgxpool.Pool
}

// NewPAMRepository creates a new PAMRepository.
func NewPAMRepository(pool *pgxpool.Pool) *PAMRepository {
	return &PAMRepository{pool: pool}
}

// ── Access Requests ───────────────────────────────────────────────────────────

// CreateAccessRequest inserts a new JIT access request.
func (r *PAMRepository) CreateAccessRequest(ctx context.Context, req *PAMAccessRequest) error {
	const q = `
		INSERT INTO pam_access_requests
			(org_id, requester_id, resource_type, resource_id, resource_name,
			 justification, requested_duration)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, status, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		req.OrgID, req.RequesterID, req.ResourceType, req.ResourceID,
		req.ResourceName, req.Justification, req.RequestedDuration,
	).Scan(&req.ID, &req.Status, &req.CreatedAt, &req.UpdatedAt)
}

// GetAccessRequest returns a single access request, verifying org ownership.
func (r *PAMRepository) GetAccessRequest(ctx context.Context, orgID, id uuid.UUID) (*PAMAccessRequest, error) {
	const q = `SELECT * FROM pam_access_requests WHERE org_id=$1 AND id=$2`
	rows, err := r.pool.Query(ctx, q, orgID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	var ar PAMAccessRequest
	if err := scanPAMAccessRequest(rows, &ar); err != nil {
		return nil, err
	}
	return &ar, nil
}

// ListAccessRequests returns paginated access requests for an org.
// status="" returns all; otherwise filters by the given status.
func (r *PAMRepository) ListAccessRequests(ctx context.Context, orgID uuid.UUID, status string, page, perPage int) ([]PAMAccessRequest, int, error) {
	offset := (page - 1) * perPage

	var countQuery string
	var listQuery string
	var args []any

	if status == "" {
		countQuery = `SELECT COUNT(*) FROM pam_access_requests WHERE org_id=$1`
		listQuery = `SELECT * FROM pam_access_requests WHERE org_id=$1
			ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = []any{orgID, perPage, offset}
	} else {
		countQuery = `SELECT COUNT(*) FROM pam_access_requests WHERE org_id=$1 AND status=$2`
		listQuery = `SELECT * FROM pam_access_requests WHERE org_id=$1 AND status=$2
			ORDER BY created_at DESC LIMIT $3 OFFSET $4`
		args = []any{orgID, status, perPage, offset}
	}

	var total int
	if status == "" {
		if err := r.pool.QueryRow(ctx, countQuery, orgID).Scan(&total); err != nil {
			return nil, 0, err
		}
	} else {
		if err := r.pool.QueryRow(ctx, countQuery, orgID, status).Scan(&total); err != nil {
			return nil, 0, err
		}
	}

	rows, err := r.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []PAMAccessRequest
	for rows.Next() {
		var ar PAMAccessRequest
		if err := scanPAMAccessRequest(rows, &ar); err != nil {
			return nil, 0, err
		}
		results = append(results, ar)
	}
	return results, total, nil
}

// ApproveAccessRequest sets status to 'active', records approver + timestamps.
func (r *PAMRepository) ApproveAccessRequest(ctx context.Context, orgID, id, approverID uuid.UUID, note string) (*PAMAccessRequest, error) {
	const q = `
		UPDATE pam_access_requests SET
			status       = 'active',
			approved_by  = $3,
			approve_note = NULLIF($4,''),
			granted_at   = NOW(),
			expires_at   = NOW() + (requested_duration || ' minutes')::INTERVAL,
			updated_at   = NOW()
		WHERE org_id=$1 AND id=$2 AND status='pending'
		RETURNING *`
	rows, err := r.pool.Query(ctx, q, orgID, id, approverID, note)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	var ar PAMAccessRequest
	return &ar, scanPAMAccessRequest(rows, &ar)
}

// DenyAccessRequest sets status to 'denied'.
func (r *PAMRepository) DenyAccessRequest(ctx context.Context, orgID, id, approverID uuid.UUID, note string) (*PAMAccessRequest, error) {
	const q = `
		UPDATE pam_access_requests SET
			status       = 'denied',
			approved_by  = $3,
			approve_note = NULLIF($4,''),
			updated_at   = NOW()
		WHERE org_id=$1 AND id=$2 AND status='pending'
		RETURNING *`
	rows, err := r.pool.Query(ctx, q, orgID, id, approverID, note)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	var ar PAMAccessRequest
	return &ar, scanPAMAccessRequest(rows, &ar)
}

// RevokeAccessRequest sets status to 'revoked'.
func (r *PAMRepository) RevokeAccessRequest(ctx context.Context, orgID, id uuid.UUID, reason string) (*PAMAccessRequest, error) {
	const q = `
		UPDATE pam_access_requests SET
			status        = 'revoked',
			revoked_at    = NOW(),
			revoke_reason = NULLIF($3,''),
			updated_at    = NOW()
		WHERE org_id=$1 AND id=$2 AND status IN ('approved','active')
		RETURNING *`
	rows, err := r.pool.Query(ctx, q, orgID, id, reason)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	var ar PAMAccessRequest
	return &ar, scanPAMAccessRequest(rows, &ar)
}

// ExpireAccessRequests moves all active requests past their expiry to 'expired'.
// Designed to be called periodically by a background goroutine.
func (r *PAMRepository) ExpireAccessRequests(ctx context.Context) (int64, error) {
	const q = `
		UPDATE pam_access_requests SET status='expired', updated_at=NOW()
		WHERE status='active' AND expires_at < NOW()`
	res, err := r.pool.Exec(ctx, q)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// ── Sessions ──────────────────────────────────────────────────────────────────

// StartSession inserts a new privileged session record.
func (r *PAMRepository) StartSession(ctx context.Context, s *PAMSession) error {
	const q = `
		INSERT INTO pam_sessions
			(org_id, access_request_id, user_id, session_type,
			 target_host, target_port, target_user, client_ip)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, event_count, started_at`
	return r.pool.QueryRow(ctx, q,
		s.OrgID, s.AccessRequestID, s.UserID, s.SessionType,
		s.TargetHost, s.TargetPort, s.TargetUser, s.ClientIP,
	).Scan(&s.ID, &s.EventCount, &s.StartedAt)
}

// EndSession marks a session as ended.
func (r *PAMRepository) EndSession(ctx context.Context, orgID, id uuid.UUID) error {
	const q = `UPDATE pam_sessions SET ended_at=NOW() WHERE org_id=$1 AND id=$2 AND ended_at IS NULL`
	_, err := r.pool.Exec(ctx, q, orgID, id)
	return err
}

// GetSession returns a single session.
func (r *PAMRepository) GetSession(ctx context.Context, orgID, id uuid.UUID) (*PAMSession, error) {
	return r.getSessionByRow(ctx, orgID, id)
}

func (r *PAMRepository) getSessionByRow(ctx context.Context, orgID, id uuid.UUID) (*PAMSession, error) {
	const q = `SELECT id,org_id,access_request_id,user_id,session_type,
		target_host,target_port,target_user,client_ip::text,event_count,started_at,ended_at
		FROM pam_sessions WHERE org_id=$1 AND id=$2`
	rows, err := r.pool.Query(ctx, q, orgID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	s, err := scanPAMSessionRow(rows)
	return s, err
}

// ListSessions returns paginated sessions for an org.
func (r *PAMRepository) ListSessions(ctx context.Context, orgID uuid.UUID, page, perPage int) ([]PAMSession, int, error) {
	offset := (page - 1) * perPage
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM pam_sessions WHERE org_id=$1`, orgID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id,org_id,access_request_id,user_id,session_type,
		  target_host,target_port,target_user,client_ip::text,event_count,started_at,ended_at
		 FROM pam_sessions WHERE org_id=$1 ORDER BY started_at DESC LIMIT $2 OFFSET $3`,
		orgID, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var results []PAMSession
	for rows.Next() {
		s, err := scanPAMSessionRow(rows)
		if err != nil {
			return nil, 0, err
		}
		results = append(results, *s)
	}
	return results, total, nil
}

// AddSessionEvent inserts an event and increments event_count on the session.
func (r *PAMRepository) AddSessionEvent(ctx context.Context, ev *PAMSessionEvent) error {
	const q = `
		INSERT INTO pam_session_events (session_id, event_type, payload)
		VALUES ($1,$2,$3)
		RETURNING id, ts`
	if err := r.pool.QueryRow(ctx, q, ev.SessionID, ev.EventType, ev.Payload).
		Scan(&ev.ID, &ev.Ts); err != nil {
		return err
	}
	_, err := r.pool.Exec(ctx,
		`UPDATE pam_sessions SET event_count = event_count+1 WHERE id=$1`, ev.SessionID)
	return err
}

// ListSessionEvents returns all events for a session in chronological order.
func (r *PAMRepository) ListSessionEvents(ctx context.Context, sessionID uuid.UUID) ([]PAMSessionEvent, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id,session_id,event_type,payload,ts FROM pam_session_events WHERE session_id=$1 ORDER BY ts ASC`,
		sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []PAMSessionEvent
	for rows.Next() {
		var ev PAMSessionEvent
		if err := rows.Scan(&ev.ID, &ev.SessionID, &ev.EventType, &ev.Payload, &ev.Ts); err != nil {
			return nil, err
		}
		results = append(results, ev)
	}
	return results, nil
}

// ── Credential Vault ──────────────────────────────────────────────────────────

// CreateCredential inserts a new vault credential (secret already encrypted by caller).
func (r *PAMRepository) CreateCredential(ctx context.Context, c *PAMCredential, encryptedSecret string) error {
	const q = `
		INSERT INTO pam_credentials
			(org_id, name, description, credential_type, username,
			 encrypted_secret, target_host, checkout_duration, require_access_request,
			 rotation_interval_days)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id, is_active, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		c.OrgID, c.Name, c.Description, c.CredentialType, c.Username,
		encryptedSecret, c.TargetHost, c.CheckoutDuration, c.RequireAccessRequest,
		c.RotationIntervalDays,
	).Scan(&c.ID, &c.IsActive, &c.CreatedAt, &c.UpdatedAt)
}

// GetCredential returns a credential (no secret) and the encrypted secret separately.
func (r *PAMRepository) GetCredential(ctx context.Context, orgID, id uuid.UUID) (*PAMCredential, string, error) {
	const q = `SELECT id,org_id,name,description,credential_type,username,
		encrypted_secret,target_host,checkout_duration,require_access_request,
		is_active,rotation_interval_days,last_rotated_at,created_at,updated_at
		FROM pam_credentials WHERE org_id=$1 AND id=$2`
	var c PAMCredential
	var enc string
	err := r.pool.QueryRow(ctx, q, orgID, id).Scan(
		&c.ID, &c.OrgID, &c.Name, &c.Description, &c.CredentialType, &c.Username,
		&enc, &c.TargetHost, &c.CheckoutDuration, &c.RequireAccessRequest,
		&c.IsActive, &c.RotationIntervalDays, &c.LastRotatedAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, "", err
	}
	return &c, enc, nil
}

// ListCredentials returns all credentials for an org (no secrets).
func (r *PAMRepository) ListCredentials(ctx context.Context, orgID uuid.UUID) ([]PAMCredential, error) {
	const q = `SELECT id,org_id,name,description,credential_type,username,
		target_host,checkout_duration,require_access_request,
		is_active,rotation_interval_days,last_rotated_at,created_at,updated_at
		FROM pam_credentials WHERE org_id=$1 ORDER BY name ASC`
	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []PAMCredential
	for rows.Next() {
		var c PAMCredential
		if err := rows.Scan(
			&c.ID, &c.OrgID, &c.Name, &c.Description, &c.CredentialType, &c.Username,
			&c.TargetHost, &c.CheckoutDuration, &c.RequireAccessRequest,
			&c.IsActive, &c.RotationIntervalDays, &c.LastRotatedAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		results = append(results, c)
	}
	return results, nil
}

// UpdateCredential updates credential metadata. Pass empty string for encryptedSecret to skip rotation.
func (r *PAMRepository) UpdateCredential(ctx context.Context, orgID, id uuid.UUID,
	name, description, username, targetHost *string,
	checkoutDuration *int, requireAccessRequest *bool, isActive *bool,
	rotationIntervalDays *int,
	encryptedSecret string,
) error {
	const q = `
		UPDATE pam_credentials SET
			name                   = COALESCE($3, name),
			description            = COALESCE($4, description),
			username               = COALESCE($5, username),
			target_host            = COALESCE($6, target_host),
			checkout_duration      = COALESCE($7, checkout_duration),
			require_access_request = COALESCE($8, require_access_request),
			is_active              = COALESCE($9, is_active),
			rotation_interval_days = COALESCE($10, rotation_interval_days),
			encrypted_secret       = CASE WHEN $11 != '' THEN $11 ELSE encrypted_secret END,
			last_rotated_at        = CASE WHEN $11 != '' THEN NOW() ELSE last_rotated_at END,
			updated_at             = NOW()
		WHERE org_id=$1 AND id=$2`
	_, err := r.pool.Exec(ctx, q,
		orgID, id, name, description, username, targetHost,
		checkoutDuration, requireAccessRequest, isActive, rotationIntervalDays, encryptedSecret,
	)
	return err
}

// DeleteCredential removes a credential.
func (r *PAMRepository) DeleteCredential(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM pam_credentials WHERE org_id=$1 AND id=$2`, orgID, id)
	return err
}

// CheckoutCredential creates a checkout record and returns the encrypted secret.
func (r *PAMRepository) CheckoutCredential(ctx context.Context, orgID, credID, userID uuid.UUID, accessRequestID *uuid.UUID, reason string, durationMinutes int) (*PAMCredentialCheckout, string, error) {
	_, encSecret, err := r.GetCredential(ctx, orgID, credID)
	if err != nil {
		return nil, "", err
	}

	expiresAt := time.Now().Add(time.Duration(durationMinutes) * time.Minute)
	const q = `
		INSERT INTO pam_credential_checkouts
			(credential_id, org_id, user_id, access_request_id, reason, expires_at)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),$6)
		RETURNING id, checked_out_at`
	var co PAMCredentialCheckout
	co.CredentialID = credID
	co.OrgID = orgID
	co.UserID = userID
	co.AccessRequestID = accessRequestID
	co.ExpiresAt = expiresAt
	if reason != "" {
		co.Reason = &reason
	}
	if err := r.pool.QueryRow(ctx, q,
		credID, orgID, userID, accessRequestID, reason, expiresAt,
	).Scan(&co.ID, &co.CheckedOutAt); err != nil {
		return nil, "", err
	}
	return &co, encSecret, nil
}

// ReturnCheckout marks a checkout as returned.
func (r *PAMRepository) ReturnCheckout(ctx context.Context, orgID, checkoutID uuid.UUID) error {
	const q = `
		UPDATE pam_credential_checkouts co
		SET returned_at = NOW()
		FROM pam_credentials c
		WHERE co.id=$2 AND co.org_id=$1
		  AND co.credential_id = c.id AND c.org_id=$1
		  AND co.returned_at IS NULL`
	_, err := r.pool.Exec(ctx, q, orgID, checkoutID)
	return err
}

// ListActiveCheckouts returns currently-active checkouts for a credential.
func (r *PAMRepository) ListActiveCheckouts(ctx context.Context, credID uuid.UUID) ([]PAMCredentialCheckout, error) {
	const q = `SELECT id,credential_id,org_id,user_id,access_request_id,reason,checked_out_at,expires_at,returned_at
		FROM pam_credential_checkouts
		WHERE credential_id=$1 AND returned_at IS NULL AND expires_at > NOW()`
	rows, err := r.pool.Query(ctx, q, credID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []PAMCredentialCheckout
	for rows.Next() {
		var co PAMCredentialCheckout
		if err := rows.Scan(
			&co.ID, &co.CredentialID, &co.OrgID, &co.UserID, &co.AccessRequestID,
			&co.Reason, &co.CheckedOutAt, &co.ExpiresAt, &co.ReturnedAt,
		); err != nil {
			return nil, err
		}
		results = append(results, co)
	}
	return results, nil
}

// ── Vault SSH CA Config ───────────────────────────────────────────────────────

// GetSSHCAConfig returns the SSH CA config for an org (encrypted token NOT included).
func (r *PAMRepository) GetSSHCAConfig(ctx context.Context, orgID uuid.UUID) (*PAMSSHCAConfig, error) {
	const q = `SELECT org_id,vault_addr,vault_mount,vault_role,ca_public_key,
		cert_ttl_seconds,require_access_request,created_at,updated_at
		FROM pam_ssh_ca_configs WHERE org_id=$1`
	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	var c PAMSSHCAConfig
	if err := rows.Scan(
		&c.OrgID, &c.VaultAddr, &c.VaultMount, &c.VaultRole, &c.CAPublicKey,
		&c.CertTTLSeconds, &c.RequireAccessRequest, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

// GetSSHCAConfigWithToken returns the full config including the encrypted vault token.
func (r *PAMRepository) GetSSHCAConfigWithToken(ctx context.Context, orgID uuid.UUID) (*PAMSSHCAConfig, string, error) {
	const q = `SELECT org_id,vault_addr,encrypted_vault_token,vault_mount,vault_role,ca_public_key,
		cert_ttl_seconds,require_access_request,created_at,updated_at
		FROM pam_ssh_ca_configs WHERE org_id=$1`
	var c PAMSSHCAConfig
	var encToken string
	err := r.pool.QueryRow(ctx, q, orgID).Scan(
		&c.OrgID, &c.VaultAddr, &encToken, &c.VaultMount, &c.VaultRole, &c.CAPublicKey,
		&c.CertTTLSeconds, &c.RequireAccessRequest, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, "", err
	}
	return &c, encToken, nil
}

// UpsertSSHCAConfig creates or updates the Vault SSH CA config for an org.
func (r *PAMRepository) UpsertSSHCAConfig(ctx context.Context, orgID uuid.UUID,
	vaultAddr, encryptedToken, vaultMount, vaultRole string,
	certTTL int, requireAccessRequest bool,
) error {
	const q = `
		INSERT INTO pam_ssh_ca_configs
			(org_id, vault_addr, encrypted_vault_token, vault_mount, vault_role,
			 cert_ttl_seconds, require_access_request)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (org_id) DO UPDATE SET
			vault_addr             = EXCLUDED.vault_addr,
			encrypted_vault_token  = EXCLUDED.encrypted_vault_token,
			vault_mount            = EXCLUDED.vault_mount,
			vault_role             = EXCLUDED.vault_role,
			cert_ttl_seconds       = EXCLUDED.cert_ttl_seconds,
			require_access_request = EXCLUDED.require_access_request,
			updated_at             = NOW()`
	_, err := r.pool.Exec(ctx, q,
		orgID, vaultAddr, encryptedToken, vaultMount, vaultRole,
		certTTL, requireAccessRequest,
	)
	return err
}

// UpdateSSHCAPublicKey caches the CA public key fetched from Vault.
func (r *PAMRepository) UpdateSSHCAPublicKey(ctx context.Context, orgID uuid.UUID, pubKey string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE pam_ssh_ca_configs SET ca_public_key=$2, updated_at=NOW() WHERE org_id=$1`,
		orgID, pubKey,
	)
	return err
}

// DeleteSSHCAConfig removes the SSH CA config for an org.
func (r *PAMRepository) DeleteSSHCAConfig(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM pam_ssh_ca_configs WHERE org_id=$1`, orgID)
	return err
}

// ── Scan helpers ──────────────────────────────────────────────────────────────

func scanPAMSessionRow(rows interface{ Scan(...any) error }) (*PAMSession, error) {
	var s PAMSession
	if err := rows.Scan(
		&s.ID, &s.OrgID, &s.AccessRequestID, &s.UserID, &s.SessionType,
		&s.TargetHost, &s.TargetPort, &s.TargetUser, &s.ClientIP, &s.EventCount,
		&s.StartedAt, &s.EndedAt,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

func scanPAMAccessRequest(rows interface{ Scan(...any) error }, ar *PAMAccessRequest) error {
	return rows.Scan(
		&ar.ID, &ar.OrgID, &ar.RequesterID,
		&ar.ResourceType, &ar.ResourceID, &ar.ResourceName,
		&ar.Justification, &ar.RequestedDuration, &ar.Status,
		&ar.ApprovedBy, &ar.ApproveNote,
		&ar.GrantedAt, &ar.ExpiresAt,
		&ar.RevokedAt, &ar.RevokeReason,
		&ar.CreatedAt, &ar.UpdatedAt,
		&ar.IsBreakGlass,
	)
}

// ── Credential Rotation ───────────────────────────────────────────────────────

// ListDueForRotation returns all credentials whose auto-rotation is due.
// A credential is due when rotation_interval_days IS NOT NULL and
// (last_rotated_at IS NULL OR last_rotated_at + interval <= NOW()).
func (r *PAMRepository) ListDueForRotation(ctx context.Context) ([]PAMCredential, error) {
	const q = `
		SELECT id,org_id,name,description,credential_type,username,
		       target_host,checkout_duration,require_access_request,
		       is_active,rotation_interval_days,last_rotated_at,created_at,updated_at
		FROM pam_credentials
		WHERE is_active = TRUE
		  AND rotation_interval_days IS NOT NULL
		  AND (
		      last_rotated_at IS NULL
		      OR last_rotated_at + (rotation_interval_days || ' days')::INTERVAL <= NOW()
		  )
		ORDER BY last_rotated_at ASC NULLS FIRST`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []PAMCredential
	for rows.Next() {
		var c PAMCredential
		if err := rows.Scan(
			&c.ID, &c.OrgID, &c.Name, &c.Description, &c.CredentialType, &c.Username,
			&c.TargetHost, &c.CheckoutDuration, &c.RequireAccessRequest,
			&c.IsActive, &c.RotationIntervalDays, &c.LastRotatedAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		results = append(results, c)
	}
	return results, nil
}

// ListStaleCredentials returns all active credentials across all orgs that have
// a rotation_interval_days set but have not been rotated within staleDays days.
// These are credentials overdue for manual rotation (ssh_key/certificate types)
// or where auto-rotation has repeatedly failed.
func (r *PAMRepository) ListStaleCredentials(ctx context.Context, staleDays int) ([]PAMCredential, error) {
	const q = `
		SELECT id,org_id,name,description,credential_type,username,
		       target_host,checkout_duration,require_access_request,
		       is_active,rotation_interval_days,last_rotated_at,created_at,updated_at
		FROM pam_credentials
		WHERE is_active = TRUE
		  AND rotation_interval_days IS NOT NULL
		  AND (
		      last_rotated_at IS NULL
		      OR last_rotated_at < NOW() - ($1 * INTERVAL '1 day')
		  )
		ORDER BY last_rotated_at ASC NULLS FIRST`
	rows, err := r.pool.Query(ctx, q, staleDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []PAMCredential
	for rows.Next() {
		var c PAMCredential
		if err := rows.Scan(
			&c.ID, &c.OrgID, &c.Name, &c.Description, &c.CredentialType, &c.Username,
			&c.TargetHost, &c.CheckoutDuration, &c.RequireAccessRequest,
			&c.IsActive, &c.RotationIntervalDays, &c.LastRotatedAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		results = append(results, c)
	}
	return results, nil
}

// ListLongRunningSessions returns all open sessions (ended_at IS NULL) across all
// orgs that have been running for longer than maxHours.
func (r *PAMRepository) ListLongRunningSessions(ctx context.Context, maxHours int) ([]PAMSession, error) {
	const q = `
		SELECT id,org_id,access_request_id,user_id,session_type,
		       target_host,target_port,target_user,client_ip,
		       event_count,started_at,ended_at
		FROM pam_sessions
		WHERE ended_at IS NULL
		  AND started_at < NOW() - ($1 * INTERVAL '1 hour')
		ORDER BY started_at ASC`
	rows, err := r.pool.Query(ctx, q, maxHours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []PAMSession
	for rows.Next() {
		var s PAMSession
		if err := rows.Scan(
			&s.ID, &s.OrgID, &s.AccessRequestID, &s.UserID, &s.SessionType,
			&s.TargetHost, &s.TargetPort, &s.TargetUser, &s.ClientIP,
			&s.EventCount, &s.StartedAt, &s.EndedAt,
		); err != nil {
			return nil, err
		}
		results = append(results, s)
	}
	return results, nil
}

// RotateCredentialSecret updates the encrypted secret and last_rotated_at timestamp.
func (r *PAMRepository) RotateCredentialSecret(ctx context.Context, credID uuid.UUID, encryptedSecret string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE pam_credentials SET encrypted_secret=$2, last_rotated_at=NOW(), updated_at=NOW() WHERE id=$1`,
		credID, encryptedSecret,
	)
	return err
}

// LogRotation appends a rotation event to the audit log.
func (r *PAMRepository) LogRotation(ctx context.Context, credID, orgID uuid.UUID, rotatedBy, rotationType, note string) error {
	var notePtr *string
	if note != "" {
		notePtr = &note
	}
	_, err := r.pool.Exec(ctx,
		`INSERT INTO pam_credential_rotation_log (credential_id, org_id, rotated_by, rotation_type, note)
		 VALUES ($1,$2,$3,$4,$5)`,
		credID, orgID, rotatedBy, rotationType, notePtr,
	)
	return err
}

// ListRotationLog returns the most recent rotation events for a credential.
func (r *PAMRepository) ListRotationLog(ctx context.Context, orgID, credID uuid.UUID, limit int) ([]PAMCredentialRotationLog, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	const q = `
		SELECT id,credential_id,org_id,rotated_by,rotation_type,note,rotated_at
		FROM pam_credential_rotation_log
		WHERE org_id=$1 AND credential_id=$2
		ORDER BY rotated_at DESC
		LIMIT $3`
	rows, err := r.pool.Query(ctx, q, orgID, credID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []PAMCredentialRotationLog
	for rows.Next() {
		var l PAMCredentialRotationLog
		if err := rows.Scan(&l.ID, &l.CredentialID, &l.OrgID, &l.RotatedBy, &l.RotationType, &l.Note, &l.RotatedAt); err != nil {
			return nil, err
		}
		results = append(results, l)
	}
	return results, nil
}

// ── Break-Glass Emergency Access ──────────────────────────────────────────────

// GetBreakGlassConfig returns the break-glass policy for an org.
// If no explicit config exists, safe defaults are returned (enabled, max 3/week).
func (r *PAMRepository) GetBreakGlassConfig(ctx context.Context, orgID uuid.UUID) (*BreakGlassConfig, error) {
	const q = `
		SELECT org_id, enabled, max_uses_per_week,
		       require_justification, notify_on_use,
		       created_at, updated_at
		FROM pam_break_glass_configs
		WHERE org_id = $1`
	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return &BreakGlassConfig{
			OrgID:                orgID,
			Enabled:              true,
			MaxUsesPerWeek:       3,
			RequireJustification: true,
			NotifyOnUse:          true,
		}, nil
	}
	var cfg BreakGlassConfig
	err = rows.Scan(
		&cfg.OrgID, &cfg.Enabled, &cfg.MaxUsesPerWeek,
		&cfg.RequireJustification, &cfg.NotifyOnUse,
		&cfg.CreatedAt, &cfg.UpdatedAt,
	)
	return &cfg, err
}

// UpsertBreakGlassConfig saves (or overwrites) the break-glass policy for an org.
func (r *PAMRepository) UpsertBreakGlassConfig(ctx context.Context, cfg *BreakGlassConfig) error {
	const q = `
		INSERT INTO pam_break_glass_configs
		    (org_id, enabled, max_uses_per_week, require_justification, notify_on_use)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (org_id) DO UPDATE SET
		    enabled               = EXCLUDED.enabled,
		    max_uses_per_week     = EXCLUDED.max_uses_per_week,
		    require_justification = EXCLUDED.require_justification,
		    notify_on_use         = EXCLUDED.notify_on_use,
		    updated_at            = NOW()
		RETURNING created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		cfg.OrgID, cfg.Enabled, cfg.MaxUsesPerWeek,
		cfg.RequireJustification, cfg.NotifyOnUse,
	).Scan(&cfg.CreatedAt, &cfg.UpdatedAt)
}

// CountBreakGlassUsesThisWeek returns the number of break-glass access requests
// created in the current ISO week for the given org.
func (r *PAMRepository) CountBreakGlassUsesThisWeek(ctx context.Context, orgID uuid.UUID) (int, error) {
	const q = `
		SELECT COUNT(*) FROM pam_access_requests
		WHERE org_id       = $1
		  AND is_break_glass = TRUE
		  AND created_at  >= date_trunc('week', NOW())`
	var n int
	err := r.pool.QueryRow(ctx, q, orgID).Scan(&n)
	return n, err
}

// CreateBreakGlassRequest inserts a pre-approved emergency access request.
// The request bypasses JIT approval: status is 'active' and granted_at/expires_at
// are set immediately. is_break_glass is stored as TRUE.
func (r *PAMRepository) CreateBreakGlassRequest(ctx context.Context, req *PAMAccessRequest) error {
	const q = `
		INSERT INTO pam_access_requests
		    (org_id, requester_id, resource_type, resource_id, resource_name,
		     justification, requested_duration, status, is_break_glass,
		     granted_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'active',TRUE,
		        NOW(), NOW() + ($7 || ' minutes')::INTERVAL)
		RETURNING id, status, granted_at, expires_at, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		req.OrgID, req.RequesterID, req.ResourceType, req.ResourceID,
		req.ResourceName, req.Justification, req.RequestedDuration,
	).Scan(&req.ID, &req.Status, &req.GrantedAt, &req.ExpiresAt, &req.CreatedAt, &req.UpdatedAt)
}
