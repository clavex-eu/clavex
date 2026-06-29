package repository

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CIBARequest is a row from the ciba_requests table.
type CIBARequest struct {
	AuthReqID      string
	OrgID          uuid.UUID
	ClientID       string
	UserID         *uuid.UUID // nil until resolved from login_hint
	Scope          string
	BindingMessage *string
	LoginHint      *string
	Status         string // "pending" | "approved" | "denied"
	Interval       int    // minimum polling interval in seconds
	ExpiresAt      time.Time
	CreatedAt      time.Time
	// VPClaims holds the verified credential claims from the OID4VP presentation
	// submitted as part of a CIBA+OID4VP SCA flow. Nil for classic CIBA.
	VPClaims map[string]interface{}
	// ACR is the Authentication Context Class Reference value achieved when
	// VP-based SCA was used (e.g. "urn:clavex:acr:oid4vp-credential").
	// Empty for classic CIBA.
	ACR string
}

// CIBARepository manages persistence for ciba_requests.
type CIBARepository struct {
	pool *pgxpool.Pool
}

// NewCIBARepository creates a new CIBARepository.
func NewCIBARepository(pool *pgxpool.Pool) *CIBARepository {
	return &CIBARepository{pool: pool}
}

// generateAuthReqID produces a 32-byte URL-safe opaque identifier.
// The resulting string is 43 characters (base64url, no padding).
func generateAuthReqID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateParams holds the inputs for creating a new CIBA request.
type CIBACreateParams struct {
	OrgID          uuid.UUID
	ClientID       string
	UserID         *uuid.UUID // may be nil if hint is not yet resolved
	Scope          string
	BindingMessage string // required for FAPI2; may be empty for basic CIBA
	LoginHint      string // email or sub sent by the client
	ExpiresIn      time.Duration // typically 120 s; caller controls
	Interval       int           // polling interval in seconds (default 5)
}

// Create inserts a new CIBA request and returns the generated auth_req_id.
func (r *CIBARepository) Create(ctx context.Context, p CIBACreateParams) (string, error) {
	id, err := generateAuthReqID()
	if err != nil {
		return "", err
	}

	interval := p.Interval
	if interval <= 0 {
		interval = 5
	}
	expiresAt := time.Now().Add(p.ExpiresIn)
	if p.ExpiresIn <= 0 {
		expiresAt = time.Now().Add(120 * time.Second)
	}

	var bm, lh *string
	if p.BindingMessage != "" {
		bm = &p.BindingMessage
	}
	if p.LoginHint != "" {
		lh = &p.LoginHint
	}

	const q = `
		INSERT INTO ciba_requests
		  (auth_req_id, org_id, client_id, user_id, scope, binding_message, login_hint, interval, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = r.pool.Exec(ctx, q,
		id, p.OrgID, p.ClientID, p.UserID, p.Scope,
		bm, lh, interval, expiresAt,
	)
	if err != nil {
		return "", err
	}
	return id, nil
}

// Get returns the CIBA request for authReqID or nil when not found.
func (r *CIBARepository) Get(ctx context.Context, authReqID string) (*CIBARequest, error) {
	const q = `
		SELECT auth_req_id, org_id, client_id, user_id, scope,
		       binding_message, login_hint, status, interval, expires_at, created_at,
		       vp_claims, acr
		FROM ciba_requests
		WHERE auth_req_id = $1`

	row := r.pool.QueryRow(ctx, q, authReqID)
	cr := &CIBARequest{}
	var vpClaimsRaw []byte
	var acrVal *string
	err := row.Scan(
		&cr.AuthReqID, &cr.OrgID, &cr.ClientID, &cr.UserID, &cr.Scope,
		&cr.BindingMessage, &cr.LoginHint, &cr.Status, &cr.Interval,
		&cr.ExpiresAt, &cr.CreatedAt,
		&vpClaimsRaw, &acrVal,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(vpClaimsRaw) > 0 {
		_ = json.Unmarshal(vpClaimsRaw, &cr.VPClaims)
	}
	if acrVal != nil {
		cr.ACR = *acrVal
	}
	return cr, nil
}

// Approve marks the CIBA request as approved, optionally setting the user_id.
// Called by the out-of-band approval API (admin or push notification handler).
// The approved user is the one resolved at request-creation time (user_id is
// NOT overwritten here) so an approver cannot substitute a different identity.
func (r *CIBARepository) Approve(ctx context.Context, authReqID string) error {
	const q = `
		UPDATE ciba_requests
		SET status = 'approved'
		WHERE auth_req_id = $1 AND status = 'pending'`
	_, err := r.pool.Exec(ctx, q, authReqID)
	return err
}

// ApproveWithVPClaims marks the CIBA request as approved and stores the
// verified credential claims and ACR value from an OID4VP presentation.
// Called automatically when the wallet completes the VP response in a
// CIBA+OID4VP SCA flow (PSD2 Level 2 Strong Customer Authentication).
func (r *CIBARepository) ApproveWithVPClaims(ctx context.Context, authReqID string, userID uuid.UUID, vpClaims map[string]interface{}, acr string) error {
	claimsJSON, err := json.Marshal(vpClaims)
	if err != nil {
		return err
	}
	const q = `
		UPDATE ciba_requests
		SET status = 'approved', user_id = $2, vp_claims = $3, acr = $4
		WHERE auth_req_id = $1 AND status = 'pending'`
	_, err = r.pool.Exec(ctx, q, authReqID, userID, claimsJSON, acr)
	return err
}

// Deny marks the CIBA request as denied.
// Called when the user rejects the backchannel authentication.
func (r *CIBARepository) Deny(ctx context.Context, authReqID string) error {
	const q = `
		UPDATE ciba_requests
		SET status = 'denied'
		WHERE auth_req_id = $1 AND status = 'pending'`
	_, err := r.pool.Exec(ctx, q, authReqID)
	return err
}

// Delete removes a CIBA request after tokens have been issued.
func (r *CIBARepository) Delete(ctx context.Context, authReqID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM ciba_requests WHERE auth_req_id = $1`, authReqID)
	return err
}

// CleanupExpired deletes all expired CIBA requests.
// Should be called periodically (e.g. every minute) by a background worker.
func (r *CIBARepository) CleanupExpired(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM ciba_requests WHERE expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ListPending returns all pending CIBA requests for an org.
// Used by the admin dashboard / approval UI.
func (r *CIBARepository) ListPending(ctx context.Context, orgID uuid.UUID) ([]*CIBARequest, error) {
	const q = `
		SELECT auth_req_id, org_id, client_id, user_id, scope,
		       binding_message, login_hint, status, interval, expires_at, created_at,
		       vp_claims, acr
		FROM ciba_requests
		WHERE org_id = $1 AND status = 'pending' AND expires_at > NOW()
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*CIBARequest
	for rows.Next() {
		cr := &CIBARequest{}
		var vpClaimsRaw []byte
		var acrVal *string
		if err := rows.Scan(
			&cr.AuthReqID, &cr.OrgID, &cr.ClientID, &cr.UserID, &cr.Scope,
			&cr.BindingMessage, &cr.LoginHint, &cr.Status, &cr.Interval,
			&cr.ExpiresAt, &cr.CreatedAt,
			&vpClaimsRaw, &acrVal,
		); err != nil {
			return nil, err
		}
		if len(vpClaimsRaw) > 0 {
			_ = json.Unmarshal(vpClaimsRaw, &cr.VPClaims)
		}
		if acrVal != nil {
			cr.ACR = *acrVal
		}
		out = append(out, cr)
	}
	return out, rows.Err()
}
