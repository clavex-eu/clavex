package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RefreshToken is the DB representation of a refresh token.
type RefreshToken struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	ClientID   string
	UserID     *uuid.UUID // nil for client_credentials
	FamilyID   uuid.UUID
	TokenHash  string
	Scope      string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *uuid.UUID
	CreatedAt  time.Time
	// DPoP key binding (RFC 9449 §6): JWK Thumbprint of the key bound at
	// authorization time. Empty for non-DPoP tokens.
	DpopJKT string
	// MTLSX5TS256 is the RFC 8705 §3.1 thumbprint of the TLS client certificate
	// presented during the initial authorization code exchange.  Carried forward
	// on every rotation so the new access token can be certificate-bound even
	// when the client does not re-present its cert on subsequent refresh requests.
	MTLSX5TS256 string
	// AttestationJKT is the OAuth2-ATCA §10.3 JWK Thumbprint of the client
	// instance key (cnf.jwk) from the attestation JWT used at issuance. Empty
	// for non-attest_jwt_client_auth clients. Carried forward on every rotation
	// to enforce that the same instance key must be used throughout the token family.
	AttestationJKT string
	// Device / session metadata (migration 000020)
	UserAgent  *string
	IPAddress  *string
	DeviceName *string
	LastSeenAt *time.Time
}

// CreateRefreshTokenParams holds the fields for creating a refresh token.
type CreateRefreshTokenParams struct {
	OrgID      uuid.UUID
	ClientID   string
	UserID     *uuid.UUID
	FamilyID   uuid.UUID
	TokenHash  string
	Scope      string
	ExpiresAt  time.Time
	ReplacesID *uuid.UUID // ID of the token this replaces (for rotation chain)
	// DPoP key binding: JWK Thumbprint from the DPoP proof used at authorization
	// or at the previous refresh.  Empty for non-DPoP tokens (RFC 9449 §6).
	DpopJKT string
	// MTLSX5TS256 is the RFC 8705 §3.1 x5t#S256 thumbprint of the mTLS client
	// certificate.  Propagated on every rotation so new access tokens remain
	// certificate-bound without requiring the cert to be re-presented.
	MTLSX5TS256 string
	// AttestationJKT is the OAuth2-ATCA §10.3 JWK Thumbprint of the client
	// instance key (cnf.jwk) from the attestation JWT. Empty for non-attestation clients.
	AttestationJKT string
	// Optional device metadata
	UserAgent  *string
	IPAddress  *string
	DeviceName *string
}

// RefreshTokenRepository manages refresh token persistence.
type RefreshTokenRepository struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepository(pool *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{pool: pool}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, p CreateRefreshTokenParams) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO refresh_tokens
			(org_id, client_id, user_id, family_id, token_hash, scope, expires_at,
			 dpop_jkt, mtls_x5t_s256, attest_jkt, user_agent, ip_address, device_name, last_seen_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
	`, p.OrgID, p.ClientID, p.UserID, p.FamilyID, p.TokenHash, p.Scope, p.ExpiresAt,
		nullStr(p.DpopJKT), nullStr(p.MTLSX5TS256), p.AttestationJKT,
		p.UserAgent, p.IPAddress, p.DeviceName,
	)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}

	// Mark the old token as replaced
	if p.ReplacesID != nil {
		newID := uuid.UUID{}
		// We need the new ID from the insert — use RETURNING instead
		_ = newID // handled below via separate query for simplicity
		_, _ = r.pool.Exec(ctx,
			`UPDATE refresh_tokens SET replaced_by = (SELECT id FROM refresh_tokens WHERE token_hash = $1) WHERE id = $2`,
			p.TokenHash, *p.ReplacesID,
		)
	}
	return nil
}

func (r *RefreshTokenRepository) GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	rt := &RefreshToken{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, client_id, user_id, family_id, token_hash, scope, expires_at, revoked_at, replaced_by, created_at,
		       COALESCE(dpop_jkt,''), COALESCE(mtls_x5t_s256,''), COALESCE(attest_jkt,''),
		       user_agent, ip_address, device_name, last_seen_at
		FROM refresh_tokens WHERE token_hash = $1
	`, tokenHash).Scan(
		&rt.ID, &rt.OrgID, &rt.ClientID, &rt.UserID, &rt.FamilyID,
		&rt.TokenHash, &rt.Scope, &rt.ExpiresAt, &rt.RevokedAt, &rt.ReplacedBy, &rt.CreatedAt,
		&rt.DpopJKT, &rt.MTLSX5TS256, &rt.AttestationJKT,
		&rt.UserAgent, &rt.IPAddress, &rt.DeviceName, &rt.LastSeenAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	return rt, nil
}

// GetByID returns a refresh token by its primary key.
func (r *RefreshTokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*RefreshToken, error) {
	rt := &RefreshToken{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, client_id, user_id, family_id, token_hash, scope, expires_at, revoked_at, replaced_by, created_at,
		       COALESCE(dpop_jkt,''), COALESCE(mtls_x5t_s256,''), COALESCE(attest_jkt,''),
		       user_agent, ip_address, device_name, last_seen_at
		FROM refresh_tokens WHERE id = $1
	`, id).Scan(
		&rt.ID, &rt.OrgID, &rt.ClientID, &rt.UserID, &rt.FamilyID,
		&rt.TokenHash, &rt.Scope, &rt.ExpiresAt, &rt.RevokedAt, &rt.ReplacedBy, &rt.CreatedAt,
		&rt.DpopJKT, &rt.MTLSX5TS256, &rt.AttestationJKT,
		&rt.UserAgent, &rt.IPAddress, &rt.DeviceName, &rt.LastSeenAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get refresh token by id: %w", err)
	}
	return rt, nil
}

// RevokeByID marks a single refresh token as revoked.
func (r *RefreshTokenRepository) RevokeByID(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1`,
		id,
	)
	return err
}

// RevokeFamilyByID revokes all tokens in a family (used on replay detection).
func (r *RefreshTokenRepository) RevokeFamilyByID(ctx context.Context, familyID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL`,
		familyID,
	)
	return err
}

// ActiveSession is a view of a refresh token used by the sessions admin API.
type ActiveSession struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	ClientID   string     `json:"client_id"`
	UserID     *uuid.UUID `json:"user_id,omitempty"`
	FamilyID   uuid.UUID  `json:"family_id"`
	Scope      string     `json:"scope"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	IPAddress  *string    `json:"ip_address,omitempty"`
	DeviceName *string    `json:"device_name,omitempty"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

// ListActiveByOrg returns non-revoked, non-expired refresh tokens for an org.
func (r *RefreshTokenRepository) ListActiveByOrg(ctx context.Context, orgID uuid.UUID) ([]*ActiveSession, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, client_id, user_id, family_id, scope, expires_at, created_at,
		       user_agent, ip_address, device_name, last_seen_at
		FROM refresh_tokens
		WHERE org_id = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list active sessions: %w", err)
	}
	defer rows.Close()
	var sessions []*ActiveSession
	for rows.Next() {
		s := &ActiveSession{}
		if err := rows.Scan(&s.ID, &s.OrgID, &s.ClientID, &s.UserID, &s.FamilyID, &s.Scope, &s.ExpiresAt, &s.CreatedAt,
			&s.UserAgent, &s.IPAddress, &s.DeviceName, &s.LastSeenAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	if sessions == nil {
		sessions = []*ActiveSession{}
	}
	return sessions, rows.Err()
}

// ListActiveByUser returns non-revoked, non-expired refresh tokens for a specific user.
func (r *RefreshTokenRepository) ListActiveByUser(ctx context.Context, orgID, userID uuid.UUID) ([]*ActiveSession, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, client_id, user_id, family_id, scope, expires_at, created_at,
		       user_agent, ip_address, device_name, last_seen_at
		FROM refresh_tokens
		WHERE org_id = $1
		  AND user_id = $2
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		ORDER BY created_at DESC
	`, orgID, userID)
	if err != nil {
		return nil, fmt.Errorf("list active sessions by user: %w", err)
	}
	defer rows.Close()
	var sessions []*ActiveSession
	for rows.Next() {
		s := &ActiveSession{}
		if err := rows.Scan(&s.ID, &s.OrgID, &s.ClientID, &s.UserID, &s.FamilyID, &s.Scope, &s.ExpiresAt, &s.CreatedAt,
			&s.UserAgent, &s.IPAddress, &s.DeviceName, &s.LastSeenAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	if sessions == nil {
		sessions = []*ActiveSession{}
	}
	return sessions, rows.Err()
}

// RevokeAllByUser revokes every active refresh token for a given user.
func (r *RefreshTokenRepository) RevokeAllByUser(ctx context.Context, orgID, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE org_id = $1 AND user_id = $2 AND revoked_at IS NULL
	`, orgID, userID)
	return err
}

// RevokeByUserAndClient revokes all active refresh tokens for a specific
// (org, user, client) triple.  Used to implement RFC 6749 §4.1.2 token
// revocation when an authorization code is detected to have been reused.
func (r *RefreshTokenRepository) RevokeByUserAndClient(ctx context.Context, orgID, userID uuid.UUID, clientID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE org_id = $1 AND user_id = $2 AND client_id = $3 AND revoked_at IS NULL
	`, orgID, userID, clientID)
	return err
}

// RevokeAllByUserExcept revokes all sessions for a user except the specified one.
// Used for "sign out all other sessions" / "revoke all except current".
func (r *RefreshTokenRepository) RevokeAllByUserExcept(ctx context.Context, orgID, userID, exceptID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE org_id = $1 AND user_id = $2 AND id != $3 AND revoked_at IS NULL
	`, orgID, userID, exceptID)
	return err
}

// UpdateLastSeen refreshes the last_seen_at timestamp for a token (best-effort).
func (r *RefreshTokenRepository) UpdateLastSeen(ctx context.Context, id uuid.UUID) {
	_, _ = r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET last_seen_at = NOW() WHERE id = $1`,
		id,
	)
}

// SetDeviceInfo stores user-agent and IP on a refresh token identified by its
// plain-text value (we re-hash here). Best-effort — errors are silently ignored.
func (r *RefreshTokenRepository) SetDeviceInfoByHash(ctx context.Context, tokenHash, userAgent, ipAddress string) {
	ua := &userAgent
	ip := &ipAddress
	if userAgent == "" {
		ua = nil
	}
	if ipAddress == "" {
		ip = nil
	}
	_, _ = r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET user_agent = $1, ip_address = $2, last_seen_at = NOW() WHERE token_hash = $3`,
		ua, ip, tokenHash,
	)
}
