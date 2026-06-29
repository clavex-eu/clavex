package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuthCode is the DB representation of an authorization code.
type AuthCode struct {
	ID            uuid.UUID
	OrgID         uuid.UUID
	ClientID      string
	UserID        uuid.UUID
	CodeHash      string
	RedirectURI   string
	Scope         string
	Nonce         string
	PKCEChallenge string
	PKCEMethod    string
	AuthTime      int64
	ExpiresAt     time.Time
	UsedAt        *time.Time
	CreatedAt     time.Time
	// AuthorizationDetails is the RFC 9396 RAR array (nil = not a RAR request).
	AuthorizationDetails []map[string]any
	// Acr is the Authentication Context Class Reference value achieved (OIDC Core §2).
	Acr string
	// AccessTokenJTI is the jti of the access token issued from this code.
	// Set after the token exchange; used for revocation on code replay (RFC 6749 §4.1.2).
	AccessTokenJTI string
	// RefreshFamilyID is the family_id of the refresh token issued from this code.
	// Set alongside AccessTokenJTI; used for targeted family revocation on replay.
	RefreshFamilyID uuid.UUID
	// ClaimsParam is the raw JSON value of the OIDC claims request parameter
	// (OIDC Core §5.5). Forwarded to the access token for userinfo claim delivery.
	ClaimsParam string
	// ExtraClaims carries claims injected by the login flow engine.
	ExtraClaims map[string]any
	// DpopJKT is the JWK Thumbprint committed at authorization time via dpop_jkt
	// (RFC 9449 §10). If set, the token endpoint must receive a DPoP proof whose
	// JWK thumbprint matches this value.
	DpopJKT string
}

// CreateAuthCodeParams holds the fields for creating an authorization code.
type CreateAuthCodeParams struct {
	OrgID         uuid.UUID
	ClientID      string
	UserID        uuid.UUID
	CodeHash      string
	RedirectURI   string
	Scope         string
	Nonce         string
	PKCEChallenge string
	PKCEMethod    string
	AuthTime      int64
	ExpiresAt     time.Time
	// AuthorizationDetails is the optional RFC 9396 RAR JSON array.
	AuthorizationDetails []map[string]any
	// Acr is the ACR value to store (empty string = not set).
	Acr string
	// ClaimsParam is the raw JSON of the OIDC claims request parameter (OIDC Core §5.5).
	ClaimsParam string
	// ExtraClaims carries claims injected by the login flow engine.
	ExtraClaims map[string]any
	// DpopJKT is the JWK Thumbprint committed via dpop_jkt in the authorization request.
	DpopJKT string
}

// AuthCodeRepository manages authorization code persistence.
type AuthCodeRepository struct {
	pool *pgxpool.Pool
}

func NewAuthCodeRepository(pool *pgxpool.Pool) *AuthCodeRepository {
	return &AuthCodeRepository{pool: pool}
}

func (r *AuthCodeRepository) Create(ctx context.Context, p CreateAuthCodeParams) error {
	var authDetailsJSON []byte
	if len(p.AuthorizationDetails) > 0 {
		b, err := json.Marshal(p.AuthorizationDetails)
		if err != nil {
			return fmt.Errorf("marshal authorization_details: %w", err)
		}
		authDetailsJSON = b
	}
	extraClaimsJSON := []byte("{}")
	if len(p.ExtraClaims) > 0 {
		b, err := json.Marshal(p.ExtraClaims)
		if err != nil {
			return fmt.Errorf("marshal extra_claims: %w", err)
		}
		extraClaimsJSON = b
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO authorization_codes
			(org_id, client_id, user_id, code_hash, redirect_uri, scope, nonce, pkce_challenge, pkce_method, auth_time, expires_at, authorization_details, acr, claims_param, extra_claims, dpop_jkt)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
	`, p.OrgID, p.ClientID, p.UserID, p.CodeHash, p.RedirectURI, p.Scope,
		nullStr(p.Nonce), nullStr(p.PKCEChallenge), nullStr(p.PKCEMethod), p.AuthTime, p.ExpiresAt, authDetailsJSON, p.Acr,
		nullStr(p.ClaimsParam), extraClaimsJSON, nullStr(p.DpopJKT),
	)
	return err
}

// Consume atomically marks the code as used and returns it.
// Returns an error if not found or already used.
func (r *AuthCodeRepository) Consume(ctx context.Context, codeHash string) (*AuthCode, error) {
	ac := &AuthCode{}
	var authDetailsRaw []byte
	var extraClaimsRaw []byte
	err := r.pool.QueryRow(ctx, `
		UPDATE authorization_codes
		SET used_at = NOW()
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > NOW()
		RETURNING id, org_id, client_id, user_id, code_hash, redirect_uri, scope,
		          COALESCE(nonce,''), COALESCE(pkce_challenge,''), COALESCE(pkce_method,''),
		          COALESCE(auth_time,0), expires_at, used_at, created_at, authorization_details,
		          COALESCE(acr,''), COALESCE(claims_param,''), COALESCE(extra_claims,'{}'),
		          COALESCE(dpop_jkt,'')
	`, codeHash).Scan(
		&ac.ID, &ac.OrgID, &ac.ClientID, &ac.UserID, &ac.CodeHash,
		&ac.RedirectURI, &ac.Scope, &ac.Nonce, &ac.PKCEChallenge, &ac.PKCEMethod,
		&ac.AuthTime, &ac.ExpiresAt, &ac.UsedAt, &ac.CreatedAt, &authDetailsRaw,
		&ac.Acr, &ac.ClaimsParam, &extraClaimsRaw, &ac.DpopJKT,
	)
	if err != nil {
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	if len(authDetailsRaw) > 0 {
		_ = json.Unmarshal(authDetailsRaw, &ac.AuthorizationDetails)
	}
	if len(extraClaimsRaw) > 0 && string(extraClaimsRaw) != "{}" {
		_ = json.Unmarshal(extraClaimsRaw, &ac.ExtraClaims)
	}
	return ac, nil
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// GetUsedByHash returns a previously-consumed authorization code so the caller
// can revoke the tokens that were issued from it (RFC 6749 §4.1.2).
// Returns nil, nil if no used code with that hash exists.
func (r *AuthCodeRepository) GetUsedByHash(ctx context.Context, codeHash string) (*AuthCode, error) {
	ac := &AuthCode{}
	var jti *string
	var familyID *uuid.UUID
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, client_id, user_id, code_hash,
		       COALESCE(access_token_jti,''), refresh_family_id
		FROM   authorization_codes
		WHERE  code_hash = $1 AND used_at IS NOT NULL
	`, codeHash).Scan(&ac.ID, &ac.OrgID, &ac.ClientID, &ac.UserID, &ac.CodeHash, &jti, &familyID)
	if err != nil {
		return nil, nil //nolint:nilerr // not found → treat same as not used
	}
	if jti != nil {
		ac.AccessTokenJTI = *jti
	}
	if familyID != nil {
		ac.RefreshFamilyID = *familyID
	}
	return ac, nil
}

// SetRevocationData records the access token JTI and refresh token family_id
// from a successful code exchange. Called asynchronously; both values are used
// together for targeted revocation if the code is later replayed (RFC 6749 §4.1.2).
func (r *AuthCodeRepository) SetRevocationData(ctx context.Context, codeHash, jti string, familyID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE authorization_codes SET access_token_jti = $1, refresh_family_id = $2 WHERE code_hash = $3`,
		jti, familyID, codeHash,
	)
	return err
}
