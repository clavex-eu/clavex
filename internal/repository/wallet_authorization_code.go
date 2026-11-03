package repository

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Read only the routing/selection evidence. Actual consumption and PKCE checks
// happen within the wallet grant transaction, never from this preview alone.
func (r *OID4WRepository) WalletAuthorizationCode(ctx context.Context, hash string) (*AuthCode, error) {
	ac := &AuthCode{}
	var details []byte
	err := r.pool.QueryRow(ctx, `SELECT id,org_id,client_id,user_id,code_hash,redirect_uri,scope,
 COALESCE(nonce,''),COALESCE(pkce_challenge,''),COALESCE(pkce_method,''),COALESCE(auth_time,0),
 expires_at,used_at,COALESCE(authorization_details,'[]'),COALESCE(acr,''),COALESCE(dpop_jkt,'')
 FROM sessions.authorization_codes WHERE code_hash=$1`, hash).Scan(&ac.ID, &ac.OrgID, &ac.ClientID, &ac.UserID, &ac.CodeHash, &ac.RedirectURI, &ac.Scope, &ac.Nonce, &ac.PKCEChallenge, &ac.PKCEMethod, &ac.AuthTime, &ac.ExpiresAt, &ac.UsedAt, &details, &ac.Acr, &ac.DpopJKT)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(details, &ac.AuthorizationDetails) != nil {
		return nil, pgx.ErrNoRows
	}
	return ac, nil
}
func (r *OID4WRepository) ConsumeWalletAuthorizationCode(ctx context.Context, hash string) (*AuthCode, error) {
	// The shared repository can now use this transaction. Its public API and
	// ordinary OIDC lifecycle remain unchanged.
	return NewAuthCodeRepository(r.pool).Consume(ctx, hash)
}

// LockWalletGrantForCode orders replay invalidation against refresh and issuance.
func (r *OID4WRepository) LockWalletGrantForCode(ctx context.Context, code, org uuid.UUID, client string) (*WalletIssuanceGrant, error) {
	return scanWalletGrant(r.pool.QueryRow(ctx, `SELECT `+walletGrantColumns+` FROM identity.wallet_issuance_grants g
 WHERE g.authorization_code_id=$1 AND g.org_id=$2 AND g.client_id=$3 FOR UPDATE`, code, org, client))
}
