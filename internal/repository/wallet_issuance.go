package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A grant is a stable, tenant-scoped authorization, not a particular access
// token. Rotating a token never changes its subject, configuration or deadline.
type WalletIssuanceGrant struct {
	ClientAuthMethod, AttestationJKT    string
	StatusParents                       json.RawMessage
	AuthorizationScope                  string
	AuthorizationDetails                json.RawMessage
	AuthorizationCodeID                 *uuid.UUID
	ID, OrgID, OfferID, ConfigurationID uuid.UUID
	UserID                              *uuid.UUID
	VCT, ClientID, DPoPJKT, MTLSX5TS256 string
	DeferredAllowed                     bool
	ExpiresAt                           time.Time
	RevokedAt, ClosedAt                 *time.Time
}

const walletGrantColumns = `g.id,g.org_id,g.offer_id,g.configuration_id,g.user_id,g.vct,g.client_id,g.dpop_jkt,g.mtls_x5t_s256,g.deferred_allowed,g.expires_at,g.revoked_at,g.closed_at,g.client_auth_method,g.attestation_jkt,g.status_parents,g.authorization_code_id,g.authorization_scope,g.authorization_details`

func scanWalletGrant(row pgx.Row) (*WalletIssuanceGrant, error) {
	g := &WalletIssuanceGrant{}
	err := row.Scan(&g.ID, &g.OrgID, &g.OfferID, &g.ConfigurationID, &g.UserID, &g.VCT, &g.ClientID, &g.DPoPJKT, &g.MTLSX5TS256, &g.DeferredAllowed, &g.ExpiresAt, &g.RevokedAt, &g.ClosedAt, &g.ClientAuthMethod, &g.AttestationJKT, &g.StatusParents, &g.AuthorizationCodeID, &g.AuthorizationScope, &g.AuthorizationDetails)
	return g, err
}

func (r *OID4WRepository) CreateWalletGrant(ctx context.Context, g WalletIssuanceGrant) (*WalletIssuanceGrant, error) {
	if g.ClientAuthMethod == "" {
		g.ClientAuthMethod = "none"
	}
	if len(g.AuthorizationDetails) == 0 {
		g.AuthorizationDetails = json.RawMessage(`[]`)
	}
	if len(g.StatusParents) == 0 {
		g.StatusParents = json.RawMessage(`[]`)
	}
	// Must share the token endpoint transaction with the grant/token inserts.
	if _, err := r.pool.Exec(ctx, `UPDATE identity.credential_offers SET wallet_grant_version=1 WHERE id=$1 AND org_id=$2`, g.OfferID, g.OrgID); err != nil {
		return nil, err
	}
	return scanWalletGrant(r.pool.QueryRow(ctx, `INSERT INTO identity.wallet_issuance_grants AS g
	(org_id,offer_id,configuration_id,user_id,vct,client_id,dpop_jkt,mtls_x5t_s256,deferred_allowed,expires_at,client_auth_method,attestation_jkt,status_parents,authorization_code_id,authorization_scope,authorization_details)
	VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING `+walletGrantColumns, g.OrgID, g.OfferID, g.ConfigurationID, g.UserID, g.VCT, g.ClientID, g.DPoPJKT, g.MTLSX5TS256, g.DeferredAllowed, g.ExpiresAt, g.ClientAuthMethod, g.AttestationJKT, g.StatusParents, g.AuthorizationCodeID, g.AuthorizationScope, g.AuthorizationDetails))
}

// Includes spent tokens so the caller can authenticate the sender before
// revoking a family on reuse. Never expose this lookup through an API.
func (r *OID4WRepository) WalletGrantForToken(ctx context.Context, hash, kind string) (*WalletIssuanceGrant, time.Time, *time.Time, error) {
	var id uuid.UUID
	var expires time.Time
	var used *time.Time
	err := r.pool.QueryRow(ctx, `SELECT grant_id,expires_at,used_at FROM identity.wallet_issuance_tokens WHERE token_hash=$1 AND kind=$2`, hash, kind).Scan(&id, &expires, &used)
	if err != nil {
		return nil, expires, nil, err
	}
	g, err := scanWalletGrant(r.pool.QueryRow(ctx, `SELECT `+walletGrantColumns+` FROM identity.wallet_issuance_grants g WHERE g.id=$1`, id))
	return g, expires, used, err
}

// nil means a legacy offer, which gains no refresh authorization by migration.
func (r *OID4WRepository) LockWalletGrant(ctx context.Context, offer, org uuid.UUID) (*WalletIssuanceGrant, error) {
	g, err := scanWalletGrant(r.pool.QueryRow(ctx, `SELECT `+walletGrantColumns+` FROM identity.wallet_issuance_grants g WHERE g.offer_id=$1 AND g.org_id=$2 FOR UPDATE`, offer, org))
	if errors.Is(err, pgx.ErrNoRows) {
		var generation int
		if err := r.pool.QueryRow(ctx, `SELECT wallet_grant_version FROM identity.credential_offers WHERE id=$1 AND org_id=$2`, offer, org).Scan(&generation); err != nil {
			return nil, err
		}
		if generation != 0 {
			return nil, pgx.ErrNoRows
		}
		return nil, nil
	}
	return g, err
}

func (r *OID4WRepository) AddWalletToken(ctx context.Context, g *WalletIssuanceGrant, hash, kind string, expiry time.Time) error {
	if expiry.After(g.ExpiresAt) {
		expiry = g.ExpiresAt
	}
	_, err := r.pool.Exec(ctx, `INSERT INTO identity.wallet_issuance_tokens(token_hash,grant_id,kind,expires_at) VALUES($1,$2,$3,$4)`, hash, g.ID, kind, expiry)
	return err
}

func (r *OID4WRepository) ConsumeWalletRefresh(ctx context.Context, hash string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE identity.wallet_issuance_tokens SET used_at=clock_timestamp() WHERE token_hash=$1 AND kind='refresh' AND used_at IS NULL AND expires_at>clock_timestamp()`, hash)
	if err == nil && tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return err
}

func (r *OID4WRepository) RevokeWalletGrant(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE identity.wallet_issuance_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1`, id)
	return err
}

func (r *OID4WRepository) CloseWalletGrant(ctx context.Context, offer uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE identity.wallet_issuance_grants SET closed_at=COALESCE(closed_at,clock_timestamp()) WHERE offer_id=$1`, offer)
	return err
}

// Call inside the same transaction as refresh/issuance/delivery. SHARE locks
// order the decision against disabling users, clients, tenants and configs.
func (r *OID4WRepository) CheckWalletEligibility(ctx context.Context, g *WalletIssuanceGrant, offer *models.CredentialOffer) error {
	if g.RevokedAt != nil || !time.Now().Before(g.ExpiresAt) || g.OrgID != offer.OrgID || g.OfferID != offer.ID || g.VCT != offer.VCT || (g.UserID == nil) != (offer.UserID == nil) {
		return pgx.ErrNoRows
	}
	if g.UserID != nil && *g.UserID != *offer.UserID {
		return pgx.ErrNoRows
	}
	if err := r.LockWalletEligibility(ctx, g.OrgID, g.UserID, g.ClientID, g.ConfigurationID, g.VCT, g.ClientAuthMethod); err != nil {
		return err
	}
	if g.AuthorizationCodeID != nil {
		var id string
		if err := r.pool.QueryRow(ctx, `SELECT client_id FROM identity.oidc_clients WHERE org_id=$1 AND client_id=$2
  AND 'authorization_code'=ANY(grant_types) AND (NOT $3 OR 'refresh_token'=ANY(grant_types)) FOR SHARE`, g.OrgID, g.ClientID, g.DeferredAllowed).Scan(&id); err != nil {
			return err
		}
	}
	if g.ClientID != "" {
		var id string
		return r.pool.QueryRow(ctx, `SELECT client_id FROM identity.oidc_clients WHERE org_id=$1 AND client_id=$2
 AND (NOT dpop_bound_access_tokens OR $3<>'' OR $4<>'') AND (NOT tls_client_certificate_bound_access_tokens OR $4<>'') FOR SHARE`, g.OrgID, g.ClientID, g.DPoPJKT, g.MTLSX5TS256).Scan(&id)
	}
	return nil
}

func (r *OID4WRepository) LockWalletEligibility(ctx context.Context, org uuid.UUID, user *uuid.UUID, client string, config uuid.UUID, vct string, methods ...string) error {
	method := "none"
	if len(methods) > 0 {
		method = methods[0]
	}
	var id uuid.UUID
	if err := r.pool.QueryRow(ctx, `SELECT id FROM identity.organizations WHERE id=$1 AND is_active FOR SHARE`, org).Scan(&id); err != nil {
		return err
	}
	if user != nil {
		if err := r.pool.QueryRow(ctx, `SELECT id FROM identity.users WHERE org_id=$1 AND id=$2 AND is_active FOR SHARE`, org, *user).Scan(&id); err != nil {
			return err
		}
	}
	if client != "" {
		var cid string
		if err := r.pool.QueryRow(ctx, `SELECT client_id FROM identity.oidc_clients WHERE org_id=$1 AND client_id=$2 AND is_active AND token_endpoint_auth_method=$3 FOR SHARE`, org, client, method).Scan(&cid); err != nil {
			return err
		}
	}
	return r.pool.QueryRow(ctx, `SELECT id FROM identity.credential_configs WHERE org_id=$1 AND id=$2 AND vct=$3 AND is_active FOR SHARE`, org, config, vct).Scan(&id)
}

func (r *OID4WRepository) LockWalletOffer(ctx context.Context, id, org uuid.UUID) (*models.CredentialOffer, error) {
	var found uuid.UUID
	if err := r.pool.QueryRow(ctx, `SELECT id FROM identity.credential_offers WHERE id=$1 AND org_id=$2 FOR SHARE`, id, org).Scan(&found); err != nil {
		return nil, err
	}
	return r.GetOfferByID(ctx, id)
}

func (r *OID4WRepository) LockDeferredDelivery(ctx context.Context, txn string, org uuid.UUID) (bool, error) {
	var delivered bool
	err := r.pool.QueryRow(ctx, `SELECT delivered_at IS NOT NULL FROM identity.deferred_credentials WHERE transaction_id=$1 AND org_id=$2 FOR UPDATE NOWAIT`, txn, org).Scan(&delivered)
	return delivered, err
}

func (r *OID4WRepository) ConsumeDeferredDelivery(ctx context.Context, txn string, org uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `UPDATE identity.deferred_credentials SET delivered_at=clock_timestamp() WHERE transaction_id=$1 AND org_id=$2 AND status='completed' AND delivered_at IS NULL AND expires_at>clock_timestamp()`, txn, org)
	if err == nil && tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return err
}

func (r *OID4WRepository) DeferredRetrievable(ctx context.Context, offer uuid.UUID) (bool, error) {
	var yes bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.deferred_credentials WHERE offer_id=$1 AND status IN ('pending','completed') AND delivered_at IS NULL AND expires_at>clock_timestamp())`, offer).Scan(&yes)
	return yes, err
}

func (r *OID4WRepository) WalletClientMethod(ctx context.Context, org uuid.UUID, id string) (string, error) {
	var method string
	err := r.pool.QueryRow(ctx, `SELECT token_endpoint_auth_method FROM identity.oidc_clients WHERE org_id=$1 AND client_id=$2 AND is_active`, org, id).Scan(&method)
	return method, err
}
