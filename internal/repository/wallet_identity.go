package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type WalletIdentityLink struct {
	ID                 uuid.UUID  `json:"id"`
	OrgID              uuid.UUID  `json:"org_id"`
	UserID             uuid.UUID  `json:"user_id"`
	Format             string     `json:"format"`
	Issuer             string     `json:"issuer"`
	CredentialType     string     `json:"credential_type"`
	ClaimPath          []string   `json:"claim_path"`
	SubjectDigest      []byte     `json:"-"`
	VerificationMethod string     `json:"verification_method"`
	VerifiedBy         *uuid.UUID `json:"verified_by,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	IsActive           bool       `json:"is_active"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
}

type WalletIdentityRepository struct{ q Querier }

func NewWalletIdentityRepository(q Querier) *WalletIdentityRepository {
	return &WalletIdentityRepository{q: q}
}

// These locks make eligibility/profile revocation and the authentication decision
// observe a single ordering in the enclosing transaction.
func (r *WalletIdentityRepository) LockActiveOrg(ctx context.Context, id uuid.UUID) (string, map[string]interface{}, error) {
	var slug string
	var settings map[string]interface{}
	err := r.q.QueryRow(ctx, `SELECT slug,settings FROM identity.organizations WHERE id=$1 AND is_active FOR SHARE`, id).Scan(&slug, &settings)
	return slug, settings, err
}
func (r *WalletIdentityRepository) LockActiveUser(ctx context.Context, org, user uuid.UUID) error {
	var id uuid.UUID
	return r.q.QueryRow(ctx, `SELECT id FROM identity.users WHERE org_id=$1 AND id=$2 AND is_active FOR SHARE`, org, user).Scan(&id)
}
func (r *WalletIdentityRepository) LockActiveClient(ctx context.Context, org uuid.UUID, client string) error {
	var id string
	return r.q.QueryRow(ctx, `SELECT client_id FROM identity.oidc_clients WHERE org_id=$1 AND client_id=$2 AND is_active FOR SHARE`, org, client).Scan(&id)
}
func (r *WalletIdentityRepository) FindActive(ctx context.Context, org uuid.UUID, format, issuer, credentialType string, path []string, digest []byte) (uuid.UUID, uuid.UUID, error) {
	var id, user uuid.UUID
	err := r.q.QueryRow(ctx, `SELECT id,user_id FROM identity.wallet_identity_links
	 WHERE org_id=$1 AND format=$2 AND issuer=$3 AND credential_type=$4 AND claim_path=$5 AND subject_digest=$6 AND is_active FOR SHARE`, org, format, issuer, credentialType, path, digest).Scan(&id, &user)
	return id, user, err
}
func (r *WalletIdentityRepository) Create(ctx context.Context, p WalletIdentityLink) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.q.QueryRow(ctx, `INSERT INTO identity.wallet_identity_links
	 (org_id,user_id,format,issuer,credential_type,claim_path,subject_digest,verification_method,verified_by)
	 VALUES($1,$2,$3,$4,$5,$6,$7,'administrative_review',$8) RETURNING id`, p.OrgID, p.UserID, p.Format, p.Issuer, p.CredentialType, p.ClaimPath, p.SubjectDigest, p.VerifiedBy).Scan(&id)
	return id, err
}
func (r *WalletIdentityRepository) List(ctx context.Context, org, user uuid.UUID) ([]WalletIdentityLink, error) {
	rows, err := r.q.Query(ctx, `SELECT id,org_id,user_id,format,issuer,credential_type,claim_path,
	 verification_method,verified_by,created_at,is_active,revoked_at FROM identity.wallet_identity_links
	 WHERE org_id=$1 AND user_id=$2 ORDER BY created_at DESC`, org, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []WalletIdentityLink{}
	for rows.Next() {
		var x WalletIdentityLink
		if err := rows.Scan(&x.ID, &x.OrgID, &x.UserID, &x.Format, &x.Issuer, &x.CredentialType, &x.ClaimPath, &x.VerificationMethod, &x.VerifiedBy, &x.CreatedAt, &x.IsActive, &x.RevokedAt); err != nil {
			return nil, err
		}
		result = append(result, x)
	}
	return result, rows.Err()
}
func (r *WalletIdentityRepository) Revoke(ctx context.Context, org, user, id uuid.UUID) (bool, error) {
	tag, err := r.q.Exec(ctx, `UPDATE identity.wallet_identity_links SET is_active=false,revoked_at=NOW()
	 WHERE org_id=$1 AND user_id=$2 AND id=$3 AND is_active`, org, user, id)
	return tag.RowsAffected() == 1, err
}
