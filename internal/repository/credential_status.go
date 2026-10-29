package repository

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Status allocation and its eventual issued record must share a transaction.
// The advisory lock serializes list rollover without upgrading organisation
// SHARE locks acquired by the issuance grant's eligibility checks.
func (r *OID4WRepository) AllocateCredentialStatus(ctx context.Context, org uuid.UUID) (uuid.UUID, int, error) {
	if _, ok := r.pool.(pgx.Tx); !ok {
		return uuid.Nil, 0, fmt.Errorf("credential status allocation requires an issuance transaction")
	}
	if _, err := r.pool.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('wallet-status:'||$1::text,0))`, org.String()); err != nil {
		return uuid.Nil, 0, err
	}
	list, err := r.GetOrCreateStatusList(ctx, org)
	if err != nil {
		return uuid.Nil, 0, err
	}
	index, err := r.AllocateStatusIndex(ctx, list.ID)
	return list.ID, index, err
}

type CredentialStatusBinding struct {
	ListID         uuid.UUID
	Index          int
	IssuerJWTHash  string
	IssuerCOSEHash string
}

func (r *OID4WRepository) LockWalletStatusPolicy(ctx context.Context, org uuid.UUID) (map[string]interface{}, error) {
	_, settings, err := NewWalletIdentityRepository(r.pool).LockActiveOrg(ctx, org)
	return settings, err
}

// Recheck the actual validated root under the authentication transaction so a
// concurrent deletion or deactivation cannot race the final approval.
func (r *OID4WRepository) LockActiveIACA(ctx context.Context, org uuid.UUID, docType, fingerprint string) error {
	var id uuid.UUID
	return r.pool.QueryRow(ctx, `SELECT id FROM org_iaca_roots
	 WHERE org_id=$1 AND sha256_fingerprint=$2 AND is_active
	 AND (cardinality(doc_types)=0 OR $3=ANY(doc_types)) FOR SHARE`, org, fingerprint, docType).Scan(&id)
}

func (r *OID4WRepository) RecordCredentialWithStatus(ctx context.Context, org uuid.UUID, user *uuid.UUID, vct, hash string, expires *time.Time, status CredentialStatusBinding) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO identity.issued_credentials(org_id,user_id,vct,sd_jwt_hash,expires_at,status_list_id,status_index,issuer_jwt_hash,issuer_cose_hash)
	 VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),NULLIF($9,''))`, org, user, vct, hash, expires, status.ListID, status.Index, status.IssuerJWTHash, status.IssuerCOSEHash)
	return err
}

// Match the immutable signed issuer JWT, never the selectively disclosed
// presentation serialization. Locks order this decision against local revoke.
func (r *OID4WRepository) LockCredentialStatus(ctx context.Context, org, list uuid.UUID, index int, issuerHash, coseHash, vct string) (string, int, error) {
	var id uuid.UUID
	if err := r.pool.QueryRow(ctx, `SELECT id FROM identity.issued_credentials WHERE org_id=$1 AND status_list_id=$2 AND status_index=$3
	 AND (($4<>'' AND issuer_jwt_hash=$4) OR ($5<>'' AND issuer_cose_hash=$5)) AND vct=$6 AND NOT is_revoked AND NOT is_suspended AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE`, org, list, index, issuerHash, coseHash, vct).Scan(&id); err != nil {
		return "", 0, err
	}
	var encoded string
	var bits int
	err := r.pool.QueryRow(ctx, `SELECT encoded,bits FROM identity.credential_status_lists WHERE id=$1 AND org_id=$2 AND next_slot>$3 FOR SHARE`, list, org, index).Scan(&encoded, &bits)
	return encoded, bits, err
}

func (r *OID4WRepository) LockCredentialDelivery(ctx context.Context, org uuid.UUID, hash string) error {
	var id uuid.UUID
	return r.pool.QueryRow(ctx, `SELECT id FROM identity.issued_credentials WHERE org_id=$1 AND sd_jwt_hash=$2 AND NOT is_revoked AND NOT is_suspended
	 AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE`, org, hash).Scan(&id)
}

// Load and lock the trust anchors used to validate a locally issued mdoc at
// deferred delivery, where there is deliberately no wallet DeviceAuthentication.
func (r *OID4WRepository) LockIACAPool(ctx context.Context, org uuid.UUID, docType string) (*x509.CertPool, error) {
	rows, err := r.pool.Query(ctx, `SELECT pem FROM org_iaca_roots WHERE org_id=$1 AND is_active AND (cardinality(doc_types)=0 OR $2=ANY(doc_types)) FOR SHARE`, org, docType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roots := x509.NewCertPool()
	count := 0
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		cert, err := parseSingleCertPEM(raw)
		if err != nil {
			return nil, err
		}
		roots.AddCert(cert)
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, pgx.ErrNoRows
	}
	return roots, nil
}
