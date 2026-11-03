package repository

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"math/bits"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *OID4WRepository) allocateRandomStatusIndex(ctx context.Context, list uuid.UUID) (int, error) {
	if _, ok := r.pool.(pgx.Tx); !ok {
		return 0, fmt.Errorf("status slot reservation requires an issuance transaction")
	}
	var occupied []byte
	var count int
	if err := r.pool.QueryRow(ctx, `SELECT allocated_slots,next_slot FROM identity.credential_status_lists WHERE id=$1 FOR UPDATE`, list).Scan(&occupied, &count); err != nil {
		return 0, err
	}
	if len(occupied) != 8192 || count < 0 || count >= 65536 {
		return 0, fmt.Errorf("status list is full or allocation state is invalid")
	}
	used := 0
	for _, value := range occupied {
		used += bits.OnesCount8(value)
	}
	if used != count {
		return 0, fmt.Errorf("status slot occupancy does not match reservation count")
	}
	// Choose a uniform rank among all free slots, including on nearly full
	// lists. No collision retry limit or predictable sequential fallback.
	rank, err := rand.Int(rand.Reader, big.NewInt(int64(65536-count)))
	if err != nil {
		return 0, err
	}
	remaining := int(rank.Int64())
	for index := 0; index < 65536; index++ {
		mask := byte(1 << uint(index%8))
		if occupied[index/8]&mask != 0 {
			continue
		}
		if remaining > 0 {
			remaining--
			continue
		}
		occupied[index/8] |= mask
		_, err = r.pool.Exec(ctx, `UPDATE identity.credential_status_lists SET allocated_slots=$2,next_slot=next_slot+1,updated_at=NOW() WHERE id=$1`, list, occupied)
		return index, err
	}
	return 0, fmt.Errorf("status slot occupancy is invalid")
}

// Status allocation and its eventual issued record must share a transaction.
// The advisory lock serialises list rollover without upgrading organisation
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
// presentation serialisation. Locks order this decision against local revoke.
func (r *OID4WRepository) LockCredentialStatus(ctx context.Context, org, list uuid.UUID, index int, issuerHash, coseHash, vct string) (string, int, error) {
	if index < 0 || index >= 65536 {
		return "", 0, fmt.Errorf("invalid credential status index")
	}
	var id uuid.UUID
	if err := r.pool.QueryRow(ctx, `SELECT id FROM identity.issued_credentials WHERE org_id=$1 AND status_list_id=$2 AND status_index=$3
	 AND (($4<>'' AND issuer_jwt_hash=$4) OR ($5<>'' AND issuer_cose_hash=$5)) AND vct=$6 AND NOT is_revoked AND NOT is_suspended AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE`, org, list, index, issuerHash, coseHash, vct).Scan(&id); err != nil {
		return "", 0, err
	}
	var encoded string
	var bits int
	err := r.pool.QueryRow(ctx, `SELECT encoded,bits FROM identity.credential_status_lists WHERE id=$1 AND org_id=$2 AND get_bit(allocated_slots,$3)=1 FOR SHARE`, list, org, index).Scan(&encoded, &bits)
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
