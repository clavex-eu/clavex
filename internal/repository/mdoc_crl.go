package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MdocCRLRepository stores only signed public revocation information.
type MdocCRLRepository struct{ pool Querier }

func NewMdocCRLRepository(pool Querier) *MdocCRLRepository { return &MdocCRLRepository{pool: pool} }

func ValidateMdocCRL(root *x509.Certificate, der []byte, now time.Time) (*x509.RevocationList, error) {
	if root == nil || !root.IsCA || root.KeyUsage&x509.KeyUsageCRLSign == 0 || now.Before(root.NotBefore) || !now.Before(root.NotAfter) || len(der) > 1024*1024 {
		return nil, fmt.Errorf("invalid CRL issuer")
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	if err = crl.CheckSignatureFrom(root); err != nil {
		return nil, err
	}
	if !bytes.Equal(crl.RawIssuer, root.RawSubject) || !bytes.Equal(crl.AuthorityKeyId, root.SubjectKeyId) {
		return nil, fmt.Errorf("CRL issuer does not match IACA")
	}
	if crl.Number == nil || !crl.Number.IsInt64() || crl.Number.Sign() < 0 || crl.ThisUpdate.After(now) || !now.Before(crl.NextUpdate) || crl.NextUpdate.After(root.NotAfter) || !crl.ThisUpdate.Before(crl.NextUpdate) {
		return nil, fmt.Errorf("invalid or stale CRL")
	}
	return crl, nil
}

func (r *MdocCRLRepository) Put(ctx context.Context, org uuid.UUID, root *x509.Certificate, der []byte) (string, error) {
	crl, err := ValidateMdocCRL(root, der, time.Now())
	if err != nil {
		return "", err
	}
	fp := sha256.Sum256(root.Raw)
	fingerprint := hex.EncodeToString(fp[:])
	public := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	var returned string
	err = r.pool.QueryRow(ctx, `INSERT INTO identity.mdoc_iaca_crls(org_id,fingerprint,iaca_pem,der,number) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(org_id,fingerprint) DO UPDATE SET der=EXCLUDED.der,number=EXCLUDED.number
 WHERE identity.mdoc_iaca_crls.number<EXCLUDED.number RETURNING fingerprint`, org, fingerprint, public, der, crl.Number.Int64()).Scan(&returned)
	return returned, err
}

func (r *MdocCRLRepository) Get(ctx context.Context, org uuid.UUID, fingerprint string) ([]byte, error) {
	var public string
	var der []byte
	if err := r.pool.QueryRow(ctx, `SELECT iaca_pem,der FROM identity.mdoc_iaca_crls WHERE org_id=$1 AND fingerprint=$2`, org, fingerprint).Scan(&public, &der); err != nil {
		return nil, err
	}
	root, err := parseSingleCertPEM(public)
	if err != nil {
		return nil, err
	}
	if _, err = ValidateMdocCRL(root, der, time.Now()); err != nil {
		return nil, err
	}
	return der, nil
}

func (r *MdocCRLRepository) NextNumber(ctx context.Context, org uuid.UUID, fingerprint string) (int64, error) {
	var number int64
	err := r.pool.QueryRow(ctx, `SELECT number FROM identity.mdoc_iaca_crls WHERE org_id=$1 AND fingerprint=$2`, org, fingerprint).Scan(&number)
	if err == pgx.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	if number == 1<<63-1 {
		return 0, fmt.Errorf("CRL number exhausted")
	}
	return number + 1, nil
}
