package repository

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MdocIssuerRepository manages per-org Document Signer (DS) key + cert pairs
// used to issue ISO 18013-5 mdoc credentials via OID4VCI.
type MdocIssuerRepository struct {
	pool Querier
}

func NewMdocIssuerRepository(pool Querier) *MdocIssuerRepository {
	return &MdocIssuerRepository{pool: pool}
}

// Create stores a new mdoc issuer record for an org.
func (r *MdocIssuerRepository) Create(
	ctx context.Context,
	orgID uuid.UUID,
	displayName, docType string,
	dsPrivateKeyPEM, dsCertPEM string,
	iacaCertPEM *string,
	validityHours int,
) (*models.OrgMdocIssuer, error) {
	return r.CreateWithSigner(ctx, orgID, displayName, docType, &dsPrivateKeyPEM, dsCertPEM, iacaCertPEM, validityHours, "", true)
}

// CreateWithSigner stores either an encrypted local key or an authorised Vault
// reference. Existing callers of Create retain their legacy storage behaviour.
func (r *MdocIssuerRepository) CreateWithSigner(ctx context.Context, orgID uuid.UUID, displayName, docType string, dsPrivateKeyPEM *string, dsCertPEM string, iacaCertPEM *string, validityHours int, vaultRef string, replaceExisting bool) (*models.OrgMdocIssuer, error) {
	if validityHours <= 0 {
		validityHours = 720
	}
	issuer := &models.OrgMdocIssuer{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO org_mdoc_issuers
		    (org_id, display_name, doc_type, ds_private_key_pem, ds_certificate_pem,
		     iaca_certificate_pem, validity_hours, vault_signer_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (org_id, doc_type, is_active) DO UPDATE
		    SET vault_signer_ref = EXCLUDED.vault_signer_ref,
                ds_private_key_pem   = EXCLUDED.ds_private_key_pem,
		        ds_certificate_pem   = EXCLUDED.ds_certificate_pem,
		        iaca_certificate_pem = EXCLUDED.iaca_certificate_pem,
		        validity_hours       = EXCLUDED.validity_hours,
		        display_name         = EXCLUDED.display_name,
		        updated_at           = NOW()
        WHERE $9
		RETURNING id, org_id, display_name, doc_type, ds_private_key_pem,
		          ds_certificate_pem, iaca_certificate_pem, validity_hours,
		          is_active, created_at, updated_at, vault_signer_ref
	`, orgID, displayName, docType, dsPrivateKeyPEM, dsCertPEM, iacaCertPEM, validityHours, vaultRef, replaceExisting).Scan(
		&issuer.ID, &issuer.OrgID, &issuer.DisplayName, &issuer.DocType,
		&issuer.DSPrivateKeyPEM, &issuer.DSCertificatePEM, &issuer.IACACertificatePEM,
		&issuer.ValidityHours, &issuer.IsActive, &issuer.CreatedAt, &issuer.UpdatedAt, &issuer.VaultSignerRef,
	)
	if err != nil {
		return nil, fmt.Errorf("create mdoc issuer: %w", err)
	}
	return issuer, nil
}

// GetActiveByDocType returns the active mdoc issuer for the given org + docType.
// Returns nil, nil when no issuer is configured.
func (r *MdocIssuerRepository) GetActiveByDocType(ctx context.Context, orgID uuid.UUID, docType string) (*models.OrgMdocIssuer, error) {
	issuer := &models.OrgMdocIssuer{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, display_name, doc_type, ds_private_key_pem,
		       ds_certificate_pem, iaca_certificate_pem, validity_hours,
		       is_active, created_at, updated_at, vault_signer_ref
		FROM org_mdoc_issuers
		WHERE org_id = $1 AND doc_type = $2 AND is_active = TRUE
		LIMIT 1
	`, orgID, docType).Scan(
		&issuer.ID, &issuer.OrgID, &issuer.DisplayName, &issuer.DocType,
		&issuer.DSPrivateKeyPEM, &issuer.DSCertificatePEM, &issuer.IACACertificatePEM,
		&issuer.ValidityHours, &issuer.IsActive, &issuer.CreatedAt, &issuer.UpdatedAt, &issuer.VaultSignerRef,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get mdoc issuer: %w", err)
	}
	return issuer, nil
}

// List returns all mdoc issuers for an org.
func (r *MdocIssuerRepository) List(ctx context.Context, orgID uuid.UUID) ([]*models.OrgMdocIssuer, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, display_name, doc_type, ds_private_key_pem,
		       ds_certificate_pem, iaca_certificate_pem, validity_hours,
		       is_active, created_at, updated_at, vault_signer_ref
		FROM org_mdoc_issuers
		WHERE org_id = $1
		ORDER BY doc_type, created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.OrgMdocIssuer
	for rows.Next() {
		issuer := &models.OrgMdocIssuer{}
		if err := rows.Scan(
			&issuer.ID, &issuer.OrgID, &issuer.DisplayName, &issuer.DocType,
			&issuer.DSPrivateKeyPEM, &issuer.DSCertificatePEM, &issuer.IACACertificatePEM,
			&issuer.ValidityHours, &issuer.IsActive, &issuer.CreatedAt, &issuer.UpdatedAt, &issuer.VaultSignerRef,
		); err != nil {
			return nil, err
		}
		out = append(out, issuer)
	}
	return out, rows.Err()
}

// Delete removes an mdoc issuer by ID.
func (r *MdocIssuerRepository) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM org_mdoc_issuers WHERE id = $1 AND org_id = $2`, id, orgID)
	return err
}

// ParseDSKey parses the DS private key PEM from an OrgMdocIssuer.
func ParseDSKey(issuer *models.OrgMdocIssuer) (*ecdsa.PrivateKey, error) {
	if issuer.DSPrivateKeyPEM == nil || *issuer.DSPrivateKeyPEM == "" {
		return nil, errors.New("mdoc issuer has no DS private key configured")
	}
	block, _ := pem.Decode([]byte(*issuer.DSPrivateKeyPEM))
	if block == nil {
		return nil, errors.New("DS private key: invalid PEM")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("DS key (EC): %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("DS key (PKCS8): %w", err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("DS key (PKCS8): not ECDSA")
		}
		return ecKey, nil
	default:
		return nil, fmt.Errorf("DS key: unsupported PEM type %q", block.Type)
	}
}

// ParseDSCert parses the DS certificate DER bytes from an OrgMdocIssuer.
func ParseDSCert(issuer *models.OrgMdocIssuer) ([]byte, error) {
	block, _ := pem.Decode([]byte(issuer.DSCertificatePEM))
	if block == nil {
		return nil, errors.New("DS certificate: invalid PEM")
	}
	return block.Bytes, nil
}
