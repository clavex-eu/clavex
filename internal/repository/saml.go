package repository

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SAMLRepository manages SAML service providers and per-org IdP certificates.
type SAMLRepository struct {
	pool *pgxpool.Pool
}

func NewSAMLRepository(pool *pgxpool.Pool) *SAMLRepository {
	return &SAMLRepository{pool: pool}
}

// ── Service Provider CRUD ─────────────────────────────────────────────────────

type CreateSAMLSPParams struct {
	OrgID        uuid.UUID
	EntityID     string
	Name         string
	ACSURL       string
	SLOURL       *string
	MetadataXML  *string
	NameIDFormat string
}

func (r *SAMLRepository) CreateSP(ctx context.Context, p CreateSAMLSPParams) (*models.SAMLServiceProvider, error) {
	sp := &models.SAMLServiceProvider{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO saml_service_providers
			(org_id, entity_id, name, acs_url, slo_url, metadata_xml, name_id_format)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, org_id, entity_id, name, acs_url, slo_url, metadata_xml, name_id_format, is_active, created_at
	`, p.OrgID, p.EntityID, p.Name, p.ACSURL, p.SLOURL, p.MetadataXML, p.NameIDFormat).
		Scan(&sp.ID, &sp.OrgID, &sp.EntityID, &sp.Name, &sp.ACSURL, &sp.SLOURL,
			&sp.MetadataXML, &sp.NameIDFormat, &sp.IsActive, &sp.CreatedAt)
	return sp, err
}

func (r *SAMLRepository) GetSPByEntityID(ctx context.Context, orgID uuid.UUID, entityID string) (*models.SAMLServiceProvider, error) {
	sp := &models.SAMLServiceProvider{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, org_id, entity_id, name, acs_url, slo_url, metadata_xml, name_id_format, is_active, created_at
		FROM saml_service_providers
		WHERE org_id = $1 AND entity_id = $2 AND is_active = true
	`, orgID, entityID).
		Scan(&sp.ID, &sp.OrgID, &sp.EntityID, &sp.Name, &sp.ACSURL, &sp.SLOURL,
			&sp.MetadataXML, &sp.NameIDFormat, &sp.IsActive, &sp.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sp, err
}

func (r *SAMLRepository) ListSPsByOrg(ctx context.Context, orgID uuid.UUID) ([]*models.SAMLServiceProvider, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, entity_id, name, acs_url, slo_url, metadata_xml, name_id_format, is_active, created_at
		FROM saml_service_providers
		WHERE org_id = $1
		ORDER BY name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sps []*models.SAMLServiceProvider
	for rows.Next() {
		sp := &models.SAMLServiceProvider{}
		if err := rows.Scan(&sp.ID, &sp.OrgID, &sp.EntityID, &sp.Name, &sp.ACSURL,
			&sp.SLOURL, &sp.MetadataXML, &sp.NameIDFormat, &sp.IsActive, &sp.CreatedAt); err != nil {
			return nil, err
		}
		sps = append(sps, sp)
	}
	return sps, rows.Err()
}

// DeleteSP removes a SAML service provider scoped to its owning org. The org_id
// predicate makes this IDOR-safe: a cross-org id returns pgx.ErrNoRows instead
// of deleting another tenant's SP. Returns pgx.ErrNoRows when no row matches.
func (r *SAMLRepository) DeleteSP(ctx context.Context, id, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM saml_service_providers WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ── IdP Certificate management ────────────────────────────────────────────────

// IDPCertificate holds the parsed key and certificate for an org's SAML IdP.
type IDPCertificate struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
	ExpiresAt  time.Time
}

// GetActiveIDPCert returns the current active signing cert for the org.
func (r *SAMLRepository) GetActiveIDPCert(ctx context.Context, orgID uuid.UUID) (*IDPCertificate, error) {
	var certPEM, keyPEM string
	var id uuid.UUID
	var expiresAt time.Time

	err := r.pool.QueryRow(ctx, `
		SELECT id, cert_pem, key_pem, expires_at
		FROM idp_certificates
		WHERE org_id = $1 AND is_active = true
		LIMIT 1
	`, orgID).Scan(&id, &certPEM, &keyPEM, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	cert, key, err := decodeCertAndKey(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &IDPCertificate{ID: id, OrgID: orgID, Cert: cert, PrivateKey: key, ExpiresAt: expiresAt}, nil
}

// StoreIDPCert persists (or replaces) the active IdP certificate for an org.
// It deactivates any previous active cert before inserting the new one.
func (r *SAMLRepository) StoreIDPCert(ctx context.Context, orgID uuid.UUID, certPEM, keyPEM string, expiresAt time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx, `
		UPDATE idp_certificates SET is_active = false
		WHERE org_id = $1 AND is_active = true
	`, orgID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO idp_certificates (org_id, cert_pem, key_pem, is_active, expires_at)
		VALUES ($1, $2, $3, true, $4)
	`, orgID, certPEM, keyPEM, expiresAt)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

var ErrNotFound = errors.New("not found")

func decodeCertAndKey(certPEM, keyPEM string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, nil, errors.New("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, nil, errors.New("invalid private key PEM")
	}
	var privKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		k, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if e != nil {
			return nil, nil, e
		}
		var ok bool
		privKey, ok = k.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("PKCS#8 key is not RSA")
		}
	default:
		return nil, nil, errors.New("unsupported key PEM type: " + keyBlock.Type)
	}
	if err != nil {
		return nil, nil, err
	}
	return cert, privKey, nil
}
