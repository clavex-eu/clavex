package repository

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IACARepository manages per-org IACA root CA certificates used for
// mdoc IssuerAuth chain validation (ISO 18013-5 §9.3.3 / §9.4).
type IACARepository struct {
	pool *pgxpool.Pool
}

func NewIACARepository(pool *pgxpool.Pool) *IACARepository {
	return &IACARepository{pool: pool}
}

// Create parses the PEM certificate, validates it is a CA, and persists it.
// Returns ErrDuplicateCert if the same cert is already registered for the org.
var ErrDuplicateCert = errors.New("certificate already registered for this organisation")

func (r *IACARepository) Create(
	ctx context.Context,
	orgID uuid.UUID,
	label string,
	certPEM string,
	docTypes []string,
	createdBy *uuid.UUID,
) (*models.OrgIACARoot, error) {
	// Validate PEM and extract cert.
	cert, err := parseSingleCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("iaca: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("iaca: certificate is not a CA (BasicConstraints.IsCA must be true)")
	}

	fp := sha256Fingerprint(cert)
	subjectDN := cert.Subject.String()

	if docTypes == nil {
		docTypes = []string{}
	}

	const q = `
		INSERT INTO org_iaca_roots
			(org_id, label, subject_dn, sha256_fingerprint, pem, doc_types, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, org_id, label, subject_dn, sha256_fingerprint, pem, doc_types,
		          created_at, created_by, is_active`

	var root models.OrgIACARoot
	err = r.pool.QueryRow(ctx, q,
		orgID, label, subjectDN, fp, certPEM, docTypes, createdBy,
	).Scan(
		&root.ID, &root.OrgID, &root.Label, &root.SubjectDN, &root.SHA256Fingerprint,
		&root.PEM, &root.DocTypes, &root.CreatedAt, &root.CreatedBy, &root.IsActive,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			return nil, ErrDuplicateCert
		}
		return nil, err
	}
	return &root, nil
}

// List returns all active IACA roots for the given org.
func (r *IACARepository) List(ctx context.Context, orgID uuid.UUID) ([]*models.OrgIACARoot, error) {
	const q = `
		SELECT id, org_id, label, subject_dn, sha256_fingerprint, pem, doc_types,
		       created_at, created_by, is_active
		FROM org_iaca_roots
		WHERE org_id = $1
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.OrgIACARoot
	for rows.Next() {
		var root models.OrgIACARoot
		if err := rows.Scan(
			&root.ID, &root.OrgID, &root.Label, &root.SubjectDN, &root.SHA256Fingerprint,
			&root.PEM, &root.DocTypes, &root.CreatedAt, &root.CreatedBy, &root.IsActive,
		); err != nil {
			return nil, err
		}
		out = append(out, &root)
	}
	return out, rows.Err()
}

// Delete removes an IACA root by ID scoped to the org.
func (r *IACARepository) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM org_iaca_roots WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// GetCertPool builds an *x509.CertPool from all active roots for the given org.
// Returns nil, nil when no roots are configured (caller treats nil pool as
// "skip chain validation" and falls back to best-effort verification).
func (r *IACARepository) GetCertPool(ctx context.Context, orgID uuid.UUID) (*x509.CertPool, error) {
	const q = `
		SELECT pem FROM org_iaca_roots
		WHERE org_id = $1 AND is_active = true`

	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pool := x509.NewCertPool()
	count := 0
	for rows.Next() {
		var certPEM string
		if err := rows.Scan(&certPEM); err != nil {
			return nil, err
		}
		cert, err := parseSingleCertPEM(certPEM)
		if err != nil {
			// Skip malformed stored certs rather than failing completely.
			continue
		}
		pool.AddCert(cert)
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil // no roots → caller skips chain validation
	}
	return pool, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseSingleCertPEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type %q (want CERTIFICATE)", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func sha256Fingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}
