package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CustomDomain represents a row in the org_custom_domains table.
type CustomDomain struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	Domain     string     `json:"domain"`
	Status     string     `json:"status"`      // "pending" | "active" | "failed"
	CertSource string     `json:"cert_source"` // "acme" | "byo"
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CertExpiry *time.Time `json:"cert_expiry,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// customDomainCols is the non-sensitive column list. cert_pem / cert_key_enc are
// deliberately excluded — they are read only by the ingress reconciler.
const customDomainCols = `id, org_id, domain, status, cert_source, verified_at, cert_expiry, created_at, updated_at`

// CustomDomainRepository manages per-org custom domain persistence.
type CustomDomainRepository struct {
	pool *pgxpool.Pool
}

func NewCustomDomainRepository(pool *pgxpool.Pool) *CustomDomainRepository {
	return &CustomDomainRepository{pool: pool}
}

// GetByDomain looks up a custom domain by its hostname.
// Returns pgx.ErrNoRows if not found.
func (r *CustomDomainRepository) GetByDomain(ctx context.Context, domain string) (*CustomDomain, error) {
	q := `SELECT ` + customDomainCols + ` FROM org_custom_domains WHERE domain = $1`

	row := r.pool.QueryRow(ctx, q, domain)
	return scanCustomDomain(row)
}

// ListByOrg returns all custom domains for an organisation.
func (r *CustomDomainRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*CustomDomain, error) {
	q := `SELECT ` + customDomainCols + ` FROM org_custom_domains WHERE org_id = $1 ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*CustomDomain
	for rows.Next() {
		d, err := scanCustomDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListPending returns all pending domains across orgs, for the background
// re-verify worker to re-check CNAME as DNS propagates.
func (r *CustomDomainRepository) ListPending(ctx context.Context) ([]*CustomDomain, error) {
	q := `SELECT ` + customDomainCols + ` FROM org_custom_domains WHERE status = 'pending' ORDER BY created_at`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*CustomDomain
	for rows.Next() {
		d, err := scanCustomDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Create inserts a new custom domain with status='pending'.
func (r *CustomDomainRepository) Create(ctx context.Context, orgID uuid.UUID, domain string) (*CustomDomain, error) {
	q := `INSERT INTO org_custom_domains (org_id, domain) VALUES ($1, $2) RETURNING ` + customDomainCols

	row := r.pool.QueryRow(ctx, q, orgID, domain)
	return scanCustomDomain(row)
}

// Activate marks a domain as verified and active (called by the verification job).
func (r *CustomDomainRepository) Activate(ctx context.Context, id uuid.UUID, certExpiry *time.Time) error {
	const q = `
		UPDATE org_custom_domains
		SET status      = 'active',
		    verified_at = NOW(),
		    cert_expiry = $2,
		    updated_at  = NOW()
		WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, id, certExpiry)
	return err
}

// SetFailed marks a domain verification as failed.
func (r *CustomDomainRepository) SetFailed(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE org_custom_domains
		SET status     = 'failed',
		    updated_at = NOW()
		WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, id)
	return err
}

// Delete removes a custom domain record.
func (r *CustomDomainRepository) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	const q = `DELETE FROM org_custom_domains WHERE id = $1 AND org_id = $2`
	tag, err := r.pool.Exec(ctx, q, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ErrDomainNotFound is returned when GetByDomain finds no matching row.
var ErrDomainNotFound = errors.New("custom domain not found")

// scanCustomDomain scans a single CustomDomain row from any pgx row scanner.
func scanCustomDomain(row interface {
	Scan(...any) error
}) (*CustomDomain, error) {
	var d CustomDomain
	err := row.Scan(&d.ID, &d.OrgID, &d.Domain, &d.Status, &d.CertSource,
		&d.VerifiedAt, &d.CertExpiry, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// SetBYOCert stores a customer-supplied certificate for a domain and switches it
// to the 'byo' cert source. The private key must already be encrypted (keyEnc).
// Scoped by org_id so one tenant cannot attach a cert to another's domain.
// Returns pgx.ErrNoRows when the domain does not belong to the org.
func (r *CustomDomainRepository) SetBYOCert(ctx context.Context, id, orgID uuid.UUID, certPEM string, keyEnc []byte, expiry *time.Time) error {
	const q = `
		UPDATE org_custom_domains
		SET cert_source  = 'byo',
		    cert_pem     = $3,
		    cert_key_enc = $4,
		    cert_expiry  = $5,
		    updated_at   = NOW()
		WHERE id = $1 AND org_id = $2`
	tag, err := r.pool.Exec(ctx, q, id, orgID, certPEM, keyEnc, expiry)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// RevertToACME clears a BYO certificate and returns the domain to ACME issuance.
func (r *CustomDomainRepository) RevertToACME(ctx context.Context, id, orgID uuid.UUID) error {
	const q = `
		UPDATE org_custom_domains
		SET cert_source = 'acme', cert_pem = NULL, cert_key_enc = NULL, updated_at = NOW()
		WHERE id = $1 AND org_id = $2`
	tag, err := r.pool.Exec(ctx, q, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// DomainCertMaterial is the reconciler's view of a domain's TLS material.
type DomainCertMaterial struct {
	Domain     string
	OrgID      uuid.UUID
	CertSource string
	CertPEM    string // BYO only
	CertKeyEnc []byte // BYO only, still encrypted
}

// ListActiveForReconcile returns the TLS material of every active domain so the
// ingress reconciler can create/update the corresponding Ingress + TLS Secret.
func (r *CustomDomainRepository) ListActiveForReconcile(ctx context.Context) ([]*DomainCertMaterial, error) {
	const q = `
		SELECT domain, org_id, cert_source, COALESCE(cert_pem, ''), cert_key_enc
		FROM org_custom_domains
		WHERE status = 'active'
		ORDER BY domain`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*DomainCertMaterial
	for rows.Next() {
		m := &DomainCertMaterial{}
		if err := rows.Scan(&m.Domain, &m.OrgID, &m.CertSource, &m.CertPEM, &m.CertKeyEnc); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
