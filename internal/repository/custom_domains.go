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
	Status     string     `json:"status"` // "pending" | "active" | "failed"
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CertExpiry *time.Time `json:"cert_expiry,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

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
	const q = `
		SELECT id, org_id, domain, status, verified_at, cert_expiry, created_at, updated_at
		FROM org_custom_domains
		WHERE domain = $1`

	row := r.pool.QueryRow(ctx, q, domain)
	return scanCustomDomain(row)
}

// ListByOrg returns all custom domains for an organisation.
func (r *CustomDomainRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*CustomDomain, error) {
	const q = `
		SELECT id, org_id, domain, status, verified_at, cert_expiry, created_at, updated_at
		FROM org_custom_domains
		WHERE org_id = $1
		ORDER BY created_at DESC`

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

// Create inserts a new custom domain with status='pending'.
func (r *CustomDomainRepository) Create(ctx context.Context, orgID uuid.UUID, domain string) (*CustomDomain, error) {
	const q = `
		INSERT INTO org_custom_domains (org_id, domain)
		VALUES ($1, $2)
		RETURNING id, org_id, domain, status, verified_at, cert_expiry, created_at, updated_at`

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
	err := row.Scan(&d.ID, &d.OrgID, &d.Domain, &d.Status,
		&d.VerifiedAt, &d.CertExpiry, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}
