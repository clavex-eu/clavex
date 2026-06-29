package repository

import (
	"context"
	"fmt"
	"net"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IPAllowlistEntry is a single CIDR entry in an org's IP allowlist.
type IPAllowlistEntry struct {
	ID        uuid.UUID  `db:"id"         json:"id"`
	OrgID     uuid.UUID  `db:"org_id"     json:"org_id"`
	CIDR      string     `db:"cidr"       json:"cidr"`
	Label     string     `db:"label"      json:"label"`
	CreatedBy *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
}

// IPAllowlistRepository manages per-org IP allowlists.
type IPAllowlistRepository struct {
	pool *pgxpool.Pool
}

func NewIPAllowlistRepository(pool *pgxpool.Pool) *IPAllowlistRepository {
	return &IPAllowlistRepository{pool: pool}
}

func (r *IPAllowlistRepository) List(ctx context.Context, orgID uuid.UUID) ([]*IPAllowlistEntry, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, cidr, label, created_by
		FROM org_ip_allowlist WHERE org_id = $1 ORDER BY created_at ASC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*IPAllowlistEntry
	for rows.Next() {
		e := &IPAllowlistEntry{}
		if err := rows.Scan(&e.ID, &e.OrgID, &e.CIDR, &e.Label, &e.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *IPAllowlistRepository) Add(ctx context.Context, orgID uuid.UUID, cidr, label string, createdBy *uuid.UUID) (*IPAllowlistEntry, error) {
	// Validate CIDR
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		// Try parsing as plain IP and convert to /32
		if ip := net.ParseIP(cidr); ip != nil {
			if ip.To4() != nil {
				cidr = cidr + "/32"
			} else {
				cidr = cidr + "/128"
			}
		} else {
			return nil, &net.ParseError{Type: "CIDR", Text: cidr}
		}
	}
	e := &IPAllowlistEntry{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO org_ip_allowlist (org_id, cidr, label, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, org_id, cidr, label, created_by
	`, orgID, cidr, label, createdBy).Scan(&e.ID, &e.OrgID, &e.CIDR, &e.Label, &e.CreatedBy)
	return e, err
}

func (r *IPAllowlistRepository) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM org_ip_allowlist WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ip allowlist entry not found")
	}
	return nil
}

// IsAllowed returns true if the given IP is allowed for the org.
// If the allowlist is empty it returns true (disabled = allow all).
func (r *IPAllowlistRepository) IsAllowed(ctx context.Context, orgID uuid.UUID, ipStr string) (bool, error) {
	entries, err := r.List(ctx, orgID)
	if err != nil {
		return true, err // fail open
	}
	if len(entries) == 0 {
		return true, nil // no allowlist configured
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, nil
	}
	for _, e := range entries {
		_, network, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}
