package repository

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IPRule represents a single allow or deny CIDR rule for an organisation.
type IPRule struct {
	ID        uuid.UUID  `json:"id"`
	OrgID     uuid.UUID  `json:"org_id"`
	Type      string     `json:"type"` // "allow" | "deny"
	CIDR      string     `json:"cidr"`
	Notes     string     `json:"notes"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// IPRulesRepository manages per-org IP allow/deny rules stored in org_ip_rules.
type IPRulesRepository struct {
	pool *pgxpool.Pool
}

// NewIPRulesRepository creates a new IPRulesRepository.
func NewIPRulesRepository(pool *pgxpool.Pool) *IPRulesRepository {
	return &IPRulesRepository{pool: pool}
}

// List returns all rules for an organisation ordered by type then created_at.
func (r *IPRulesRepository) List(ctx context.Context, orgID uuid.UUID) ([]*IPRule, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, org_id, type, cidr, notes, created_by, created_at
		 FROM org_ip_rules
		 WHERE org_id = $1
		 ORDER BY type, created_at`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("ip_rules.List: %w", err)
	}
	defer rows.Close()

	var rules []*IPRule
	for rows.Next() {
		ru := &IPRule{}
		if err := rows.Scan(&ru.ID, &ru.OrgID, &ru.Type, &ru.CIDR, &ru.Notes, &ru.CreatedBy, &ru.CreatedAt); err != nil {
			return nil, fmt.Errorf("ip_rules.List scan: %w", err)
		}
		rules = append(rules, ru)
	}
	return rules, rows.Err()
}

// Add inserts a new rule.  cidr must be a valid CIDR string (e.g. "10.0.0.0/8").
func (r *IPRulesRepository) Add(ctx context.Context, orgID uuid.UUID, ruleType, cidr, notes string, createdBy *uuid.UUID) (*IPRule, error) {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return nil, fmt.Errorf("ip_rules.Add: invalid CIDR %q: %w", cidr, err)
	}
	ru := &IPRule{}
	err := r.pool.QueryRow(ctx,
		`INSERT INTO org_ip_rules (org_id, type, cidr, notes, created_by)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, type, cidr, notes, created_by, created_at`,
		orgID, ruleType, cidr, notes, createdBy,
	).Scan(&ru.ID, &ru.OrgID, &ru.Type, &ru.CIDR, &ru.Notes, &ru.CreatedBy, &ru.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("ip_rules.Add: %w", err)
	}
	return ru, nil
}

// Delete removes a rule by ID, scoped to the org to prevent cross-org deletion.
func (r *IPRulesRepository) Delete(ctx context.Context, orgID, ruleID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM org_ip_rules WHERE id = $1 AND org_id = $2`,
		ruleID, orgID,
	)
	if err != nil {
		return fmt.Errorf("ip_rules.Delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CheckIP evaluates all rules for orgID against ip, applying deny-first logic:
//
//   - Returns "deny" if any deny rule's CIDR contains ip.
//   - Returns "allow" if any allow rule's CIDR contains ip (and no deny matched).
//   - Returns "" if no rule matches (neutral — apply normal flow).
func (r *IPRulesRepository) CheckIP(ctx context.Context, orgID uuid.UUID, ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Unparseable IP — treat as neutral to avoid blocking legitimate traffic.
		return "", nil
	}

	rows, err := r.pool.Query(ctx,
		`SELECT type, cidr FROM org_ip_rules WHERE org_id = $1 ORDER BY type DESC`,
		// ORDER BY type DESC puts "deny" before "allow" (d > a lexically).
		orgID,
	)
	if err != nil {
		return "", fmt.Errorf("ip_rules.CheckIP: %w", err)
	}
	defer rows.Close()

	var bestMatch string // "" | "allow" | "deny"
	for rows.Next() {
		var rType, cidr string
		if err := rows.Scan(&rType, &cidr); err != nil {
			return "", fmt.Errorf("ip_rules.CheckIP scan: %w", err)
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // skip malformed stored rules
		}
		if network.Contains(parsed) {
			if rType == "deny" {
				return "deny", nil // deny wins immediately
			}
			bestMatch = "allow"
		}
	}
	return bestMatch, rows.Err()
}
