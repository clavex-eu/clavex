package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ClientLifecycleItem is one row in the Object Lifecycle Management report for OIDC clients.
type ClientLifecycleItem struct {
	ClientID        string     `json:"client_id"`
	Name            string     `json:"name"`
	IsActive        bool       `json:"is_active"`
	GrantTypes      []string   `json:"grant_types"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`   // nil = never used
	DaysSinceUse    *int       `json:"days_since_use,omitempty"` // nil = never used
	StalenessSignal string     `json:"staleness_signal"`         // "active"|"stale"|"never_used"|"unknown"
	CreatedAt       time.Time  `json:"created_at"`
}

// GroupLifecycleItem is one row in the Object Lifecycle Management report for groups.
type GroupLifecycleItem struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	MemberCount int       `json:"member_count"`
	// LastActivityAt approximates last use: most recent group_members update
	// or last login from a user that has this group.
	LastActivityAt  *time.Time `json:"last_activity_at,omitempty"`
	DaysSinceUse    *int       `json:"days_since_use,omitempty"`
	StalenessSignal string     `json:"staleness_signal"` // "active"|"stale"|"empty"|"unknown"
	CreatedAt       time.Time  `json:"created_at"`
}

// LifecycleReport is the full Object Lifecycle Management dashboard payload.
type LifecycleReport struct {
	OrgID       uuid.UUID             `json:"org_id"`
	GeneratedAt time.Time             `json:"generated_at"`
	Clients     []ClientLifecycleItem `json:"clients"`
	Groups      []GroupLifecycleItem  `json:"groups"`
}

// LifecycleReportRepository generates the lifecycle management report.
type LifecycleReportRepository struct {
	pool *pgxpool.Pool
}

func NewLifecycleReportRepository(pool *pgxpool.Pool) *LifecycleReportRepository {
	return &LifecycleReportRepository{pool: pool}
}

const (
	staleThresholdDays  = 90 // client not used in 90 days → "stale"
	activeThresholdDays = 30 // used within 30 days → "active"
)

// GetLifecycleReport generates the full lifecycle report for an org.
func (r *LifecycleReportRepository) GetLifecycleReport(ctx context.Context, orgID uuid.UUID) (*LifecycleReport, error) {
	report := &LifecycleReport{
		OrgID:       orgID,
		GeneratedAt: time.Now().UTC(),
	}

	// ── OIDC clients ──────────────────────────────────────────────────────────
	crows, err := r.pool.Query(ctx, `
		SELECT client_id, name, is_active, grant_types, last_used_at, created_at
		FROM oidc_clients
		WHERE org_id = $1
		ORDER BY name ASC`, orgID)
	if err != nil {
		return nil, err
	}
	defer crows.Close()

	for crows.Next() {
		var item ClientLifecycleItem
		if scanErr := crows.Scan(
			&item.ClientID, &item.Name, &item.IsActive,
			&item.GrantTypes, &item.LastUsedAt, &item.CreatedAt,
		); scanErr != nil {
			return nil, scanErr
		}
		item.StalenessSignal = clientStaleness(item.LastUsedAt)
		if item.LastUsedAt != nil {
			days := int(time.Since(*item.LastUsedAt).Hours() / 24)
			item.DaysSinceUse = &days
		}
		report.Clients = append(report.Clients, item)
	}
	if err := crows.Err(); err != nil {
		return nil, err
	}
	if report.Clients == nil {
		report.Clients = []ClientLifecycleItem{}
	}

	// ── Groups ────────────────────────────────────────────────────────────────
	grows, err := r.pool.Query(ctx, `
		SELECT g.id, g.name, g.created_at,
		       COUNT(gm.user_id) AS member_count,
		       MAX(u.last_login_at) AS last_activity_at
		FROM groups g
		LEFT JOIN group_members gm ON gm.group_id = g.id
		LEFT JOIN users u ON u.id = gm.user_id
		WHERE g.org_id = $1
		GROUP BY g.id, g.name, g.created_at
		ORDER BY g.name ASC`, orgID)
	if err != nil {
		return nil, err
	}
	defer grows.Close()

	for grows.Next() {
		var item GroupLifecycleItem
		if scanErr := grows.Scan(
			&item.ID, &item.Name, &item.CreatedAt,
			&item.MemberCount, &item.LastActivityAt,
		); scanErr != nil {
			return nil, scanErr
		}
		item.StalenessSignal = groupStaleness(item.MemberCount, item.LastActivityAt)
		if item.LastActivityAt != nil {
			days := int(time.Since(*item.LastActivityAt).Hours() / 24)
			item.DaysSinceUse = &days
		}
		report.Groups = append(report.Groups, item)
	}
	if err := grows.Err(); err != nil {
		return nil, err
	}
	if report.Groups == nil {
		report.Groups = []GroupLifecycleItem{}
	}

	return report, nil
}

func clientStaleness(lastUsedAt *time.Time) string {
	if lastUsedAt == nil {
		return "never_used"
	}
	days := time.Since(*lastUsedAt).Hours() / 24
	switch {
	case days <= float64(activeThresholdDays):
		return "active"
	case days <= float64(staleThresholdDays):
		return "unknown"
	default:
		return "stale"
	}
}

func groupStaleness(memberCount int, lastActivityAt *time.Time) string {
	if memberCount == 0 {
		return "empty"
	}
	if lastActivityAt == nil {
		return "unknown"
	}
	days := time.Since(*lastActivityAt).Hours() / 24
	if days <= float64(activeThresholdDays) {
		return "active"
	}
	if days > float64(staleThresholdDays) {
		return "stale"
	}
	return "unknown"
}
