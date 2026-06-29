package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OrgHealthRow contains aggregated per-org metrics for the health dashboard.
type OrgHealthRow struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	Slug              string    `json:"slug"`
	IsActive          bool      `json:"is_active"`
	UserCount         int64     `json:"user_count"`
	MAU               int64     `json:"mau"`
	DAU               int64     `json:"dau"`
	LoginsToday       int64     `json:"logins_today"`
	FailedLoginsToday int64     `json:"failed_logins_today"`
	// AnomalyScore is derived: 100 − min(failed_logins_today * 5, 100).
	// < 70 → alert; < 40 → critical.
	AnomalyScore int `json:"anomaly_score"`
}

// WorkerStatus reports the last known state of a background worker.
type WorkerStatus struct {
	Name      string     `json:"name"`
	LastRunAt *time.Time `json:"last_run_at"`
	// Status is "ok", "error", or "never".
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Extra   any    `json:"extra,omitempty"` // e.g. {"entry_count": 1234}
}

// HealthAlert flags an org-level anomaly detected during the dashboard build.
type HealthAlert struct {
	OrgID   uuid.UUID `json:"org_id"`
	OrgName string    `json:"org_name"`
	OrgSlug string    `json:"org_slug"`
	// Type is one of: "high_failure_rate", "inactive_org_with_traffic".
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// InstallationTotals holds cross-org aggregate counters.
type InstallationTotals struct {
	OrgCount          int   `json:"org_count"`
	ActiveOrgCount    int   `json:"active_org_count"`
	DAUTotal          int64 `json:"dau_total"`
	LoginsToday       int64 `json:"logins_today"`
	FailedLoginsToday int64 `json:"failed_logins_today"`
}

// HealthDashboard is the complete payload returned by GetHealthDashboard.
type HealthDashboard struct {
	DBVersion string             `json:"db_version"`
	Orgs      []OrgHealthRow     `json:"orgs"`
	Workers   []WorkerStatus     `json:"workers"`
	Totals    InstallationTotals `json:"totals"`
	Alerts    []HealthAlert      `json:"alerts"`
	ComputedAt time.Time         `json:"computed_at"`
}

// HealthDashboardRepository assembles the superadmin installation health view.
type HealthDashboardRepository struct {
	pool *pgxpool.Pool
}

func NewHealthDashboardRepository(pool *pgxpool.Pool) *HealthDashboardRepository {
	return &HealthDashboardRepository{pool: pool}
}

// GetHealthDashboard assembles the full health dashboard in a few DB round-trips.
func (r *HealthDashboardRepository) GetHealthDashboard(ctx context.Context) (*HealthDashboard, error) {
	dash := &HealthDashboard{ComputedAt: time.Now().UTC()}

	// ── 1. DB version ─────────────────────────────────────────────────────────
	if err := r.pool.QueryRow(ctx, `SELECT version()`).Scan(&dash.DBVersion); err != nil {
		dash.DBVersion = "unknown"
	}

	// ── 2. Per-org stats (single CTE query) ───────────────────────────────────
	rows, err := r.pool.Query(ctx, `
		WITH login_stats AS (
			SELECT
				org_id,
				COUNT(DISTINCT CASE
					WHEN status = 'success'
					  AND created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')
					THEN user_id END) AS mau,
				COUNT(DISTINCT CASE
					WHEN status = 'success'
					  AND created_at >= current_date
					THEN user_id END) AS dau,
				COUNT(CASE WHEN created_at >= current_date THEN 1 END) AS logins_today,
				COUNT(CASE
					WHEN status = 'failure'
					  AND created_at >= current_date
					THEN 1 END) AS failed_today
			FROM login_history
			WHERE created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')
			GROUP BY org_id
		),
		user_counts AS (
			SELECT org_id, COUNT(*) AS cnt
			FROM users
			WHERE is_active = TRUE
			GROUP BY org_id
		)
		SELECT
			o.id, o.name, o.slug, o.is_active,
			COALESCE(uc.cnt,           0) AS user_count,
			COALESCE(ls.mau,           0) AS mau,
			COALESCE(ls.dau,           0) AS dau,
			COALESCE(ls.logins_today,  0) AS logins_today,
			COALESCE(ls.failed_today,  0) AS failed_today
		FROM organizations o
		LEFT JOIN login_stats  ls ON ls.org_id = o.id
		LEFT JOIN user_counts  uc ON uc.org_id = o.id
		ORDER BY COALESCE(ls.mau, 0) DESC, o.name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var row OrgHealthRow
		var failedToday int64
		if err := rows.Scan(
			&row.ID, &row.Name, &row.Slug, &row.IsActive,
			&row.UserCount, &row.MAU, &row.DAU, &row.LoginsToday, &failedToday,
		); err != nil {
			return nil, err
		}
		row.FailedLoginsToday = failedToday
		// AnomalyScore: 100 minus failure penalty, clamped to [0, 100].
		penalty := int(failedToday) * 5
		if penalty > 100 {
			penalty = 100
		}
		row.AnomalyScore = 100 - penalty
		dash.Orgs = append(dash.Orgs, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// ── 3. Cross-org totals ───────────────────────────────────────────────────
	for _, o := range dash.Orgs {
		dash.Totals.OrgCount++
		if o.IsActive {
			dash.Totals.ActiveOrgCount++
		}
		dash.Totals.DAUTotal += o.DAU
		dash.Totals.LoginsToday += o.LoginsToday
		dash.Totals.FailedLoginsToday += o.FailedLoginsToday
	}

	// ── 4. Worker statuses ────────────────────────────────────────────────────
	dash.Workers = append(dash.Workers, r.mds3Status(ctx))
	dash.Workers = append(dash.Workers, r.gdprErasureStatus(ctx))

	// ── 5. Alerts ─────────────────────────────────────────────────────────────
	for _, o := range dash.Orgs {
		if o.AnomalyScore < 70 && o.LoginsToday > 0 {
			pct := float64(0)
			if o.LoginsToday > 0 {
				pct = float64(o.FailedLoginsToday) / float64(o.LoginsToday) * 100
			}
			alert := HealthAlert{
				OrgID:   o.ID,
				OrgName: o.Name,
				OrgSlug: o.Slug,
				Type:    "high_failure_rate",
				Detail:  fmt.Sprintf("%.0f%% failure rate today (%d failures / %d logins)", pct, o.FailedLoginsToday, o.LoginsToday),
			}
			dash.Alerts = append(dash.Alerts, alert)
		}
		if !o.IsActive && o.LoginsToday > 0 {
			dash.Alerts = append(dash.Alerts, HealthAlert{
				OrgID:   o.ID,
				OrgName: o.Name,
				OrgSlug: o.Slug,
				Type:    "inactive_org_with_traffic",
				Detail:  fmt.Sprintf("%d login attempts on inactive org", o.LoginsToday),
			})
		}
	}
	if dash.Alerts == nil {
		dash.Alerts = []HealthAlert{}
	}

	return dash, nil
}

// mds3Status reads the singleton fido_mds_sync row.
func (r *HealthDashboardRepository) mds3Status(ctx context.Context) WorkerStatus {
	ws := WorkerStatus{Name: "MDS3 Catalog"}
	var lastSynced *time.Time
	var entryCount int
	var lastErr *string
	err := r.pool.QueryRow(ctx, `
		SELECT last_synced_at, entry_count, last_error
		FROM fido_mds_sync WHERE id = 1
	`).Scan(&lastSynced, &entryCount, &lastErr)
	if err != nil || lastSynced == nil {
		ws.Status = "never"
		ws.Detail = "no sync recorded"
		return ws
	}
	ws.LastRunAt = lastSynced
	if lastErr != nil && *lastErr != "" {
		ws.Status = "error"
		ws.Detail = *lastErr
	} else {
		ws.Status = "ok"
	}
	ws.Extra = map[string]int{"entry_count": entryCount}
	return ws
}

// gdprErasureStatus reports the last completed erasure and pending count.
func (r *HealthDashboardRepository) gdprErasureStatus(ctx context.Context) WorkerStatus {
	ws := WorkerStatus{Name: "GDPR Erasure"}
	var lastCompleted *time.Time
	_ = r.pool.QueryRow(ctx, `
		SELECT MAX(completed_at) FROM gdpr_erasure_requests WHERE status = 'completed'
	`).Scan(&lastCompleted)
	ws.LastRunAt = lastCompleted
	if lastCompleted == nil {
		ws.Status = "never"
		ws.Detail = "no erasures completed"
	} else {
		ws.Status = "ok"
	}
	var pending int
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM gdpr_erasure_requests
		WHERE status = 'scheduled' AND scheduled_for <= NOW()
	`).Scan(&pending)
	ws.Extra = map[string]int{"pending_count": pending}
	return ws
}
