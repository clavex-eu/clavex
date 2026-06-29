package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OrgUsage holds per-organisation usage analytics derived from login_history.
// Used for billing (MAU-based plans) and security posture reporting.
type OrgUsage struct {
	OrgID uuid.UUID `json:"org_id"`

	// Time window this report covers.
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`

	// Monthly / daily active users (distinct authenticated user_id values).
	MAU int64 `json:"mau"` // current calendar month
	DAU int64 `json:"dau"` // current calendar day (UTC)

	// Total login events in the window.
	TotalLogins   int64 `json:"total_logins"`
	SuccessLogins int64 `json:"success_logins"`
	FailedLogins  int64 `json:"failed_logins"`

	// Logins broken down by auth_method.
	LoginsByMethod []MethodCount `json:"logins_by_method"`

	// Top 10 OIDC client_ids by login volume.
	TopClients []ClientCount `json:"top_clients"`

	// New users first seen this month (JIT-provisioned or created).
	NewUsers int64 `json:"new_users_this_month"`
}

// MethodCount is one row of the login-by-method breakdown.
type MethodCount struct {
	Method string `json:"method"`
	Count  int64  `json:"count"`
}

// ClientCount is one row of the top-clients breakdown.
type ClientCount struct {
	ClientID string `json:"client_id"`
	Count    int64  `json:"count"`
}

// UsageRepository provides analytics queries over login_history.
type UsageRepository struct {
	pool *pgxpool.Pool
}

// NewUsageRepository constructs a UsageRepository.
func NewUsageRepository(pool *pgxpool.Pool) *UsageRepository {
	return &UsageRepository{pool: pool}
}

// GetOrgUsage returns aggregated usage metrics for the given org.
// The report window is always the trailing 30 days; DAU is today (UTC).
func (r *UsageRepository) GetOrgUsage(ctx context.Context, orgID uuid.UUID) (*OrgUsage, error) {
	now := time.Now().UTC()
	// Trailing 30 days for the main window; start-of-day UTC for DAU.
	windowStart := now.AddDate(0, 0, -30)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// ── MAU / DAU / total / success / failure ───────────────────────────────
	var (
		mau           int64
		dau           int64
		totalLogins   int64
		successLogins int64
		failedLogins  int64
		newUsers      int64
	)

	err := r.pool.QueryRow(ctx, `
		SELECT
		  COUNT(DISTINCT CASE WHEN created_at >= $2       AND status = 'success' THEN user_id END) AS mau,
		  COUNT(DISTINCT CASE WHEN created_at >= $3       AND status = 'success' THEN user_id END) AS dau,
		  COUNT(*)                                                                                  AS total_logins,
		  COUNT(CASE WHEN status = 'success' THEN 1 END)                                           AS success_logins,
		  COUNT(CASE WHEN status = 'failure' THEN 1 END)                                           AS failed_logins,
		  COUNT(DISTINCT CASE WHEN created_at >= $2 AND user_id IS NOT NULL THEN user_id END)      AS new_users
		FROM login_history
		WHERE org_id = $1
		  AND created_at >= $2
	`, orgID, windowStart, dayStart,
	).Scan(&mau, &dau, &totalLogins, &successLogins, &failedLogins, &newUsers)
	if err != nil {
		return nil, err
	}

	// ── Logins by method ────────────────────────────────────────────────────
	methodRows, err := r.pool.Query(ctx, `
		SELECT auth_method, COUNT(*) AS cnt
		FROM login_history
		WHERE org_id = $1
		  AND created_at >= $2
		GROUP BY auth_method
		ORDER BY cnt DESC
	`, orgID, windowStart)
	if err != nil {
		return nil, err
	}
	defer methodRows.Close()

	var loginsByMethod []MethodCount
	for methodRows.Next() {
		var mc MethodCount
		if err := methodRows.Scan(&mc.Method, &mc.Count); err != nil {
			return nil, err
		}
		loginsByMethod = append(loginsByMethod, mc)
	}
	if err := methodRows.Err(); err != nil {
		return nil, err
	}

	// ── Top clients ──────────────────────────────────────────────────────────
	clientRows, err := r.pool.Query(ctx, `
		SELECT c.client_id, COUNT(*) AS cnt
		FROM login_history lh
		JOIN oidc_clients c ON c.client_id = lh.client_id
		WHERE lh.org_id = $1
		  AND lh.created_at >= $2
		  AND lh.client_id IS NOT NULL
		GROUP BY c.client_id
		ORDER BY cnt DESC
		LIMIT 10
	`, orgID, windowStart)
	if err != nil {
		return nil, err
	}
	defer clientRows.Close()

	var topClients []ClientCount
	for clientRows.Next() {
		var cc ClientCount
		if err := clientRows.Scan(&cc.ClientID, &cc.Count); err != nil {
			return nil, err
		}
		topClients = append(topClients, cc)
	}
	if err := clientRows.Err(); err != nil {
		return nil, err
	}

	if loginsByMethod == nil {
		loginsByMethod = []MethodCount{}
	}
	if topClients == nil {
		topClients = []ClientCount{}
	}

	return &OrgUsage{
		OrgID:          orgID,
		PeriodStart:    windowStart,
		PeriodEnd:      now,
		MAU:            mau,
		DAU:            dau,
		TotalLogins:    totalLogins,
		SuccessLogins:  successLogins,
		FailedLogins:   failedLogins,
		LoginsByMethod: loginsByMethod,
		TopClients:     topClients,
		NewUsers:       newUsers,
	}, nil
}
