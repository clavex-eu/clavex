package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DailyCount is one data point in a time-series (day → count).
type DailyCount struct {
	Date  string `json:"date"`  // "2026-05-14"
	Count int64  `json:"count"`
}

// OrgAnalytics is the richer per-org analytics payload, designed for the
// "Organization Analytics" dashboard page that mirrors Clerk's member/MAU/DAU
// trends view — but accessible to org admins, not just superadmins.
type OrgAnalytics struct {
	OrgID uuid.UUID `json:"org_id"`

	// ── Current snapshot ──────────────────────────────────────────────────────
	TotalMembers    int64 `json:"total_members"`
	ActiveMembers   int64 `json:"active_members"` // is_active = true
	MAU             int64 `json:"mau"`             // trailing 30 days
	DAU             int64 `json:"dau"`             // today (UTC)
	PendingInvites  int64 `json:"pending_invites"`

	// ── Growth (trailing 30 days) ─────────────────────────────────────────────
	NewMembersLast30Days int64 `json:"new_members_last_30_days"`

	// ── Retention (D7 / D30 cohort) ───────────────────────────────────────────
	// RetentionD7  is the fraction of users who signed in at least once in
	// days 1-7 after their first login, out of those who first logged in 7+ days ago.
	RetentionD7  float64 `json:"retention_d7"`
	RetentionD30 float64 `json:"retention_d30"`

	// ── Daily active users — last 30 days ─────────────────────────────────────
	DAUTimeSeries []DailyCount `json:"dau_time_series"`

	// ── New members — last 30 days ────────────────────────────────────────────
	NewMembersTimeSeries []DailyCount `json:"new_members_time_series"`

	// ── Security / health metrics ─────────────────────────────────────────────
	// FailedLoginRate30d is the ratio of failed logins to total logins in the
	// last 30 days (0.0 = no failures, 1.0 = all logins failed).
	FailedLoginRate30d float64 `json:"failed_login_rate_30d"`
	// InactiveUsers30d counts active members who had no successful login in
	// the last 30 days — a leading indicator of churn or stale accounts.
	InactiveUsers30d int64 `json:"inactive_users_30d"`
	// LoginMethodBreakdown shows successful login counts grouped by auth_method
	// for the last 30 days (password, google, saml, oidc, passkey, …).
	LoginMethodBreakdown []LoginMethodStat `json:"login_method_breakdown"`
}

// LoginMethodStat is one row of the login method breakdown.
type LoginMethodStat struct {
	Method string `json:"method"`
	Count  int64  `json:"count"`
}

// AnalyticsRepository provides richer per-org analytics beyond OrgUsage.
type AnalyticsRepository struct {
	pool *pgxpool.Pool
}

func NewAnalyticsRepository(pool *pgxpool.Pool) *AnalyticsRepository {
	return &AnalyticsRepository{pool: pool}
}

// GetOrgAnalytics returns the full analytics payload for an org.
func (r *AnalyticsRepository) GetOrgAnalytics(ctx context.Context, orgID uuid.UUID) (*OrgAnalytics, error) {
	now := time.Now().UTC()
	windowStart := now.AddDate(0, 0, -30)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	a := &OrgAnalytics{OrgID: orgID}

	// ── Member counts ─────────────────────────────────────────────────────────
	err := r.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*)                                      AS total_members,
		  COUNT(*) FILTER (WHERE is_active = TRUE)      AS active_members,
		  COUNT(*) FILTER (WHERE created_at >= $2)      AS new_members_30d
		FROM users WHERE org_id = $1`,
		orgID, windowStart,
	).Scan(&a.TotalMembers, &a.ActiveMembers, &a.NewMembersLast30Days)
	if err != nil {
		return nil, err
	}

	// ── Pending invitations ───────────────────────────────────────────────────
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM invitations
		WHERE org_id = $1 AND accepted_at IS NULL AND expires_at > NOW()`, orgID,
	).Scan(&a.PendingInvites)

	// ── MAU / DAU from login_history ─────────────────────────────────────────
	_ = r.pool.QueryRow(ctx, `
		SELECT
		  COUNT(DISTINCT CASE WHEN created_at >= $2 AND status='success' THEN user_id END),
		  COUNT(DISTINCT CASE WHEN created_at >= $3 AND status='success' THEN user_id END)
		FROM login_history WHERE org_id = $1`,
		orgID, windowStart, dayStart,
	).Scan(&a.MAU, &a.DAU)

	// ── Retention: D7 cohort ─────────────────────────────────────────────────
	// Users who first appeared 8-37 days ago and came back within 7 days.
	cohortStart7 := now.AddDate(0, 0, -37)
	cohortEnd7 := now.AddDate(0, 0, -8)
	var cohortD7, retainedD7 int64
	_ = r.pool.QueryRow(ctx, `
		WITH cohort AS (
			SELECT user_id, MIN(created_at) AS first_seen
			FROM login_history
			WHERE org_id = $1 AND status = 'success'
			GROUP BY user_id
			HAVING MIN(created_at) BETWEEN $2 AND $3
		)
		SELECT
		  COUNT(*),
		  COUNT(*) FILTER (
		    WHERE EXISTS (
		      SELECT 1 FROM login_history lh
		      WHERE lh.user_id = cohort.user_id
		        AND lh.status = 'success'
		        AND lh.created_at > cohort.first_seen
		        AND lh.created_at <= cohort.first_seen + INTERVAL '7 days'
		    )
		  )
		FROM cohort`,
		orgID, cohortStart7, cohortEnd7,
	).Scan(&cohortD7, &retainedD7)
	if cohortD7 > 0 {
		a.RetentionD7 = float64(retainedD7) / float64(cohortD7)
	}

	// ── Retention: D30 cohort ────────────────────────────────────────────────
	cohortStart30 := now.AddDate(0, 0, -60)
	cohortEnd30 := now.AddDate(0, 0, -31)
	var cohortD30, retainedD30 int64
	_ = r.pool.QueryRow(ctx, `
		WITH cohort AS (
			SELECT user_id, MIN(created_at) AS first_seen
			FROM login_history
			WHERE org_id = $1 AND status = 'success'
			GROUP BY user_id
			HAVING MIN(created_at) BETWEEN $2 AND $3
		)
		SELECT
		  COUNT(*),
		  COUNT(*) FILTER (
		    WHERE EXISTS (
		      SELECT 1 FROM login_history lh
		      WHERE lh.user_id = cohort.user_id
		        AND lh.status = 'success'
		        AND lh.created_at > cohort.first_seen
		        AND lh.created_at <= cohort.first_seen + INTERVAL '30 days'
		    )
		  )
		FROM cohort`,
		orgID, cohortStart30, cohortEnd30,
	).Scan(&cohortD30, &retainedD30)
	if cohortD30 > 0 {
		a.RetentionD30 = float64(retainedD30) / float64(cohortD30)
	}

	// ── DAU time series ───────────────────────────────────────────────────────
	rows, err := r.pool.Query(ctx, `
		SELECT DATE(created_at) AS d, COUNT(DISTINCT user_id)
		FROM login_history
		WHERE org_id = $1 AND status = 'success' AND created_at >= $2
		GROUP BY d ORDER BY d`,
		orgID, windowStart)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dc DailyCount
			var t time.Time
			if scanErr := rows.Scan(&t, &dc.Count); scanErr == nil {
				dc.Date = t.Format("2006-01-02")
				a.DAUTimeSeries = append(a.DAUTimeSeries, dc)
			}
		}
	}
	if a.DAUTimeSeries == nil {
		a.DAUTimeSeries = []DailyCount{}
	}

	// ── New members time series ───────────────────────────────────────────────
	mrows, merr := r.pool.Query(ctx, `
		SELECT DATE(created_at) AS d, COUNT(*)
		FROM users
		WHERE org_id = $1 AND created_at >= $2
		GROUP BY d ORDER BY d`,
		orgID, windowStart)
	if merr == nil {
		defer mrows.Close()
		for mrows.Next() {
			var dc DailyCount
			var t time.Time
			if scanErr := mrows.Scan(&t, &dc.Count); scanErr == nil {
				dc.Date = t.Format("2006-01-02")
				a.NewMembersTimeSeries = append(a.NewMembersTimeSeries, dc)
			}
		}
	}
	if a.NewMembersTimeSeries == nil {
		a.NewMembersTimeSeries = []DailyCount{}
	}

	// ── Failed login rate (last 30 days) ─────────────────────────────────────
	var totalLogins, failedLogins int64
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'failure')
		FROM login_history WHERE org_id = $1 AND created_at >= $2`,
		orgID, windowStart,
	).Scan(&totalLogins, &failedLogins)
	if totalLogins > 0 {
		a.FailedLoginRate30d = float64(failedLogins) / float64(totalLogins)
	}

	// ── Inactive users (no successful login in last 30 days) ─────────────────
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users u
		WHERE u.org_id = $1 AND u.is_active = TRUE
		  AND NOT EXISTS (
		    SELECT 1 FROM login_history lh
		    WHERE lh.user_id = u.id
		      AND lh.status = 'success'
		      AND lh.created_at >= $2
		  )`,
		orgID, windowStart,
	).Scan(&a.InactiveUsers30d)

	// ── Login method breakdown (last 30 days, successful only) ───────────────
	lmRows, lmErr := r.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(auth_method, ''), 'password') AS method, COUNT(*) AS cnt
		FROM login_history
		WHERE org_id = $1 AND status = 'success' AND created_at >= $2
		GROUP BY method ORDER BY cnt DESC LIMIT 20`,
		orgID, windowStart)
	if lmErr == nil {
		defer lmRows.Close()
		for lmRows.Next() {
			var s LoginMethodStat
			if scanErr := lmRows.Scan(&s.Method, &s.Count); scanErr == nil {
				a.LoginMethodBreakdown = append(a.LoginMethodBreakdown, s)
			}
		}
	}
	if a.LoginMethodBreakdown == nil {
		a.LoginMethodBreakdown = []LoginMethodStat{}
	}

	return a, nil
}
