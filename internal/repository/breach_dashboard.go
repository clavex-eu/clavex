package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BreachCategoryCount is one row of the per-category breakdown.
type BreachCategoryCount struct {
	Category string `json:"category"` // exact_match | common_password | sub_address
	Count    int64  `json:"count"`
}

// BreachDashboard is the aggregated breached-password summary for an org.
// The shape mirrors FusionAuth's breached-password report.
type BreachDashboard struct {
	// ── Aggregate counters ────────────────────────────────────────────────────

	// TotalDetected is the total number of breach detection events recorded
	// (all time, not limited to 30 days) for this org.
	TotalDetected int64 `json:"total_detected"`

	// CategoryBreakdown lists breach counts per category (all time).
	CategoryBreakdown []BreachCategoryCount `json:"category_breakdown"`

	// ── 30-day window counters ────────────────────────────────────────────────

	// UsersActionRequired is the number of users that currently have
	// 'force_reset' in their required_actions (password not yet changed).
	UsersActionRequired int `json:"users_action_required"`
	// BlockedLast30d is the number of login-blocked events due to breach in
	// the last 30 days (sourced from audit_logs).
	BlockedLast30d   int `json:"blocked_30d"`
	// WarnedLast30d is the number of breach-warning events in the last 30 days.
	WarnedLast30d    int `json:"warned_30d"`
	// ForceResetLast30d is the number of force-reset events in the last 30 days.
	ForceResetLast30d int `json:"force_reset_30d"`

	// ── Paginated user list ───────────────────────────────────────────────────

	// UsersAtRisk is the paginated list of users with a pending breach action.
	UsersAtRisk []BreachUserEntry `json:"users_at_risk"`
	Page        int               `json:"page"`
	PerPage     int               `json:"per_page"`
	TotalUsers  int64             `json:"total_users"` // total users_at_risk rows
}

// BreachUserEntry is a single at-risk user in the breach dashboard.
type BreachUserEntry struct {
	UserID         uuid.UUID  `json:"user_id"`
	Email          string     `json:"email"`
	FirstName      *string    `json:"first_name,omitempty"`
	LastName       *string    `json:"last_name,omitempty"`
	IsActive       bool       `json:"is_active"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
	// LastBreachDetectedAt is the most recent audit event timestamp for this
	// user's breach detection (login.breach_force_reset, login.breach_warn,
	// login.blocked/breached_password).
	LastBreachDetectedAt *time.Time `json:"last_breach_detected_at,omitempty"`
	// BreachCategory is the most recent category from breach_events for this user.
	BreachCategory *string `json:"breach_category,omitempty"`
	// HIBPCount is the HIBP occurrence count at last detection.
	HIBPCount *int `json:"hibp_count,omitempty"`
}

// BreachRepository handles breach-dashboard queries.
type BreachRepository struct {
	pool *pgxpool.Pool
}

func NewBreachRepository(pool *pgxpool.Pool) *BreachRepository {
	return &BreachRepository{pool: pool}
}

// RecordEventParams carries the data for one breach detection event.
type RecordEventParams struct {
	OrgID          uuid.UUID
	UserID         *uuid.UUID // nil for unauthenticated registration checks
	Email          string
	BreachCategory string    // exact_match | common_password | sub_address
	HIBPCount      int
	ActionTaken    string    // warn | block | force_reset
	Context        string    // registration | password_change | login
}

// RecordEvent inserts one breach detection into breach_events.
// Errors are non-fatal; callers should log but proceed.
func (r *BreachRepository) RecordEvent(ctx context.Context, p RecordEventParams) error {
	if p.Context == "" {
		p.Context = "password_change"
	}
	_, err := r.pool.Exec(ctx,
		`INSERT INTO breach_events (org_id, user_id, email, breach_category, hibp_count, action_taken, context)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		p.OrgID, p.UserID, p.Email, p.BreachCategory, p.HIBPCount, p.ActionTaken, p.Context,
	)
	return err
}

// GetDashboard returns the aggregated breach dashboard for org orgID.
func (r *BreachRepository) GetDashboard(ctx context.Context, orgID uuid.UUID, page, perPage int) (*BreachDashboard, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	offset := (page - 1) * perPage

	d := &BreachDashboard{Page: page, PerPage: perPage}
	since30d := time.Now().AddDate(0, 0, -30)

	// ── 1. Aggregate totals from breach_events ────────────────────────────────
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM breach_events WHERE org_id = $1`, orgID,
	).Scan(&d.TotalDetected); err != nil {
		return nil, err
	}

	// ── 2. Category breakdown (all time) ─────────────────────────────────────
	catRows, err := r.pool.Query(ctx,
		`SELECT breach_category, COUNT(*) FROM breach_events
		 WHERE org_id = $1 GROUP BY breach_category ORDER BY COUNT(*) DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer catRows.Close()
	for catRows.Next() {
		var c BreachCategoryCount
		if scanErr := catRows.Scan(&c.Category, &c.Count); scanErr == nil {
			d.CategoryBreakdown = append(d.CategoryBreakdown, c)
		}
	}
	if d.CategoryBreakdown == nil {
		d.CategoryBreakdown = []BreachCategoryCount{}
	}

	// ── 3. Users currently requiring action (force_reset pending) ────────────
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE org_id = $1 AND 'force_reset' = ANY(required_actions)`,
		orgID,
	).Scan(&d.UsersActionRequired); err != nil {
		return nil, err
	}

	// ── 4. Audit event counters for the last 30 days ─────────────────────────
	type counter struct {
		action string
		dest   *int
	}
	counters := []counter{
		{"login.blocked", &d.BlockedLast30d},
		{"login.breach_warn", &d.WarnedLast30d},
		{"login.breach_force_reset", &d.ForceResetLast30d},
	}
	for _, c := range counters {
		if err := r.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit.audit_logs
			 WHERE org_id = $1 AND action = $2 AND created_at >= $3`,
			orgID, c.action, since30d,
		).Scan(c.dest); err != nil {
			return nil, err
		}
	}

	// ── 5. Total at-risk users count ──────────────────────────────────────────
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE org_id = $1 AND 'force_reset' = ANY(required_actions)`,
		orgID,
	).Scan(&d.TotalUsers); err != nil {
		return nil, err
	}

	// ── 6. Per-user at-risk list (paginated) ──────────────────────────────────
	// Joins with breach_events to surface the latest category + HIBP count.
	rows, err := r.pool.Query(ctx, `
		SELECT
		  u.id, u.email, u.first_name, u.last_name, u.is_active, u.last_login_at,
		  (
		    SELECT MAX(al.created_at)
		    FROM audit.audit_logs al
		    WHERE al.org_id = $1 AND al.user_id = u.id
		      AND al.action IN (
		          'login.blocked', 'login.breach_warn', 'login.breach_force_reset'
		      )
		  ) AS last_breach_at,
		  (
		    SELECT be.breach_category FROM breach_events be
		    WHERE be.org_id = $1 AND be.user_id = u.id
		    ORDER BY be.detected_at DESC LIMIT 1
		  ) AS breach_category,
		  (
		    SELECT be.hibp_count FROM breach_events be
		    WHERE be.org_id = $1 AND be.user_id = u.id
		    ORDER BY be.detected_at DESC LIMIT 1
		  ) AS hibp_count
		FROM users u
		WHERE u.org_id = $1
		  AND 'force_reset' = ANY(u.required_actions)
		ORDER BY last_breach_at DESC NULLS LAST, u.email ASC
		LIMIT $2 OFFSET $3`,
		orgID, perPage, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var e BreachUserEntry
		if err := rows.Scan(
			&e.UserID, &e.Email, &e.FirstName, &e.LastName,
			&e.IsActive, &e.LastLoginAt, &e.LastBreachDetectedAt,
			&e.BreachCategory, &e.HIBPCount,
		); err != nil {
			return nil, err
		}
		d.UsersAtRisk = append(d.UsersAtRisk, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if d.UsersAtRisk == nil {
		d.UsersAtRisk = []BreachUserEntry{} // always return array, never null
	}

	return d, nil
}
