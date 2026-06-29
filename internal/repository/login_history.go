package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LoginHistoryRepository handles the append-only login_history table and
// per-org rate limit configuration.
type LoginHistoryRepository struct {
	pool *pgxpool.Pool
}

func NewLoginHistoryRepository(pool *pgxpool.Pool) *LoginHistoryRepository {
	return &LoginHistoryRepository{pool: pool}
}

// ── Login event recording ─────────────────────────────────────────────────────

// RecordLoginParams carries the fields for a single auth event.
type RecordLoginParams struct {
	OrgID         uuid.UUID
	UserID        *uuid.UUID
	Email         *string
	AuthMethod    string // "password" | "totp" | "webauthn" | "magic_link" | "idp" | "spid" | "cie" | "device"
	Status        string // "success" | "failure"
	FailureReason *string
	IPAddress     *string
	UserAgent     *string
	CountryCode   *string
	City          *string
	ASNOrg        *string
	ClientID      *uuid.UUID
	SessionID     *string
	// Shield threat-intel verdict (nil when Shield not configured or IP is private).
	IsMalicious    *bool
	ConfidenceScore *int
	IsTorExit      *bool
}

// RecordLogin inserts an immutable login event.
// Errors are never returned to the caller — this must not break the auth flow;
// use the returned bool to know if the write succeeded (for metrics).
func (r *LoginHistoryRepository) RecordLogin(ctx context.Context, p RecordLoginParams) bool {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO login_history
		    (org_id, user_id, email, auth_method, status, failure_reason,
		     ip_address, user_agent, country_code, city, asn_org, client_id, session_id,
		     is_malicious, confidence_score, is_tor_exit)
		VALUES ($1, $2, $3, $4, $5, $6,
		        $7::inet, $8, $9, $10, $11, $12, $13,
		        $14, $15, $16)
	`,
		p.OrgID, p.UserID, p.Email, p.AuthMethod, p.Status, p.FailureReason,
		p.IPAddress, p.UserAgent, p.CountryCode, p.City, p.ASNOrg, p.ClientID, p.SessionID,
		p.IsMalicious, p.ConfidenceScore, p.IsTorExit,
	)
	return err == nil
}

// ── Login history queries ─────────────────────────────────────────────────────

// ListLoginHistoryParams controls the LoginHistory list query.
type ListLoginHistoryParams struct {
	// One of OrgID or UserID must be set, or both.
	OrgID  *uuid.UUID
	UserID *uuid.UUID
	// Optional filters
	Status string    // "success" | "failure" | "" (all)
	Since  time.Time // zero = no lower bound
	Until  time.Time // zero = no upper bound
	After  int64     // cursor: last event ID seen (0 = first page)
	Limit  int       // <= 0 → DefaultPageSize
}

const loginHistoryCols = `id, org_id, user_id, email, auth_method, status, failure_reason,
       ip_address::text, user_agent, country_code, city, asn_org, client_id, session_id, created_at`

// ListLoginHistory returns a cursor-paginated list of login events.
func (r *LoginHistoryRepository) ListLoginHistory(ctx context.Context, p ListLoginHistoryParams) (*models.Page[*models.LoginEvent], error) {
	limit := p.Limit
	if limit <= 0 {
		limit = models.DefaultPageSize
	}
	if limit > models.MaxPageSize {
		limit = models.MaxPageSize
	}
	fetch := limit + 1

	// Build query dynamically based on filters.
	args := make([]any, 0, 8)
	where := "WHERE TRUE"
	addArg := func(v any) string {
		args = append(args, v)
		return pg(len(args))
	}

	if p.OrgID != nil {
		where += " AND org_id = " + addArg(*p.OrgID)
	}
	if p.UserID != nil {
		where += " AND user_id = " + addArg(*p.UserID)
	}
	if p.Status != "" {
		where += " AND status = " + addArg(p.Status)
	}
	if !p.Since.IsZero() {
		where += " AND created_at >= " + addArg(p.Since)
	}
	if !p.Until.IsZero() {
		where += " AND created_at < " + addArg(p.Until)
	}
	if p.After > 0 {
		where += " AND id < " + addArg(p.After) // page backwards by ID (DESC sort)
	}
	where += " ORDER BY created_at DESC, id DESC"
	where += " LIMIT " + addArg(fetch)

	rows, err := r.pool.Query(ctx, `SELECT `+loginHistoryCols+` FROM login_history `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]*models.LoginEvent, 0, limit)
	for rows.Next() {
		e := &models.LoginEvent{}
		if err := rows.Scan(
			&e.ID, &e.OrgID, &e.UserID, &e.Email, &e.AuthMethod, &e.Status,
			&e.FailureReason, &e.IPAddress, &e.UserAgent, &e.CountryCode,
			&e.City, &e.ASNOrg, &e.ClientID, &e.SessionID, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	hasMore := len(events) == fetch
	if hasMore {
		events = events[:limit]
	}

	page := &models.Page[*models.LoginEvent]{Items: events, HasMore: hasMore}
	if hasMore && len(events) > 0 {
		// Next cursor is the smallest ID on this page (we're paginating DESC).
		cursor := fmt.Sprintf("%d", events[len(events)-1].ID)
		page.NextCursor = &cursor
	}
	return page, nil
}

// ── Anomaly signals ───────────────────────────────────────────────────────────

// AnomalySignals is a lightweight struct used to detect suspicious login patterns.
type AnomalySignals struct {
	// DistinctCountries is the number of distinct countries seen for this user
	// in the lookback window (rolling 7 days).
	DistinctCountries int
	// FailureCount is the number of failed login attempts from this IP in the
	// last hour.
	FailureCount int
	// LastSeenCountry is the country of the most recent successful login.
	LastSeenCountry *string
	// NewCountry is true if the current CountryCode has never been seen before
	// for this user.
	NewCountry bool
}

// GetAnomalySignals returns signals for real-time risk scoring immediately
// before (or after) recording a new login attempt.
// currentCountry may be empty ("") if geo-IP is unavailable.
func (r *LoginHistoryRepository) GetAnomalySignals(
	ctx context.Context, userID uuid.UUID, ipAddress, currentCountry string,
) (*AnomalySignals, error) {
	s := &AnomalySignals{}

	// Distinct country count from last 7 days (success only).
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT country_code)
		FROM login_history
		WHERE user_id = $1
		  AND status = 'success'
		  AND country_code IS NOT NULL
		  AND created_at >= NOW() - INTERVAL '7 days'
	`, userID).Scan(&s.DistinctCountries)

	// Recent failure count from this IP (last 1 hour, any org).
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM login_history
		WHERE ip_address = $1::inet
		  AND status = 'failure'
		  AND created_at >= NOW() - INTERVAL '1 hour'
	`, ipAddress).Scan(&s.FailureCount)

	// Last known country for this user.
	_ = r.pool.QueryRow(ctx, `
		SELECT country_code
		FROM login_history
		WHERE user_id = $1 AND status = 'success' AND country_code IS NOT NULL
		ORDER BY created_at DESC LIMIT 1
	`, userID).Scan(&s.LastSeenCountry)

	// New-country detection.
	if currentCountry != "" {
		var seen int
		_ = r.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM login_history
			WHERE user_id = $1 AND country_code = $2 AND status = 'success'
		`, userID, currentCountry).Scan(&seen)
		s.NewCountry = seen == 0
	}

	return s, nil
}

// ── Rate limit configuration ──────────────────────────────────────────────────

// GetOrgRateLimits fetches the per-org rate limit config.
// If no row exists (pre-migration orgs), returns safe defaults.
func (r *LoginHistoryRepository) GetOrgRateLimits(ctx context.Context, orgID uuid.UUID) (*models.OrgRateLimits, error) {
	rl := &models.OrgRateLimits{
		OrgID:                orgID,
		LoginPerIPPerMin:     10,
		TokenPerClientPerMin: 60,
		GlobalPerIPPerMin:    120,
		EndpointLimits:       map[string]int{},
	}
	var endpointRaw []byte
	err := r.pool.QueryRow(ctx, `
		SELECT login_per_ip_per_min, token_per_client_per_min, global_per_ip_per_min,
		       endpoint_limits, updated_at
		FROM org_rate_limits WHERE org_id = $1
	`, orgID).Scan(
		&rl.LoginPerIPPerMin, &rl.TokenPerClientPerMin, &rl.GlobalPerIPPerMin,
		&endpointRaw, &rl.UpdatedAt,
	)
	if err != nil {
		// No row yet — return defaults.
		return rl, nil
	}
	if len(endpointRaw) > 0 {
		_ = json.Unmarshal(endpointRaw, &rl.EndpointLimits)
	}
	return rl, nil
}

// UpsertOrgRateLimits creates or replaces the rate limit config for an org.
func (r *LoginHistoryRepository) UpsertOrgRateLimits(
	ctx context.Context, orgID uuid.UUID,
	loginPerIP, tokenPerClient, globalPerIP int,
	endpointLimits map[string]int,
) (*models.OrgRateLimits, error) {
	endpointJSON, err := json.Marshal(endpointLimits)
	if err != nil {
		return nil, fmt.Errorf("marshal endpoint_limits: %w", err)
	}
	var endpointRaw []byte
	rl := &models.OrgRateLimits{}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO org_rate_limits
		    (org_id, login_per_ip_per_min, token_per_client_per_min, global_per_ip_per_min, endpoint_limits)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (org_id) DO UPDATE SET
		    login_per_ip_per_min     = EXCLUDED.login_per_ip_per_min,
		    token_per_client_per_min = EXCLUDED.token_per_client_per_min,
		    global_per_ip_per_min    = EXCLUDED.global_per_ip_per_min,
		    endpoint_limits          = EXCLUDED.endpoint_limits,
		    updated_at               = NOW()
		RETURNING org_id, login_per_ip_per_min, token_per_client_per_min,
		          global_per_ip_per_min, endpoint_limits, updated_at
	`, orgID, loginPerIP, tokenPerClient, globalPerIP, endpointJSON).Scan(
		&rl.OrgID, &rl.LoginPerIPPerMin, &rl.TokenPerClientPerMin,
		&rl.GlobalPerIPPerMin, &endpointRaw, &rl.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(endpointRaw) > 0 {
		_ = json.Unmarshal(endpointRaw, &rl.EndpointLimits)
	}
	return rl, nil
}

// pg returns a PostgreSQL positional parameter placeholder ($1, $2, …).
func pg(n int) string {
	return fmt.Sprintf("$%d", n)
}

// ── Org-level risk aggregation ────────────────────────────────────────────────

// OrgRiskSummary is the aggregate risk view for a tenant dashboard.
type OrgRiskSummary struct {
	// Top users by cumulative failure+anomaly score in the last 24 h.
	TopRiskyUsers []UserRiskEntry `json:"top_risky_users"`
	// Login counts grouped by country_code (last 7 days).
	CountryBreakdown []CountryCount `json:"country_breakdown"`
	// Hourly login volume and failure count for the last 24 h (for sparklines).
	HourlyTrend []HourlyBucket `json:"hourly_trend"`
	// Impossible-travel events in the last 24 h.
	ImpossibleTravelAlerts []ImpossibleTravelAlert `json:"impossible_travel_alerts"`
}

// UserRiskEntry is a row in the top-10 risky users list.
type UserRiskEntry struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	FailureCount int    `json:"failure_count"`
	TotalLogins  int    `json:"total_logins"`
}

// CountryCount aggregates logins per country.
type CountryCount struct {
	CountryCode string `json:"country_code"`
	Count       int    `json:"count"`
}

// HourlyBucket is one hourly slot in the anomaly trend sparkline.
type HourlyBucket struct {
	Hour     string `json:"hour"` // ISO 8601 UTC, truncated to hour
	Logins   int    `json:"logins"`
	Failures int    `json:"failures"`
}

// ImpossibleTravelAlert describes a user who logged in from two distant
// countries within a 2-hour window.
type ImpossibleTravelAlert struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Country1  string    `json:"country1"`
	Country2  string    `json:"country2"`
	OccuredAt time.Time `json:"occurred_at"`
}

// GetOrgRiskSummary computes the org-level risk dashboard data.
// It runs four targeted queries against login_history (no full table scan).
func (r *LoginHistoryRepository) GetOrgRiskSummary(ctx context.Context, orgID uuid.UUID) (*OrgRiskSummary, error) {
	out := &OrgRiskSummary{
		TopRiskyUsers:          []UserRiskEntry{},
		CountryBreakdown:       []CountryCount{},
		HourlyTrend:            []HourlyBucket{},
		ImpossibleTravelAlerts: []ImpossibleTravelAlert{},
	}

	// 1. Top-10 users by failure count in the last 24 h.
	rows, err := r.pool.Query(ctx, `
		SELECT lh.user_id::text, u.email,
		       COUNT(*) FILTER (WHERE lh.status = 'failure') AS failure_count,
		       COUNT(*) AS total_logins
		FROM login_history lh
		LEFT JOIN users u ON u.id = lh.user_id
		WHERE lh.org_id = $1
		  AND lh.created_at >= NOW() - INTERVAL '24 hours'
		  AND lh.user_id IS NOT NULL
		GROUP BY lh.user_id, u.email
		HAVING COUNT(*) FILTER (WHERE lh.status = 'failure') > 0
		ORDER BY failure_count DESC
		LIMIT 10
	`, orgID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e UserRiskEntry
			if serr := rows.Scan(&e.UserID, &e.Email, &e.FailureCount, &e.TotalLogins); serr == nil {
				out.TopRiskyUsers = append(out.TopRiskyUsers, e)
			}
		}
		_ = rows.Err()
	}

	// 2. Country breakdown (last 7 days, success logins).
	crows, cerr := r.pool.Query(ctx, `
		SELECT COALESCE(country_code, 'Unknown') AS country_code, COUNT(*) AS cnt
		FROM login_history
		WHERE org_id = $1
		  AND status = 'success'
		  AND created_at >= NOW() - INTERVAL '7 days'
		GROUP BY country_code
		ORDER BY cnt DESC
		LIMIT 30
	`, orgID)
	if cerr == nil {
		defer crows.Close()
		for crows.Next() {
			var c CountryCount
			if serr := crows.Scan(&c.CountryCode, &c.Count); serr == nil {
				out.CountryBreakdown = append(out.CountryBreakdown, c)
			}
		}
		_ = crows.Err()
	}

	// 3. Hourly trend — last 24 hours.
	hrows, herr := r.pool.Query(ctx, `
		SELECT date_trunc('hour', created_at)::text AS hour,
		       COUNT(*) AS logins,
		       COUNT(*) FILTER (WHERE status = 'failure') AS failures
		FROM login_history
		WHERE org_id = $1
		  AND created_at >= NOW() - INTERVAL '24 hours'
		GROUP BY hour
		ORDER BY hour ASC
	`, orgID)
	if herr == nil {
		defer hrows.Close()
		for hrows.Next() {
			var b HourlyBucket
			if serr := hrows.Scan(&b.Hour, &b.Logins, &b.Failures); serr == nil {
				out.HourlyTrend = append(out.HourlyTrend, b)
			}
		}
		_ = hrows.Err()
	}

	// 4. Impossible-travel: successive logins from different countries <2 h apart.
	// We use a self-join on login_history with a window.
	itrows, iterr := r.pool.Query(ctx, `
		WITH ordered AS (
			SELECT user_id, country_code, created_at,
			       LAG(country_code) OVER (PARTITION BY user_id ORDER BY created_at) AS prev_country,
			       LAG(created_at)   OVER (PARTITION BY user_id ORDER BY created_at) AS prev_at
			FROM login_history
			WHERE org_id = $1
			  AND status = 'success'
			  AND country_code IS NOT NULL
			  AND created_at >= NOW() - INTERVAL '24 hours'
		)
		SELECT o.user_id::text, u.email,
		       o.prev_country, o.country_code, o.created_at
		FROM ordered o
		LEFT JOIN users u ON u.id = o.user_id
		WHERE o.prev_country IS NOT NULL
		  AND o.prev_country <> o.country_code
		  AND o.created_at - o.prev_at < INTERVAL '2 hours'
		ORDER BY o.created_at DESC
		LIMIT 20
	`, orgID)
	if iterr == nil {
		defer itrows.Close()
		for itrows.Next() {
			var a ImpossibleTravelAlert
			if serr := itrows.Scan(&a.UserID, &a.Email, &a.Country1, &a.Country2, &a.OccuredAt); serr == nil {
				out.ImpossibleTravelAlerts = append(out.ImpossibleTravelAlerts, a)
			}
		}
		_ = itrows.Err()
	}

	return out, nil
}

// ── Clavex Shield threat-intel dashboard ─────────────────────────────────────

// ShieldDashboard is the aggregated threat-intelligence view for the
// Shield ops dashboard.
type ShieldDashboard struct {
	// BlockedLastHour lists distinct IPs flagged as malicious in the last hour,
	// ordered by highest confidence score.
	BlockedLastHour []ShieldBlockedIP `json:"blocked_last_hour"`
	// TorHourlyTrend shows hourly counts of Tor exit node logins (last 7 days).
	TorHourlyTrend []TorTrendBucket `json:"tor_hourly_trend"`
	// TopIPsThisWeek lists the 10 most-seen malicious IPs this week.
	TopIPsThisWeek []ShieldTopIP `json:"top_ips_this_week"`
	// WeekOverWeek compares this week's vs last week's malicious login counts.
	WeekOverWeek WeekComparison `json:"week_over_week"`
	// Enabled is true when Shield threat-intel enrichment is active (AbuseIPDB
	// key configured). When false the dashboard is empty because enrichment is
	// off, not merely because no threats have been seen yet.
	Enabled bool `json:"enabled"`
}

// ShieldBlockedIP is one row in the blocked-IPs list.
type ShieldBlockedIP struct {
	IPAddress    string    `json:"ip_address"`
	Confidence   int       `json:"confidence"`
	IsTorExit    bool      `json:"is_tor_exit"`
	LoginCount   int       `json:"login_count"`
	LastSeen     time.Time `json:"last_seen"`
}

// TorTrendBucket is one hourly slot in the Tor trend sparkline.
type TorTrendBucket struct {
	Hour  string `json:"hour"`  // ISO 8601 UTC
	Count int    `json:"count"`
}

// ShieldTopIP is one row in the top-10 flagged IPs list.
type ShieldTopIP struct {
	IPAddress  string `json:"ip_address"`
	LoginCount int    `json:"login_count"`
	MaxConf    int    `json:"max_confidence"`
	IsTorExit  bool   `json:"is_tor_exit"`
}

// WeekComparison is the week-over-week malicious login count comparison.
type WeekComparison struct {
	ThisWeek int `json:"this_week"`
	LastWeek int `json:"last_week"`
	// Delta is ThisWeek - LastWeek (positive = more threats this week).
	Delta int `json:"delta"`
}

// GetShieldDashboard returns aggregated threat-intel data for the Shield
// operations dashboard.  All queries scope to org_id and execute independently
// so a slow query does not block the others.
func (r *LoginHistoryRepository) GetShieldDashboard(ctx context.Context, orgID uuid.UUID) (*ShieldDashboard, error) {
	out := &ShieldDashboard{
		BlockedLastHour: []ShieldBlockedIP{},
		TorHourlyTrend:  []TorTrendBucket{},
		TopIPsThisWeek:  []ShieldTopIP{},
	}

	// 1. Blocked IPs — distinct IPs flagged malicious in last 1 hour.
	rows, err := r.pool.Query(ctx, `
		SELECT
		    ip_address::text,
		    MAX(COALESCE(confidence_score, 0)) AS max_conf,
		    BOOL_OR(COALESCE(is_tor_exit, FALSE))  AS is_tor,
		    COUNT(*) AS login_count,
		    MAX(created_at) AS last_seen
		FROM login_history
		WHERE org_id = $1
		  AND is_malicious = TRUE
		  AND created_at >= NOW() - INTERVAL '1 hour'
		  AND ip_address IS NOT NULL
		GROUP BY ip_address
		ORDER BY max_conf DESC, login_count DESC
		LIMIT 50
	`, orgID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var b ShieldBlockedIP
			if serr := rows.Scan(&b.IPAddress, &b.Confidence, &b.IsTorExit, &b.LoginCount, &b.LastSeen); serr == nil {
				out.BlockedLastHour = append(out.BlockedLastHour, b)
			}
		}
		_ = rows.Err()
		rows.Close()
	}

	// 2. Tor exit node login trend — hourly buckets for last 7 days.
	trows, terr := r.pool.Query(ctx, `
		SELECT
		    date_trunc('hour', created_at)::text AS hour,
		    COUNT(*) AS cnt
		FROM login_history
		WHERE org_id = $1
		  AND is_tor_exit = TRUE
		  AND created_at >= NOW() - INTERVAL '7 days'
		GROUP BY hour
		ORDER BY hour ASC
	`, orgID)
	if terr == nil {
		defer trows.Close()
		for trows.Next() {
			var b TorTrendBucket
			if serr := trows.Scan(&b.Hour, &b.Count); serr == nil {
				out.TorHourlyTrend = append(out.TorHourlyTrend, b)
			}
		}
		_ = trows.Err()
		trows.Close()
	}

	// 3. Top 10 malicious IPs this week.
	irows, ierr := r.pool.Query(ctx, `
		SELECT
		    ip_address::text,
		    COUNT(*) AS login_count,
		    MAX(COALESCE(confidence_score, 0)) AS max_conf,
		    BOOL_OR(COALESCE(is_tor_exit, FALSE)) AS is_tor
		FROM login_history
		WHERE org_id = $1
		  AND is_malicious = TRUE
		  AND created_at >= date_trunc('week', NOW())
		  AND ip_address IS NOT NULL
		GROUP BY ip_address
		ORDER BY login_count DESC, max_conf DESC
		LIMIT 10
	`, orgID)
	if ierr == nil {
		defer irows.Close()
		for irows.Next() {
			var t ShieldTopIP
			if serr := irows.Scan(&t.IPAddress, &t.LoginCount, &t.MaxConf, &t.IsTorExit); serr == nil {
				out.TopIPsThisWeek = append(out.TopIPsThisWeek, t)
			}
		}
		_ = irows.Err()
		irows.Close()
	}

	// 4. Week-over-week comparison.
	var thisWeek, lastWeek int
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM login_history
		WHERE org_id = $1 AND is_malicious = TRUE
		  AND created_at >= date_trunc('week', NOW())
	`, orgID).Scan(&thisWeek)
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM login_history
		WHERE org_id = $1 AND is_malicious = TRUE
		  AND created_at >= date_trunc('week', NOW()) - INTERVAL '1 week'
		  AND created_at <  date_trunc('week', NOW())
	`, orgID).Scan(&lastWeek)
	out.WeekOverWeek = WeekComparison{
		ThisWeek: thisWeek,
		LastWeek: lastWeek,
		Delta:    thisWeek - lastWeek,
	}

	return out, nil
}
