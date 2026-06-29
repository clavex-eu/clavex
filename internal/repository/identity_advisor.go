package repository

// IdentityAdvisorRepository gathers the weekly security signals needed by the
// AI Identity Advisor. All queries are read-only and best-effort: individual
// query failures are silently ignored so that a partial data set is always
// returned (the advisor degrades gracefully when tables are missing or empty).

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IdentityAdvisorRepository handles signal gathering for the weekly AI report.
type IdentityAdvisorRepository struct {
	pool *pgxpool.Pool
}

// NewIdentityAdvisorRepository creates an IdentityAdvisorRepository.
func NewIdentityAdvisorRepository(pool *pgxpool.Pool) *IdentityAdvisorRepository {
	return &IdentityAdvisorRepository{pool: pool}
}

// AdvisorSignals contains all security signals for a single org's weekly report.
type AdvisorSignals struct {
	OrgID   uuid.UUID `json:"org_id"`
	OrgName string    `json:"org_name"`
	OrgSlug string    `json:"org_slug"`
	Since   time.Time `json:"since"`  // start of the analysis window (usually 7 days ago)
	Until   time.Time `json:"until"`  // end of the analysis window (usually now)

	// ── Login activity ────────────────────────────────────────────────────────
	TotalLogins       int `json:"total_logins"`
	FailedLogins      int `json:"failed_logins"`
	UniqueActiveUsers int `json:"unique_active_users"` // distinct user_ids with a successful login
	MaliciousIPLogins int `json:"malicious_ip_logins"` // Shield: is_malicious = true
	TorExitLogins     int `json:"tor_exit_logins"`     // Shield: is_tor_exit = true

	// ── Geographic anomalies ──────────────────────────────────────────────────
	// Countries present in the current window but ABSENT from the 30 days before it.
	// Empty when no historical baseline exists (new org / no prior login data).
	UnusualCountries []UnusualCountry `json:"unusual_countries"`

	// ── Admin hygiene ─────────────────────────────────────────────────────────
	// Active admin users (any admin_role_assignment) with ZERO registered MFA credentials.
	// An admin without MFA is a single-factor privileged account — critical risk.
	AdminsWithoutMFA []AdminWithoutMFA `json:"admins_without_mfa"`

	// ── OAuth2/OIDC client security ───────────────────────────────────────────
	// Clients that have at least one redirect_uri containing a wildcard ('*')
	// or a bare '%' (open redirect risk, token hijack vector).
	WildcardRedirectClients []WildcardRedirectClient `json:"wildcard_redirect_clients"`

	// ── Posture & drift ───────────────────────────────────────────────────────
	ConformanceScore *AdvisorConformanceScore `json:"conformance_score,omitempty"`
	RecentDrift      []AdvisorDriftEvent      `json:"recent_drift"`
	SecurityState    *AdvisorSecurityState    `json:"security_state,omitempty"`

	// ── Delivery ──────────────────────────────────────────────────────────────
	// Email addresses of active admin users — used by the worker to send the report.
	AdminEmails []string `json:"admin_emails"`
}

// UnusualCountry is a country that was NOT seen in the historical baseline.
type UnusualCountry struct {
	CountryCode string `json:"country_code"`
	LoginCount  int    `json:"login_count"`
}

// AdminWithoutMFA is an active admin user with no MFA credentials registered.
type AdminWithoutMFA struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

// WildcardRedirectClient is a client with at least one wildcard redirect URI.
type WildcardRedirectClient struct {
	ClientName       string   `json:"client_name"`
	WildcardURIs     []string `json:"wildcard_uris"`
}

// AdvisorConformanceScore carries the relevant score fields for the report.
type AdvisorConformanceScore struct {
	Score      int `json:"score"`
	ScoreMFA   int `json:"score_mfa"`
	ScorePKCE  int `json:"score_pkce"`
	ScoreDPoP  int `json:"score_dpop"`
	ScoreNIS2  int `json:"score_nis2"`
}

// AdvisorDriftEvent is a simplified drift event for the advisor prompt.
type AdvisorDriftEvent struct {
	Control       string  `json:"control"`
	PreviousValue *string `json:"previous_value,omitempty"`
	CurrentValue  *string `json:"current_value,omitempty"`
	Severity      string  `json:"severity"`
	DetectedAt    string  `json:"detected_at"`
}

// AdvisorSecurityState carries org-level policy settings relevant to risk.
type AdvisorSecurityState struct {
	MFARequired    bool   `json:"mfa_required"`
	AccessTokenTTL *int   `json:"access_token_ttl_secs,omitempty"`
	AdminCount     int    `json:"admin_count"`
	OrgSlug        string `json:"org_slug"`
}

// GatherSignals collects all security signals for the given org over the [since, now] window.
// Each sub-query is best-effort; partial failures are silently swallowed so the
// caller always receives whatever data is available.
func (r *IdentityAdvisorRepository) GatherSignals(
	ctx context.Context,
	orgID uuid.UUID,
	since time.Time,
) (*AdvisorSignals, error) {
	now := time.Now().UTC()
	sig := &AdvisorSignals{
		OrgID: orgID,
		Since: since,
		Until: now,
	}

	// ── Org metadata ──────────────────────────────────────────────────────────
	_ = r.pool.QueryRow(ctx,
		`SELECT name, slug FROM organizations WHERE id = $1`, orgID,
	).Scan(&sig.OrgName, &sig.OrgSlug)

	// ── Login stats ───────────────────────────────────────────────────────────
	_ = r.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*)                                                              AS total_logins,
		  COUNT(*) FILTER (WHERE status = 'failure')                            AS failed_logins,
		  COUNT(DISTINCT user_id) FILTER (WHERE status = 'success' AND user_id IS NOT NULL) AS unique_users,
		  COUNT(*) FILTER (WHERE is_malicious = TRUE)                           AS malicious_ip,
		  COUNT(*) FILTER (WHERE is_tor_exit = TRUE)                            AS tor_exit
		FROM login_history
		WHERE org_id = $1 AND created_at >= $2
	`, orgID, since).Scan(
		&sig.TotalLogins,
		&sig.FailedLogins,
		&sig.UniqueActiveUsers,
		&sig.MaliciousIPLogins,
		&sig.TorExitLogins,
	)

	// ── Unusual country logins ────────────────────────────────────────────────
	// Countries with successful logins in [since, now] that had ZERO successful
	// logins in the 30-day window immediately before `since` (historical baseline).
	baselineStart := since.Add(-30 * 24 * time.Hour)
	rows, err := r.pool.Query(ctx, `
		WITH recent AS (
		  SELECT country_code, COUNT(*) AS login_count
		  FROM login_history
		  WHERE org_id = $1
		    AND status = 'success'
		    AND country_code IS NOT NULL
		    AND created_at >= $2
		  GROUP BY country_code
		),
		historical AS (
		  SELECT DISTINCT country_code
		  FROM login_history
		  WHERE org_id = $1
		    AND status = 'success'
		    AND country_code IS NOT NULL
		    AND created_at >= $3 AND created_at < $2
		)
		SELECT r.country_code, r.login_count
		FROM recent r
		LEFT JOIN historical h USING (country_code)
		WHERE h.country_code IS NULL
		ORDER BY r.login_count DESC
	`, orgID, since, baselineStart)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var u UnusualCountry
			if err := rows.Scan(&u.CountryCode, &u.LoginCount); err == nil {
				sig.UnusualCountries = append(sig.UnusualCountries, u)
			}
		}
	}

	// ── Admins without MFA ────────────────────────────────────────────────────
	rows2, err := r.pool.Query(ctx, `
		SELECT u.id, u.email
		FROM admin_role_assignments ara
		JOIN users u ON u.id = ara.user_id AND u.org_id = ara.org_id
		WHERE ara.org_id = $1
		  AND u.is_active = TRUE
		  AND NOT EXISTS (
		    SELECT 1 FROM mfa_credentials mc WHERE mc.user_id = u.id
		  )
		GROUP BY u.id, u.email
		ORDER BY u.email
	`, orgID)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var a AdminWithoutMFA
			if err := rows2.Scan(&a.UserID, &a.Email); err == nil {
				sig.AdminsWithoutMFA = append(sig.AdminsWithoutMFA, a)
			}
		}
	}

	// ── Clients with wildcard redirect URIs ───────────────────────────────────
	rows3, err := r.pool.Query(ctx, `
		SELECT name, redirect_uris
		FROM oidc_clients
		WHERE org_id = $1
		  AND is_active = TRUE
		  AND EXISTS (
		    SELECT 1 FROM unnest(redirect_uris) AS uri WHERE uri LIKE '%*%' OR uri LIKE '%%'
		  )
		ORDER BY name
	`, orgID)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var name string
			var uris []string
			if err := rows3.Scan(&name, &uris); err == nil {
				var wildcards []string
				for _, u := range uris {
					if strings.Contains(u, "*") || strings.Contains(u, "%") {
						wildcards = append(wildcards, u)
					}
				}
				if len(wildcards) > 0 {
					sig.WildcardRedirectClients = append(sig.WildcardRedirectClients, WildcardRedirectClient{
						ClientName:   name,
						WildcardURIs: wildcards,
					})
				}
			}
		}
	}

	// ── Conformance score ─────────────────────────────────────────────────────
	var cs AdvisorConformanceScore
	err = r.pool.QueryRow(ctx, `
		SELECT score, score_mfa, score_pkce, score_dpop, score_nis2
		FROM conformance_scores
		WHERE org_id = $1
	`, orgID).Scan(&cs.Score, &cs.ScoreMFA, &cs.ScorePKCE, &cs.ScoreDPoP, &cs.ScoreNIS2)
	if err == nil {
		sig.ConformanceScore = &cs
	}

	// ── Recent compliance drift events ────────────────────────────────────────
	rows4, err := r.pool.Query(ctx, `
		SELECT control, previous_value, current_value, severity, detected_at
		FROM compliance_drift_events
		WHERE org_id = $1 AND detected_at >= $2
		ORDER BY detected_at DESC
		LIMIT 20
	`, orgID, since)
	if err == nil {
		defer rows4.Close()
		for rows4.Next() {
			var ev AdvisorDriftEvent
			var det time.Time
			if err := rows4.Scan(&ev.Control, &ev.PreviousValue, &ev.CurrentValue, &ev.Severity, &det); err == nil {
				ev.DetectedAt = det.Format(time.RFC3339)
				sig.RecentDrift = append(sig.RecentDrift, ev)
			}
		}
	}

	// ── Org security state ────────────────────────────────────────────────────
	var ss AdvisorSecurityState
	ss.OrgSlug = sig.OrgSlug
	err = r.pool.QueryRow(ctx, `
		SELECT mfa_required, access_token_ttl
		FROM organizations
		WHERE id = $1
	`, orgID).Scan(&ss.MFARequired, &ss.AccessTokenTTL)
	if err == nil {
		_ = r.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM admin_role_assignments WHERE org_id = $1
		`, orgID).Scan(&ss.AdminCount)
		sig.SecurityState = &ss
	}

	// ── Admin recipient emails ────────────────────────────────────────────────
	rows5, err := r.pool.Query(ctx, `
		SELECT DISTINCT u.email
		FROM admin_role_assignments ara
		JOIN users u ON u.id = ara.user_id AND u.org_id = ara.org_id
		WHERE ara.org_id = $1 AND u.is_active = TRUE
		ORDER BY u.email
	`, orgID)
	if err == nil {
		defer rows5.Close()
		for rows5.Next() {
			var email string
			if err := rows5.Scan(&email); err == nil {
				sig.AdminEmails = append(sig.AdminEmails, email)
			}
		}
	}

	return sig, nil
}
