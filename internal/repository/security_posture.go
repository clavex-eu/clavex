package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecurityPosture is the org-level security score returned by
// GET /api/v1/organizations/:id/security-posture.
type SecurityPosture struct {
	Score           int `json:"score"`
	MFACoverage     int `json:"mfa_coverage"`
	PasskeyCoverage int `json:"passkey_coverage"`
	PolicyEngine    int `json:"policy_engine"`
	AnomalyScore    int `json:"anomaly_score"`
	KeyRotation     int `json:"key_rotation"`

	TotalUsers         int       `json:"total_users"`
	UsersWithMFA       int       `json:"users_with_mfa"`
	UsersWithPasskey   int       `json:"users_with_passkey"`
	ActivePolicyRules  int       `json:"active_policy_rules"`
	FailedLogins24h    int       `json:"failed_logins_24h"`
	AnomalousLogins24h int       `json:"anomalous_logins_24h"`
	ComputedAt         time.Time `json:"computed_at"`
}

// postureRaw holds raw DB counts; kept separate so computeScores is pure/testable.
type postureRaw struct {
	totalUsers         int
	usersWithMFA       int
	usersWithPasskey   int
	activePolicyRules  int
	failedLogins24h    int
	anomalousLogins24h int
}

// computeScores derives component and overall scores from raw counts.
// Pure function — can be tested without a database.
func computeScores(r postureRaw) *SecurityPosture {
	p := &SecurityPosture{
		TotalUsers:         r.totalUsers,
		UsersWithMFA:       r.usersWithMFA,
		UsersWithPasskey:   r.usersWithPasskey,
		ActivePolicyRules:  r.activePolicyRules,
		FailedLogins24h:    r.failedLogins24h,
		AnomalousLogins24h: r.anomalousLogins24h,
		ComputedAt:         time.Now().UTC(),
	}
	if r.totalUsers > 0 {
		p.MFACoverage = (r.usersWithMFA * 100) / r.totalUsers
		p.PasskeyCoverage = (r.usersWithPasskey * 100) / r.totalUsers
	}
	if r.activePolicyRules > 0 {
		p.PolicyEngine = 100
	}
	p.AnomalyScore = 100 - clampInt(r.failedLogins24h*5, 0, 100)
	p.KeyRotation = 80 // static heuristic: no key-age table yet

	// Weights: MFA 35%, passkey 15%, policy 20%, anomaly 20%, key rotation 10%
	p.Score = (p.MFACoverage*35 + p.PasskeyCoverage*15 + p.PolicyEngine*20 + p.AnomalyScore*20 + p.KeyRotation*10) / 100
	return p
}

// SecurityPostureRepository computes the org security posture score.
type SecurityPostureRepository struct {
	pool *pgxpool.Pool
}

func NewSecurityPostureRepository(pool *pgxpool.Pool) *SecurityPostureRepository {
	return &SecurityPostureRepository{pool: pool}
}

// Compute calculates the security posture for the given org.
func (r *SecurityPostureRepository) Compute(ctx context.Context, orgID uuid.UUID) (*SecurityPosture, error) {
	var raw postureRaw

	err := r.pool.QueryRow(ctx, `
		SELECT
		    COUNT(*)                                                         AS total,
		    COUNT(*) FILTER (WHERE EXISTS (
		        SELECT 1 FROM mfa_credentials mc
		        WHERE mc.user_id = u.id
		    ))                                                               AS with_mfa,
		    COUNT(*) FILTER (WHERE EXISTS (
		        SELECT 1 FROM mfa_credentials mc
		        WHERE mc.user_id = u.id AND mc.type = 'webauthn'
		    ))                                                               AS with_passkey
		FROM users u
		WHERE u.org_id = $1 AND u.is_active = TRUE
	`, orgID).Scan(&raw.totalUsers, &raw.usersWithMFA, &raw.usersWithPasskey)
	if err != nil {
		return nil, err
	}

	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM org_auth_policies
		WHERE org_id = $1 AND is_active = TRUE
	`, orgID).Scan(&raw.activePolicyRules)

	since := time.Now().Add(-24 * time.Hour)
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM login_history
		WHERE org_id = $1 AND status = 'failure' AND created_at >= $2
	`, orgID, since).Scan(&raw.failedLogins24h)

	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM login_history
		WHERE org_id = $1 AND status = 'success'
		  AND created_at >= $2
		  AND failure_reason IS NOT NULL
	`, orgID, since).Scan(&raw.anomalousLogins24h)

	return computeScores(raw), nil
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
