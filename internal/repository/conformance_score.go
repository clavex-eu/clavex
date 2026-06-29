package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConformanceScoreRepository handles persistence for the continuous assurance score.
type ConformanceScoreRepository struct {
	pool *pgxpool.Pool
}

func NewConformanceScoreRepository(pool *pgxpool.Pool) *ConformanceScoreRepository {
	return &ConformanceScoreRepository{pool: pool}
}

// ConformanceScore is the stored real-time security posture score for an org.
type ConformanceScore struct {
	OrgID      uuid.UUID      `json:"org_id"`
	Score      int            `json:"score"`
	ScoreMFA   int            `json:"score_mfa"`
	ScorePKCE  int            `json:"score_pkce"`
	ScoreDPoP  int            `json:"score_dpop"`
	ScoreNIS2  int            `json:"score_nis2"`
	Components map[string]any `json:"components"`
	Threshold  int            `json:"threshold"`
	AlertedAt  *time.Time     `json:"alerted_at,omitempty"`
	ComputedAt time.Time      `json:"computed_at"`
}

// ConformanceScoreInput carries the computed values written by the worker.
type ConformanceScoreInput struct {
	OrgID      uuid.UUID
	Score      int
	ScoreMFA   int
	ScorePKCE  int
	ScoreDPoP  int
	ScoreNIS2  int
	Components map[string]any
}

// ScoreMetrics holds raw component counts queried from the database.
type ScoreMetrics struct {
	// MFA adoption
	UsersTotal   int
	UsersWithMFA int
	// PKCE clients
	ClientsTotal int
	ClientsPKCE  int
	// DPoP-bound clients
	ClientsDPoP int
}

// GetScoreMetrics fetches the raw counts needed for score computation.
func (r *ConformanceScoreRepository) GetScoreMetrics(ctx context.Context, orgID uuid.UUID) (*ScoreMetrics, error) {
	m := &ScoreMetrics{}

	// ── MFA adoption ────────────────────────────────────────────────────────
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users WHERE org_id = $1 AND is_active = TRUE
	`, orgID).Scan(&m.UsersTotal)

	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT mc.user_id)
		FROM mfa_credentials mc
		JOIN users u ON u.id = mc.user_id
		WHERE u.org_id = $1 AND u.is_active = TRUE
	`, orgID).Scan(&m.UsersWithMFA)

	// ── PKCE and DPoP client adoption ──────────────────────────────────────
	_ = r.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*)                                              AS total,
		  COUNT(*) FILTER (WHERE require_pkce = TRUE)          AS pkce,
		  COUNT(*) FILTER (WHERE dpop_bound_access_tokens = TRUE) AS dpop
		FROM oidc_clients
		WHERE org_id = $1 AND is_active = TRUE
	`, orgID).Scan(&m.ClientsTotal, &m.ClientsPKCE, &m.ClientsDPoP)

	return m, nil
}

// UpsertScore stores the latest score for an org, optionally marking it as alerted.
// alertedAt is only written if non-nil and the current alerted_at is NULL.
func (r *ConformanceScoreRepository) UpsertScore(ctx context.Context, in ConformanceScoreInput) error {
	comp, err := json.Marshal(in.Components)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO conformance_scores
		    (org_id, score, score_mfa, score_pkce, score_dpop, score_nis2, components, computed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (org_id) DO UPDATE
		    SET score       = EXCLUDED.score,
		        score_mfa   = EXCLUDED.score_mfa,
		        score_pkce  = EXCLUDED.score_pkce,
		        score_dpop  = EXCLUDED.score_dpop,
		        score_nis2  = EXCLUDED.score_nis2,
		        components  = EXCLUDED.components,
		        computed_at = EXCLUDED.computed_at
	`, in.OrgID, in.Score, in.ScoreMFA, in.ScorePKCE, in.ScoreDPoP, in.ScoreNIS2, comp)
	return err
}

// MarkAlerted sets alerted_at = NOW() for an org (when its score first drops below threshold).
func (r *ConformanceScoreRepository) MarkAlerted(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE conformance_scores SET alerted_at = NOW()
		WHERE org_id = $1 AND alerted_at IS NULL
	`, orgID)
	return err
}

// ClearAlerted resets alerted_at to NULL when the score recovers above threshold.
func (r *ConformanceScoreRepository) ClearAlerted(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE conformance_scores SET alerted_at = NULL
		WHERE org_id = $1 AND alerted_at IS NOT NULL
	`, orgID)
	return err
}

// GetScore returns the latest stored score for an org, or nil if none exists yet.
func (r *ConformanceScoreRepository) GetScore(ctx context.Context, orgID uuid.UUID) (*ConformanceScore, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT org_id, score, score_mfa, score_pkce, score_dpop, score_nis2,
		       components, threshold, alerted_at, computed_at
		FROM conformance_scores
		WHERE org_id = $1
	`, orgID)

	var s ConformanceScore
	var rawComp []byte
	if err := row.Scan(
		&s.OrgID, &s.Score, &s.ScoreMFA, &s.ScorePKCE, &s.ScoreDPoP, &s.ScoreNIS2,
		&rawComp, &s.Threshold, &s.AlertedAt, &s.ComputedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rawComp, &s.Components); err != nil {
		s.Components = map[string]any{}
	}
	return &s, nil
}

// SetThreshold updates the alert threshold for an org (idempotent — inserts row if missing).
func (r *ConformanceScoreRepository) SetThreshold(ctx context.Context, orgID uuid.UUID, threshold int) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO conformance_scores (org_id, score, components, threshold)
		VALUES ($1, 0, '{}', $2)
		ON CONFLICT (org_id) DO UPDATE SET threshold = EXCLUDED.threshold
	`, orgID, threshold)
	return err
}

// ConformanceScoreHistoryPoint is one time-series entry.
type ConformanceScoreHistoryPoint struct {
	Score      int            `json:"score"`
	Components map[string]any `json:"components,omitempty"`
	ComputedAt time.Time      `json:"computed_at"`
}

// ListHistory returns up to `limit` historical score points for an org, newest first.
func (r *ConformanceScoreRepository) ListHistory(
	ctx context.Context,
	orgID uuid.UUID,
	limit int,
) ([]ConformanceScoreHistoryPoint, error) {
	if limit <= 0 || limit > 500 {
		limit = 288 // 24 h at 5-min intervals
	}
	rows, err := r.pool.Query(ctx, `
		SELECT score, components, computed_at
		FROM conformance_score_history
		WHERE org_id = $1
		ORDER BY computed_at DESC
		LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ConformanceScoreHistoryPoint
	for rows.Next() {
		var p ConformanceScoreHistoryPoint
		var rawComp []byte
		if err := rows.Scan(&p.Score, &rawComp, &p.ComputedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rawComp, &p.Components)
		out = append(out, p)
	}
	return out, rows.Err()
}

// AppendHistory inserts one point to the score history log.
func (r *ConformanceScoreRepository) AppendHistory(ctx context.Context, in ConformanceScoreInput) error {
	comp, err := json.Marshal(in.Components)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO conformance_score_history (org_id, score, components)
		VALUES ($1, $2, $3)
	`, in.OrgID, in.Score, comp)
	return err
}

// ── Public score token ────────────────────────────────────────────────────────

const publicTokenPrefix = "clv_pub_"

// GeneratePublicScoreToken creates a new raw public-score token (shown once).
// Stores only the SHA-256 hash and a short display prefix.
// Returns (rawToken, err).
func (r *ConformanceScoreRepository) GeneratePublicScoreToken(ctx context.Context, orgID uuid.UUID) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := publicTokenPrefix + base64.RawURLEncoding.EncodeToString(b)

	// Display prefix: first 8 chars after the "clv_pub_" namespace.
	displayPrefix := strings.TrimPrefix(raw, publicTokenPrefix)
	if len(displayPrefix) > 8 {
		displayPrefix = displayPrefix[:8]
	}

	h := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(h[:])

	_, err := r.pool.Exec(ctx, `
		INSERT INTO conformance_scores (org_id, score, components, public_score_token_hash, public_score_token_prefix)
		VALUES ($1, 0, '{}', $2, $3)
		ON CONFLICT (org_id) DO UPDATE
		    SET public_score_token_hash   = EXCLUDED.public_score_token_hash,
		        public_score_token_prefix = EXCLUDED.public_score_token_prefix
	`, orgID, hash, displayPrefix)
	if err != nil {
		return "", err
	}
	return raw, nil
}

// RevokePublicScoreToken clears the stored token hash, disabling public access.
func (r *ConformanceScoreRepository) RevokePublicScoreToken(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE conformance_scores
		SET public_score_token_hash = NULL, public_score_token_prefix = NULL
		WHERE org_id = $1
	`, orgID)
	return err
}

// VerifyPublicScoreToken checks a raw token against the stored hash.
// Returns the orgID whose token matched, or an error.
func (r *ConformanceScoreRepository) VerifyPublicScoreToken(ctx context.Context, orgID uuid.UUID, rawToken string) error {
	if !strings.HasPrefix(rawToken, publicTokenPrefix) {
		return errInvalidPublicToken
	}
	h := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(h[:])

	var stored string
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(public_score_token_hash, '')
		FROM conformance_scores
		WHERE org_id = $1
	`, orgID).Scan(&stored)
	if err != nil || stored == "" {
		return errInvalidPublicToken
	}
	// Constant-time comparison to prevent timing attacks.
	if !secureEqual(hash, stored) {
		return errInvalidPublicToken
	}
	return nil
}

// errInvalidPublicToken is returned for bad/missing/revoked public score tokens.
var errInvalidPublicToken = &publicTokenError{}

type publicTokenError struct{}

func (*publicTokenError) Error() string { return "invalid or revoked public score token" }

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// PublicScore is the public-facing subset of the conformance score.
// It intentionally omits internal details (threshold, alert state, raw components).
type PublicScore struct {
	OrgID            uuid.UUID `json:"org_id"`
	Score            int       `json:"score"`
	Level            string    `json:"level"`
	MFAAdoptionPct   float64   `json:"mfa_adoption_pct"`
	PasskeyPct       float64   `json:"passkey_pct"`
	PolicyCompliance float64   `json:"policy_compliance_pct"`
	ComputedAt       time.Time `json:"computed_at"`
}

// GetPublicScore returns the public score subset for an org, computing passkey %
// directly from the database. Returns nil if no score has been computed yet.
func (r *ConformanceScoreRepository) GetPublicScore(ctx context.Context, orgID uuid.UUID) (*PublicScore, error) {
	s, err := r.GetScore(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Extract MFA adoption % from stored components.
	mfaPct := 0.0
	if comp, ok := s.Components["mfa_adoption"].(map[string]any); ok {
		if v, ok := comp["pct"].(float64); ok {
			mfaPct = v
		}
	}

	// Extract NIS2 policy compliance % from stored components.
	policyPct := 0.0
	if comp, ok := s.Components["nis2_policies"].(map[string]any); ok {
		maxScore := 0.0
		gotScore := 0.0
		if v, ok := comp["max"].(float64); ok {
			maxScore = v
		}
		if v, ok := comp["score"].(float64); ok {
			gotScore = v
		}
		if maxScore > 0 {
			policyPct = round1pub(gotScore / maxScore * 100)
		}
	}

	// Passkey % — computed live: users with ≥1 WebAuthn credential / total active users.
	passkeyPct := 0.0
	var totalUsers, passkeyUsers int
	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE org_id = $1 AND is_active = TRUE`, orgID).Scan(&totalUsers)
	_ = r.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT mc.user_id)
		FROM mfa_credentials mc
		JOIN users u ON u.id = mc.user_id
		WHERE u.org_id = $1 AND u.is_active = TRUE AND mc.type = 'webauthn'
	`, orgID).Scan(&passkeyUsers)
	if totalUsers > 0 {
		passkeyPct = round1pub(float64(passkeyUsers) / float64(totalUsers) * 100)
	}

	return &PublicScore{
		OrgID:            orgID,
		Score:            s.Score,
		Level:            publicScoreLevel(s.Score),
		MFAAdoptionPct:   mfaPct,
		PasskeyPct:       passkeyPct,
		PolicyCompliance: policyPct,
		ComputedAt:       s.ComputedAt,
	}, nil
}

// GetPublicTokenPrefix returns the display prefix of the current public score token,
// or ("", nil) if no token has been configured yet.
func (r *ConformanceScoreRepository) GetPublicTokenPrefix(ctx context.Context, orgID uuid.UUID) (string, error) {
	var prefix *string
	err := r.pool.QueryRow(ctx, `
		SELECT public_score_token_prefix FROM conformance_scores WHERE org_id = $1
	`, orgID).Scan(&prefix)
	if err != nil {
		return "", nil // row not found == no token
	}
	if prefix == nil {
		return "", nil
	}
	return *prefix, nil
}

func publicScoreLevel(s int) string {
	switch {
	case s >= 90:
		return "excellent"
	case s >= 70:
		return "good"
	case s >= 50:
		return "fair"
	case s >= 30:
		return "poor"
	default:
		return "critical"
	}
}

func round1pub(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
