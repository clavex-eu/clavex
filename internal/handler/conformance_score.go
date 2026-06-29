package handler

// ConformanceScoreHandler exposes the continuous assurance score for an org.
//
// Endpoints (scoped under /api/v1/organizations/:org_id/compliance):
//
//	GET  /score         — latest pre-computed score + component breakdown
//	GET  /score/history — time-series score history (last 288 points = 24 h at 5-min intervals)
//	PATCH /score/config — update alert threshold

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// ConformanceScoreHandler implements GET /compliance/score and related endpoints.
type ConformanceScoreHandler struct {
	repo *repository.ConformanceScoreRepository
}

// NewConformanceScoreHandler creates a handler backed by the given database pool.
func NewConformanceScoreHandler(repo *repository.ConformanceScoreRepository) *ConformanceScoreHandler {
	return &ConformanceScoreHandler{repo: repo}
}

// scoreResponse is the JSON shape returned by GET /compliance/score.
type scoreResponse struct {
	OrgID          uuid.UUID      `json:"org_id"`
	Score          int            `json:"score"`
	Level          string         `json:"level"`           // critical|poor|fair|good|excellent
	BelowThreshold bool           `json:"below_threshold"`
	Threshold      int            `json:"threshold"`
	Components     map[string]any `json:"components"`
	ComputedAt     string         `json:"computed_at"`
}

func scoreLevel(s int) string {
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

// GetScore returns the latest pre-computed conformance score for an org.
//
//	GET /api/v1/organizations/:org_id/compliance/score
func (h *ConformanceScoreHandler) GetScore(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	s, err := h.repo.GetScore(c.Request().Context(), orgID)
	if err != nil {
		// No score computed yet (worker hasn't run once).
		return c.JSON(http.StatusOK, map[string]any{
			"org_id":  orgID,
			"score":   nil,
			"message": "Score not yet computed — the worker runs every 5 minutes",
		})
	}

	return c.JSON(http.StatusOK, scoreResponse{
		OrgID:          s.OrgID,
		Score:          s.Score,
		Level:          scoreLevel(s.Score),
		BelowThreshold: s.Score < s.Threshold,
		Threshold:      s.Threshold,
		Components:     s.Components,
		ComputedAt:     s.ComputedAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// GetScoreHistory returns a time-series of score snapshots for an org.
//
//	GET /api/v1/organizations/:org_id/compliance/score/history?limit=288
func (h *ConformanceScoreHandler) GetScoreHistory(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	limit := 288
	if q := c.QueryParam("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}

	points, err := h.repo.ListHistory(c.Request().Context(), orgID, limit)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load history")
	}
	if points == nil {
		points = []repository.ConformanceScoreHistoryPoint{}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"org_id": orgID,
		"points": points,
		"count":  len(points),
	})
}

// PatchConfig updates the alert threshold for an org.
//
//	PATCH /api/v1/organizations/:org_id/compliance/score/config
//
// Body: { "threshold": 80 }
func (h *ConformanceScoreHandler) PatchConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	var body struct {
		Threshold *int `json:"threshold"`
	}
	if err := c.Bind(&body); err != nil || body.Threshold == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "threshold is required")
	}
	if *body.Threshold < 0 || *body.Threshold > 100 {
		return echo.NewHTTPError(http.StatusBadRequest, "threshold must be between 0 and 100")
	}

	if err := h.repo.SetThreshold(c.Request().Context(), orgID, *body.Threshold); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to update threshold")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"org_id":    orgID,
		"threshold": *body.Threshold,
	})
}

// ── Public score (ISV embedding) ─────────────────────────────────────────────

// GetPublicScore handles GET /api/v1/organizations/:org_id/compliance/score/public
//
// Authentication: Bearer <clv_pub_...> token in the Authorization header, issued
// by RotatePublicToken. No org-admin JWT is required — this endpoint is designed
// to be called from the ISV's own product to display their security posture to
// end customers ("powered by Clavex, 98% compliance").
//
// Returns a safe, curated subset of the score — no internal thresholds, alert
// state, or raw component details are exposed.
func (h *ConformanceScoreHandler) GetPublicScore(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	// Extract and verify the public-score Bearer token.
	authHeader := c.Request().Header.Get("Authorization")
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	if rawToken == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing Authorization header")
	}

	ctx := c.Request().Context()
	if err := h.repo.VerifyPublicScoreToken(ctx, orgID, rawToken); err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid or revoked public score token")
	}

	ps, err := h.repo.GetPublicScore(ctx, orgID)
	if err != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"org_id":  orgID,
			"score":   nil,
			"message": "Score not yet computed — the worker runs every 5 minutes",
		})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"org_id":               ps.OrgID,
		"score":                ps.Score,
		"level":                ps.Level,
		"mfa_adoption_pct":     ps.MFAAdoptionPct,
		"passkey_pct":          ps.PasskeyPct,
		"policy_compliance_pct": ps.PolicyCompliance,
		"computed_at":          ps.ComputedAt.UTC().Format("2006-01-02T15:04:05Z"),
		"powered_by":           "Clavex",
	})
}

// RotatePublicToken handles POST /api/v1/organizations/:org_id/compliance/score/public-token
//
// Generates a new public-score Bearer token. The previous token is immediately
// invalidated. The raw token is returned once — store it securely; Clavex stores
// only the SHA-256 hash.
//
// Requires: resource permission "compliance" (standard admin JWT).
func (h *ConformanceScoreHandler) RotatePublicToken(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	ctx := c.Request().Context()
	rawToken, err := h.repo.GeneratePublicScoreToken(ctx, orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate token")
	}

	// Display prefix for identification (shown again on GET).
	prefix, _ := h.repo.GetPublicTokenPrefix(ctx, orgID)

	return c.JSON(http.StatusCreated, map[string]any{
		"org_id": orgID,
		"token":  rawToken,
		"prefix": prefix,
		"note":   "This token is shown once. Store it securely — Clavex keeps only the hash.",
		"usage":  "Authorization: Bearer " + rawToken,
	})
}

// RevokePublicToken handles DELETE /api/v1/organizations/:org_id/compliance/score/public-token
//
// Immediately invalidates the public-score token. The public endpoint returns 401
// until a new token is issued via RotatePublicToken.
func (h *ConformanceScoreHandler) RevokePublicToken(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	if err := h.repo.RevokePublicScoreToken(c.Request().Context(), orgID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to revoke token")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"org_id":  orgID,
		"revoked": true,
	})
}

// GetPublicTokenInfo handles GET /api/v1/organizations/:org_id/compliance/score/public-token
//
// Returns the display prefix of the active public-score token (not the token itself).
func (h *ConformanceScoreHandler) GetPublicTokenInfo(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	prefix, err := h.repo.GetPublicTokenPrefix(c.Request().Context(), orgID)
	if err != nil || prefix == "" {
		return c.JSON(http.StatusOK, map[string]any{
			"org_id":   orgID,
			"active":   false,
			"prefix":   nil,
		})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"org_id":   orgID,
		"active":   true,
		"prefix":   "clv_pub_" + prefix + "...",
	})
}
