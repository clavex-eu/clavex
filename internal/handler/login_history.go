package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// LoginHistoryHandler exposes the login history (event log) and per-org
// rate limit configuration via the admin API.
//
//	GET  /api/v1/organizations/:org_id/login-history
//	GET  /api/v1/organizations/:org_id/users/:user_id/login-history
//	GET  /api/v1/organizations/:org_id/rate-limits
//	PUT  /api/v1/organizations/:org_id/rate-limits
type LoginHistoryHandler struct {
	repo *repository.LoginHistoryRepository
}

func NewLoginHistoryHandler(pool *pgxpool.Pool) *LoginHistoryHandler {
	return &LoginHistoryHandler{repo: repository.NewLoginHistoryRepository(pool)}
}

// ListOrgLoginHistory handles GET /api/v1/organizations/:org_id/login-history
// Returns a cursor-paginated list of all login events for the organisation.
func (h *LoginHistoryHandler) ListOrgLoginHistory(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	p := h.parseHistoryParams(c)
	p.OrgID = &orgID

	page, err := h.repo.ListLoginHistory(c.Request().Context(), p)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, page)
}

// ListUserLoginHistory handles GET /api/v1/organizations/:org_id/users/:user_id/login-history
// Returns the login history for a single user. Used for profile security pages and DSAR.
func (h *LoginHistoryHandler) ListUserLoginHistory(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	p := h.parseHistoryParams(c)
	p.OrgID = &orgID
	p.UserID = &userID

	page, err := h.repo.ListLoginHistory(c.Request().Context(), p)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, page)
}

// GetAnomalySignals handles GET /api/v1/organizations/:org_id/users/:user_id/anomaly-signals
// Returns the current risk signals for the given user (for admin dashboards).
func (h *LoginHistoryHandler) GetAnomalySignals(c echo.Context) error {
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	signals, err := h.repo.GetAnomalySignals(c.Request().Context(), userID, "", "")
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, signals)
}

// ── Rate limit config ─────────────────────────────────────────────────────────

// GetRateLimits handles GET /api/v1/organizations/:org_id/rate-limits
func (h *LoginHistoryHandler) GetRateLimits(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	rl, err := h.repo.GetOrgRateLimits(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, rl)
}

type updateRateLimitsRequest struct {
	LoginPerIPPerMin     int `json:"login_per_ip_per_min"     validate:"min=1,max=600"`
	TokenPerClientPerMin int `json:"token_per_client_per_min" validate:"min=1,max=3600"`
	GlobalPerIPPerMin    int `json:"global_per_ip_per_min"    validate:"min=1,max=3600"`
	// EndpointLimits is a map of endpoint path key → requests-per-minute limit.
	// Example: {"/elevate": 3, "/oid4vci/offers": 10}
	// Omit or set to null to clear all per-endpoint limits.
	EndpointLimits map[string]int `json:"endpoint_limits"`
}

// UpdateRateLimits handles PUT /api/v1/organizations/:org_id/rate-limits
func (h *LoginHistoryHandler) UpdateRateLimits(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req updateRateLimitsRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.EndpointLimits == nil {
		req.EndpointLimits = map[string]int{}
	}
	rl, err := h.repo.UpsertOrgRateLimits(
		c.Request().Context(), orgID,
		req.LoginPerIPPerMin, req.TokenPerClientPerMin, req.GlobalPerIPPerMin,
		req.EndpointLimits,
	)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, rl)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *LoginHistoryHandler) parseHistoryParams(c echo.Context) repository.ListLoginHistoryParams {
	p := repository.ListLoginHistoryParams{}

	if v := c.QueryParam("status"); v != "" {
		p.Status = v
	}
	if v := c.QueryParam("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			p.Since = t
		}
	}
	if v := c.QueryParam("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			p.Until = t
		}
	}
	if v := c.QueryParam("after"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			p.After = n
		}
	}
	if v := c.QueryParam("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p.Limit = n
		}
	}
	return p
}

// compile-time import checks
var _ = uuid.Nil
var _ = models.MaxPageSize
