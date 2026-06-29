package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// UsageHandler serves tenant usage analytics for the Cloud billing dashboard
// and the enterprise Security Posture report.
type UsageHandler struct {
	usage     *repository.UsageRepository
	analytics *repository.AnalyticsRepository
	orgs      *repository.OrgRepository
}

// NewUsageHandler creates a UsageHandler.
func NewUsageHandler(pool *pgxpool.Pool) *UsageHandler {
	return &UsageHandler{
		usage:     repository.NewUsageRepository(pool),
		analytics: repository.NewAnalyticsRepository(pool),
		orgs:      repository.NewOrgRepository(pool),
	}
}

// GetOrgUsage handles GET /api/v1/organizations/:id/usage.
//
// Returns usage analytics for the given org over the trailing 30-day window:
//   - MAU / DAU (Monthly / Daily Active Users)
//   - Total / success / failure login counts
//   - Login breakdown by auth_method
//   - Top 10 client_ids by login volume
//   - New users provisioned this month
//
// Access: org admins (own org) and superadmins (any org).
func (h *UsageHandler) GetOrgUsage(c echo.Context) error {
	ctx := c.Request().Context()
	claims := middleware.GetClaims(c)

	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	// Org admins may only query their own org.
	if !claims.IsSuperAdmin && claims.OrgID != orgID.String() {
		return echo.NewHTTPError(http.StatusForbidden, "access denied")
	}

	// Verify the org exists.
	if _, err := h.orgs.GetByID(ctx, orgID); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	usage, err := h.usage.GetOrgUsage(ctx, orgID)
	if err != nil {
		c.Logger().Errorf("usage: GetOrgUsage org=%s: %v", orgID, err)
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, usage)
}

// GetOrgAnalytics handles GET /api/v1/organizations/:org_id/analytics.
//
// Returns richer per-org analytics including DAU/new-member time series,
// D7/D30 retention cohort metrics, and pending invite count.
// Accessible to org admins (own org) and superadmins.
func (h *UsageHandler) GetOrgAnalytics(c echo.Context) error {
	ctx := c.Request().Context()
	claims := middleware.GetClaims(c)

	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	if !claims.IsSuperAdmin && claims.OrgID != orgID.String() {
		return echo.NewHTTPError(http.StatusForbidden, "access denied")
	}

	analytics, err := h.analytics.GetOrgAnalytics(ctx, orgID)
	if err != nil {
		c.Logger().Errorf("analytics: GetOrgAnalytics org=%s: %v", orgID, err)
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, analytics)
}
