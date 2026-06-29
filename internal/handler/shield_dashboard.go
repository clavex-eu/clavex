package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ShieldDashboardHandler exposes the Clavex Shield threat-intelligence
// aggregations for the ops security dashboard.
//
//	GET /api/v1/organizations/:org_id/shield-dashboard
type ShieldDashboardHandler struct {
	history *repository.LoginHistoryRepository
	// enabled reflects whether Shield enrichment is active (AbuseIPDB key set).
	enabled bool
}

// NewShieldDashboardHandler creates a new ShieldDashboardHandler. enabled should
// be true when Shield threat-intel enrichment is configured (AbuseIPDB key set).
func NewShieldDashboardHandler(pool *pgxpool.Pool, enabled bool) *ShieldDashboardHandler {
	return &ShieldDashboardHandler{history: repository.NewLoginHistoryRepository(pool), enabled: enabled}
}

// Dashboard handles GET /api/v1/organizations/:org_id/shield-dashboard.
// Returns the aggregated threat-intelligence view scoped to the org:
//   - Blocked IPs in the last hour with AbuseIPDB confidence score
//   - Hourly trend of Tor exit-node logins (last 7 days)
//   - Top 10 malicious IPs this week
//   - Week-over-week comparison of blocked login attempts
func (h *ShieldDashboardHandler) Dashboard(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	data, err := h.history.GetShieldDashboard(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	data.Enabled = h.enabled
	return c.JSON(http.StatusOK, data)
}
