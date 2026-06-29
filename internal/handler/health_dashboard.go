package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// HealthDashboardHandler serves the superadmin installation health overview.
type HealthDashboardHandler struct {
	repo *repository.HealthDashboardRepository
}

func NewHealthDashboardHandler(pool *pgxpool.Pool) *HealthDashboardHandler {
	return &HealthDashboardHandler{
		repo: repository.NewHealthDashboardRepository(pool),
	}
}

// Get handles GET /api/v1/superadmin/health
// Returns a comprehensive health snapshot: per-org MAU/DAU, worker statuses,
// cross-org aggregates, and anomaly alerts.
func (h *HealthDashboardHandler) Get(c echo.Context) error {
	dash, err := h.repo.GetHealthDashboard(c.Request().Context())
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, dash)
}
