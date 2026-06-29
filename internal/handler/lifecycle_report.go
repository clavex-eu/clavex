package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// LifecycleReportHandler serves the Object Lifecycle Management dashboard.
//
// It surfaces OIDC clients and groups with their last_used_at / last_activity_at
// timestamps and a staleness classification:
//   - "active"     — used within the last 30 days
//   - "unknown"    — used 31-90 days ago (monitor)
//   - "stale"      — not used in 90+ days (candidate for deprecation)
//   - "never_used" — client has never obtained a token
//   - "empty"      — group has no members
//
// Endpoint: GET /api/v1/organizations/:org_id/lifecycle-report
type LifecycleReportHandler struct {
	repo *repository.LifecycleReportRepository
}

func NewLifecycleReportHandler(pool *pgxpool.Pool) *LifecycleReportHandler {
	return &LifecycleReportHandler{repo: repository.NewLifecycleReportRepository(pool)}
}

// Get handles GET /api/v1/organizations/:org_id/lifecycle-report.
func (h *LifecycleReportHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	report, err := h.repo.GetLifecycleReport(c.Request().Context(), orgID)
	if err != nil {
		c.Logger().Errorf("lifecycle: GetLifecycleReport org=%s: %v", orgID, err)
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, report)
}
