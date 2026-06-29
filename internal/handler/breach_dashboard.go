package handler

import (
	"net/http"
	"strconv"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// BreachDashboardHandler serves the breached-password security dashboard.
//
// GET /api/v1/organizations/:org_id/security/breached-passwords[?page=1&per_page=20]
//
// Response shape (FusionAuth-compatible aggregated report):
//
//	{
//	  "total_detected":        47,
//	  "category_breakdown": [
//	    { "category": "exact_match",     "count": 35 },
//	    { "category": "common_password", "count": 8  },
//	    { "category": "sub_address",     "count": 4  }
//	  ],
//	  "users_action_required": 3,
//	  "blocked_30d":           5,
//	  "warned_30d":            8,
//	  "force_reset_30d":       3,
//	  "users_at_risk": [...],
//	  "page": 1, "per_page": 20, "total_users": 3
//	}
type BreachDashboardHandler struct {
	repo *repository.BreachRepository
}

func NewBreachDashboardHandler(pool *pgxpool.Pool) *BreachDashboardHandler {
	return &BreachDashboardHandler{repo: repository.NewBreachRepository(pool)}
}

// GetDashboard returns the aggregated breach dashboard for an organisation.
func (h *BreachDashboardHandler) GetDashboard(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	// Pagination params: ?page=1&per_page=20
	page := 1
	perPage := 20
	if p := c.QueryParam("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if pp := c.QueryParam("per_page"); pp != "" {
		if v, err := strconv.Atoi(pp); err == nil && v > 0 && v <= 100 {
			perPage = v
		}
	}

	dash, err := h.repo.GetDashboard(c.Request().Context(), orgID, page, perPage)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("breach dashboard query failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load dashboard"})
	}

	return c.JSON(http.StatusOK, dash)
}
