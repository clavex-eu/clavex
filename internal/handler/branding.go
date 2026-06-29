package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

type BrandingHandler struct {
	repo *repository.BrandingRepository
}

func NewBrandingHandler(pool *pgxpool.Pool) *BrandingHandler {
	return &BrandingHandler{repo: repository.NewBrandingRepository(pool)}
}

// GET /api/v1/organizations/:org_id/branding
func (h *BrandingHandler) Get(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	b, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, b)
}

// PUT /api/v1/organizations/:org_id/branding
func (h *BrandingHandler) Put(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	var body models.OrgBranding
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	body.OrgID = orgID

	// Apply defaults for required fields
	if body.PrimaryColor == "" {
		body.PrimaryColor = "#4f46e5"
	}
	if body.BgColor == "" {
		body.BgColor = "#f9fafb"
	}
	if body.TextColor == "" {
		body.TextColor = "#111827"
	}
	if body.WelcomeTitle == "" {
		body.WelcomeTitle = "Sign in"
	}

	out, err := h.repo.Upsert(c.Request().Context(), &body)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, out)
}
