package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// CaptchaHandler manages per-org CAPTCHA settings via the admin API.
type CaptchaHandler struct {
	repo *repository.CaptchaRepository
}

func NewCaptchaHandler(pool *pgxpool.Pool) *CaptchaHandler {
	return &CaptchaHandler{repo: repository.NewCaptchaRepository(pool)}
}

// Get returns the CAPTCHA configuration for an org (secret_key is omitted from response).
func (h *CaptchaHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	claims := middleware.GetClaims(c)
	if !claims.IsSuperAdmin && claims.OrgID != orgID.String() {
		return echo.ErrForbidden
	}

	settings, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if settings == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"configured": false,
		})
	}
	// Never expose secret_key in the response.
	return c.JSON(http.StatusOK, map[string]interface{}{
		"configured": true,
		"provider":   settings.Provider,
		"site_key":   settings.SiteKey,
		"is_active":  settings.IsActive,
	})
}

// Put creates or replaces the CAPTCHA configuration for an org.
func (h *CaptchaHandler) Put(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	claims := middleware.GetClaims(c)
	if !claims.IsSuperAdmin && claims.OrgID != orgID.String() {
		return echo.ErrForbidden
	}

	var req struct {
		Provider  string `json:"provider"`
		SiteKey   string `json:"site_key"`
		SecretKey string `json:"secret_key"`
		IsActive  *bool  `json:"is_active"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Provider == "" {
		req.Provider = "turnstile"
	}
	if req.SiteKey == "" || req.SecretKey == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "site_key and secret_key are required")
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	s := &models.CaptchaSettings{
		OrgID:     orgID,
		Provider:  req.Provider,
		SiteKey:   req.SiteKey,
		SecretKey: req.SecretKey,
		IsActive:  isActive,
	}
	if err := h.repo.Upsert(c.Request().Context(), s); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"configured": true,
		"provider":   s.Provider,
		"site_key":   s.SiteKey,
		"is_active":  s.IsActive,
	})
}

// Delete removes the CAPTCHA configuration for an org.
func (h *CaptchaHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	claims := middleware.GetClaims(c)
	if !claims.IsSuperAdmin && claims.OrgID != orgID.String() {
		return echo.ErrForbidden
	}

	if err := h.repo.Delete(c.Request().Context(), orgID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
