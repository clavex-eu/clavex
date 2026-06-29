package handler

// GDPR Art.5(1)(e) per-org data retention policy management.
//
// Routes:
//   GET    /api/v1/organizations/:org_id/gdpr/retention-policy
//   PUT    /api/v1/organizations/:org_id/gdpr/retention-policy
//   DELETE /api/v1/organizations/:org_id/gdpr/retention-policy

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/labstack/echo/v4"
)

// GDPRRetentionHandler manages per-org GDPR retention policies.
type GDPRRetentionHandler struct {
	repo *repository.GDPRRetentionRepository
}

// NewGDPRRetentionHandler creates a GDPRRetentionHandler.
func NewGDPRRetentionHandler(repo *repository.GDPRRetentionRepository) *GDPRRetentionHandler {
	return &GDPRRetentionHandler{repo: repo}
}

// GetRetentionPolicy returns the GDPR retention policy for an org.
//
//	GET /api/v1/organizations/:org_id/gdpr/retention-policy
func (h *GDPRRetentionHandler) GetRetentionPolicy(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	p, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if p == nil {
		return c.JSON(http.StatusOK, map[string]any{
			"org_id":            orgID,
			"enabled":           false,
			"retention_days":    730,
			"activity_field":    "last_login_at",
			"exempt_role_names": []string{},
		})
	}
	return c.JSON(http.StatusOK, p)
}

// UpsertRetentionPolicy creates or replaces the GDPR retention policy for an org.
//
//	PUT /api/v1/organizations/:org_id/gdpr/retention-policy
//
// Body:
//
//	{
//	  "enabled":           true,
//	  "retention_days":    365,
//	  "activity_field":    "last_login_at",  // or "updated_at"
//	  "exempt_role_names": ["superadmin"]
//	}
func (h *GDPRRetentionHandler) UpsertRetentionPolicy(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var body struct {
		Enabled         bool     `json:"enabled"`
		RetentionDays   int      `json:"retention_days"`
		ActivityField   string   `json:"activity_field"`
		ExemptRoleNames []string `json:"exempt_role_names"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if body.ActivityField != "" && body.ActivityField != "last_login_at" && body.ActivityField != "updated_at" {
		return echo.NewHTTPError(http.StatusBadRequest, "activity_field must be 'last_login_at' or 'updated_at'")
	}
	if body.RetentionDays < 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "retention_days must be a positive integer")
	}

	p := repository.GDPRRetentionPolicy{
		OrgID:           orgID,
		Enabled:         body.Enabled,
		RetentionDays:   body.RetentionDays,
		ActivityField:   body.ActivityField,
		ExemptRoleNames: body.ExemptRoleNames,
	}
	if err := h.repo.Upsert(c.Request().Context(), p); err != nil {
		return echo.ErrInternalServerError
	}
	saved, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil || saved == nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, saved)
}

// DeleteRetentionPolicy removes the GDPR retention policy for an org.
//
//	DELETE /api/v1/organizations/:org_id/gdpr/retention-policy
func (h *GDPRRetentionHandler) DeleteRetentionPolicy(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.Request().Context(), orgID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
