package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// AccountCenterHandler serves the Account Center configuration API.
//
// Public endpoint (no auth — consumed by the <ClavexAccountCenter /> React widget):
//
//	GET /:org_slug/account-center/config
//	  → returns the widget config + account_portal_url so the widget knows
//	    where to send the user for each section.
//
// Admin endpoints (org-admin JWT required):
//
//	GET /api/v1/organizations/:org_id/account-center
//	PUT /api/v1/organizations/:org_id/account-center
type AccountCenterHandler struct {
	repo *repository.AccountCenterRepository
	orgs *repository.OrgRepository
}

// NewAccountCenterHandler creates a handler backed by the given pool.
func NewAccountCenterHandler(pool *pgxpool.Pool) *AccountCenterHandler {
	return &AccountCenterHandler{
		repo: repository.NewAccountCenterRepository(pool),
		orgs: repository.NewOrgRepository(pool),
	}
}

// accountCenterResponse is the public response envelope that attaches the
// account portal URL so the widget knows where to navigate users.
type accountCenterResponse struct {
	*models.AccountCenterConfig
	AccountPortalURL string `json:"account_portal_url"`
}

// GetConfig is the public endpoint consumed by the <ClavexAccountCenter />
// React widget before the user is even logged in.
//
// GET /:org_slug/account-center/config
func (h *AccountCenterHandler) GetConfig(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	org, err := h.orgs.GetBySlug(c.Request().Context(), orgSlug)
	if err != nil || org == nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}
	cfg, err := h.repo.GetByOrg(c.Request().Context(), org.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, accountCenterResponse{
		AccountCenterConfig: cfg,
		AccountPortalURL:    "/" + orgSlug + "/account",
	})
}

// AdminGetConfig returns the saved config for org admins.
//
// GET /api/v1/organizations/:org_id/account-center
func (h *AccountCenterHandler) AdminGetConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	cfg, err := h.repo.GetByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, cfg)
}

// updateAccountCenterRequest uses pointer fields so callers can do a partial
// PATCH-style update: only supplied fields overwrite the current config.
type updateAccountCenterRequest struct {
	ShowProfile    *bool   `json:"show_profile"`
	ShowPassword   *bool   `json:"show_password"`
	ShowMFA        *bool   `json:"show_mfa"`
	ShowPasskeys   *bool   `json:"show_passkeys"`
	ShowSessions   *bool   `json:"show_sessions"`
	ShowActivity   *bool   `json:"show_activity"`
	ShowDataExport *bool   `json:"show_data_export"`
	PageTitle      *string `json:"page_title"`
}

// AdminUpdateConfig upserts the account center config for the org.
// Omitted boolean fields preserve their current values (partial update semantics).
//
// PUT /api/v1/organizations/:org_id/account-center
func (h *AccountCenterHandler) AdminUpdateConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req updateAccountCenterRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	// Load current config so omitted fields are preserved.
	current, err := h.repo.GetByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	if req.ShowProfile != nil    { current.ShowProfile    = *req.ShowProfile    }
	if req.ShowPassword != nil   { current.ShowPassword   = *req.ShowPassword   }
	if req.ShowMFA != nil        { current.ShowMFA        = *req.ShowMFA        }
	if req.ShowPasskeys != nil   { current.ShowPasskeys   = *req.ShowPasskeys   }
	if req.ShowSessions != nil   { current.ShowSessions   = *req.ShowSessions   }
	if req.ShowActivity != nil   { current.ShowActivity   = *req.ShowActivity   }
	if req.ShowDataExport != nil { current.ShowDataExport = *req.ShowDataExport }
	if req.PageTitle != nil      { current.PageTitle      = req.PageTitle       }

	updated, err := h.repo.Upsert(c.Request().Context(), current)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, updated)
}
