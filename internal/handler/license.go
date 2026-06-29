package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/license"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// LicenseHandler exposes the current license state to superadmin callers.
type LicenseHandler struct {
	checker *license.Checker
	pool    *pgxpool.Pool
}

// NewLicenseHandler creates a LicenseHandler.
func NewLicenseHandler(checker *license.Checker) *LicenseHandler {
	return &LicenseHandler{checker: checker}
}

// WithPool attaches a DB pool so the handler can persist uploaded tokens.
func (h *LicenseHandler) WithPool(pool *pgxpool.Pool) *LicenseHandler {
	h.pool = pool
	return h
}

// Get returns the current cached license state.
//
//	GET /api/v1/superadmin/license
func (h *LicenseHandler) Get(c echo.Context) error {
	return c.JSON(http.StatusOK, h.checker.State())
}

// Upload validates and hot-reloads a new license JWT at runtime.
//
//	PUT /api/v1/superadmin/license
//	Body: {"token": "<compact JWT>"}
//
// On success the license is persisted to the installation table so it survives
// restarts. The response body is the new license State.
func (h *LicenseHandler) Upload(c echo.Context) error {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.Bind(&req); err != nil || req.Token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "token field is required")
	}

	ctx := c.Request().Context()
	if err := h.checker.Reload(ctx, req.Token); err != nil {
		return c.JSON(http.StatusUnprocessableEntity, map[string]string{
			"error": err.Error(),
		})
	}

	// Persist so the license survives pod restarts.
	if h.pool != nil {
		if err := license.PersistToken(ctx, h.pool, req.Token); err != nil {
			c.Logger().Errorf("license: persist token to DB: %v", err)
			// Non-fatal — the in-memory reload already succeeded.
		}
	}

	return c.JSON(http.StatusOK, h.checker.State())
}

// InstallationID returns the installation binding identifier that customers
// paste into the Clavex license portal to bind a license to their installation.
//
// This MUST be the same value the license checker compares the JWT `sub` claim
// against, i.e. LicenseBindingID (the stable installation_uuid) — NOT the
// privacy-preserving feed id from license.InstallationID(). Returning the latter
// would make every issued license fail the binding check and silently revert the
// installation to the community tier.
//
//	GET /api/v1/superadmin/license/installation-id
func (h *LicenseHandler) InstallationID(c echo.Context) error {
	if h.pool == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "database not available")
	}
	id, err := license.LicenseBindingID(c.Request().Context(), h.pool)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to read installation ID")
	}
	return c.JSON(http.StatusOK, map[string]string{"installation_id": id})
}
