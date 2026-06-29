package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// IPAllowlistHandler manages per-org IP allowlists.
type IPAllowlistHandler struct {
	allowlist *repository.IPAllowlistRepository
}

func NewIPAllowlistHandler(pool *pgxpool.Pool) *IPAllowlistHandler {
	return &IPAllowlistHandler{allowlist: repository.NewIPAllowlistRepository(pool)}
}

// List returns all CIDR entries for an org.
// GET /api/v1/organizations/:org_id/ip-allowlist
func (h *IPAllowlistHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	entries, err := h.allowlist.List(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, entries)
}

// Add creates a new CIDR entry for an org.
// POST /api/v1/organizations/:org_id/ip-allowlist
func (h *IPAllowlistHandler) Add(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var body struct {
		CIDR  string `json:"cidr"`
		Label string `json:"label"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if body.CIDR == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "cidr is required")
	}
	// Grab caller's user ID from JWT for audit
	var createdBy *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, err := uuid.Parse(claims.Subject); err == nil {
			createdBy = &id
		}
	}
	entry, err := h.allowlist.Add(c.Request().Context(), orgID, body.CIDR, body.Label, createdBy)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return c.JSON(http.StatusCreated, entry)
}

// Delete removes a CIDR entry.
// DELETE /api/v1/organizations/:org_id/ip-allowlist/:entry_id
func (h *IPAllowlistHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	entryID, err := uuidParam(c, "entry_id")
	if err != nil {
		return err
	}
	if err := h.allowlist.Delete(c.Request().Context(), entryID, orgID); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}
	return c.NoContent(http.StatusNoContent)
}
