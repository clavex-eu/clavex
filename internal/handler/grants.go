package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// GrantHandler exposes the RAR (RFC 9396) consent grant management API.
// All endpoints require admin JWT with org access (RequireOrgAccess middleware).
type GrantHandler struct {
	repo *repository.RARGrantRepository
}

func NewGrantHandler(pool *pgxpool.Pool) *GrantHandler {
	return &GrantHandler{repo: repository.NewRARGrantRepository(pool)}
}

// GET /api/v1/organizations/:org_id/grants
// Returns all grants (active and revoked) for the org, newest first.
// Supports ?user_id=<uuid> to filter by a single user.
func (h *GrantHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	if userIDStr := c.QueryParam("user_id"); userIDStr != "" {
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
		}
		grants, err := h.repo.ListByUser(c.Request().Context(), orgID, userID)
		if err != nil {
			return echo.ErrInternalServerError
		}
		return c.JSON(http.StatusOK, grants)
	}

	grants, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, grants)
}

// GET /api/v1/organizations/:org_id/grants/:grant_id
func (h *GrantHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	grantID, err := uuidParam(c, "grant_id")
	if err != nil {
		return err
	}
	grant, err := h.repo.GetByID(c.Request().Context(), orgID, grantID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if grant == nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, grant)
}

// DELETE /api/v1/organizations/:org_id/grants/:grant_id
// Granular revocation of a single authorization_details grant (PSD2 §66 requirement).
func (h *GrantHandler) Revoke(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	grantID, err := uuidParam(c, "grant_id")
	if err != nil {
		return err
	}
	if err := h.repo.Revoke(c.Request().Context(), orgID, grantID); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}
	return c.NoContent(http.StatusNoContent)
}

// DELETE /api/v1/organizations/:org_id/users/:id/grants
// Revokes all active grants for a user (called on user deactivation or deletion).
func (h *GrantHandler) RevokeAll(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.repo.RevokeAllByUser(c.Request().Context(), orgID, userID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
