package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// DeviceTrustHandler exposes device management endpoints for users.
type DeviceTrustHandler struct {
	devices *repository.TrustedDeviceRepository
}

func NewDeviceTrustHandler(pool *pgxpool.Pool) *DeviceTrustHandler {
	return &DeviceTrustHandler{devices: repository.NewTrustedDeviceRepository(pool)}
}

// ListDevices returns all trusted devices for the authenticated user.
// GET /api/v1/organizations/:org_id/users/:user_id/trusted-devices
func (h *DeviceTrustHandler) ListDevices(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}
	devs, err := h.devices.ListByUser(c.Request().Context(), orgID, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, devs)
}

// RevokeDevice removes a trusted device.
// DELETE /api/v1/organizations/:org_id/users/:user_id/trusted-devices/:device_id
func (h *DeviceTrustHandler) RevokeDevice(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}
	deviceID, err := uuid.Parse(c.Param("device_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid device_id")
	}
	if err := h.devices.Revoke(c.Request().Context(), orgID, userID, deviceID); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "device not found")
	}
	return c.NoContent(http.StatusNoContent)
}

// RevokeAllDevices removes all trusted devices for a user.
// DELETE /api/v1/organizations/:org_id/users/:user_id/trusted-devices
func (h *DeviceTrustHandler) RevokeAllDevices(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}
	if err := h.devices.RevokeAllForUser(c.Request().Context(), orgID, userID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
