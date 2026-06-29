package handler

import (
	"crypto/subtle"
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// FleetHandler handles fleet-agent webhook ingestion and device listing.
//
// Routes:
//
//	POST /organizations/:org_id/fleet/ingest  — receive device-facts payload
//	GET  /organizations/:org_id/fleet/devices — list known devices (admin)
type FleetHandler struct {
	orgs    *repository.OrgRepository
	devices *repository.DeviceFactsRepository
}

// NewFleetHandler creates a new FleetHandler.
func NewFleetHandler(pool *pgxpool.Pool) *FleetHandler {
	return &FleetHandler{
		orgs:    repository.NewOrgRepository(pool),
		devices: repository.NewDeviceFactsRepository(pool),
	}
}

// fleetIngestRequest is the JSON body sent by fleet agents on each heartbeat.
type fleetIngestRequest struct {
	// DeviceID is a stable, agent-generated identifier for the device
	// (e.g. hardware UUID or hostname).
	DeviceID string `json:"device_id"`
	// UserID is the optional UUID of the authenticated user currently logged in
	// on the device. Omit or leave empty when no user session is active.
	UserID string `json:"user_id,omitempty"`
	// Platform is the OS/platform string (e.g. "windows", "macos", "linux").
	Platform string `json:"platform,omitempty"`
	// Facts is an arbitrary map of posture attributes. Keys are application-
	// defined strings; values must be JSON-serialisable primitives or objects.
	// Example: {"disk_encrypted": true, "os_version": "14.4", "antivirus": "up-to-date"}
	Facts map[string]interface{} `json:"facts"`
}

// Ingest handles POST /organizations/:org_id/fleet/ingest.
// Authentication: the caller must supply the org's fleet_ingest_secret in the
// X-Fleet-Token request header. The comparison is constant-time to prevent
// timing attacks.
func (h *FleetHandler) Ingest(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	// Authenticate the fleet agent via a per-org secret token.
	token := c.Request().Header.Get("X-Fleet-Token")
	if token == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing X-Fleet-Token header")
	}

	secret, err := h.orgs.GetFleetSecret(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	if secret == nil || *secret == "" {
		// Fleet ingestion not enabled for this org.
		return echo.NewHTTPError(http.StatusForbidden, "fleet ingestion not enabled for this organization")
	}

	// Constant-time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare([]byte(token), []byte(*secret)) != 1 {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid fleet token")
	}

	var req fleetIngestRequest
	if err := c.Bind(&req); err != nil || req.DeviceID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "device_id is required")
	}

	var userID *uuid.UUID
	if req.UserID != "" {
		if uid, err := uuid.Parse(req.UserID); err == nil {
			userID = &uid
		}
	}

	if err := h.devices.Upsert(c.Request().Context(), orgID, req.DeviceID, userID, req.Platform, req.Facts); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusAccepted, map[string]string{"status": "accepted"})
}

// ListDevices handles GET /organizations/:org_id/fleet/devices.
// Returns all known devices for the organization.
func (h *FleetHandler) ListDevices(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	userIDStr := c.QueryParam("user_id")
	if userIDStr != "" {
		uid, err := uuid.Parse(userIDStr)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
		}
		devices, err := h.devices.GetByUserID(c.Request().Context(), orgID, uid)
		if err != nil {
			return echo.ErrInternalServerError
		}
		return c.JSON(http.StatusOK, devices)
	}

	// Full list is not yet paginated — return 400 to encourage scoped queries.
	return echo.NewHTTPError(http.StatusBadRequest, "user_id query parameter is required")
}
