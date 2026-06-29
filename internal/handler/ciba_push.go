package handler

// CIBA push device token management endpoints.
//
// Mobile apps register their APNs / FCM push tokens so that Clavex can
// deliver native push notifications when a backchannel authentication
// request (CIBA) is created for the user.
//
// Routes:
//   Admin API (requires sessions resource permission):
//     GET    /api/v1/organizations/:org_id/ciba/device-tokens
//     POST   /api/v1/organizations/:org_id/ciba/device-tokens
//     DELETE /api/v1/organizations/:org_id/ciba/device-tokens/:token_id
//
//   Self-service API (Bearer access token, user registers own device):
//     POST   /{org}/push/device-token
//     DELETE /{org}/push/device-token

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// ── Admin endpoints ───────────────────────────────────────────────────────────

// CIBAListDeviceTokens lists all push device tokens registered for an org.
//
//	GET /api/v1/organizations/:org_id/ciba/device-tokens?user_id=<uuid>
func (h *OIDCHandler) CIBAListDeviceTokens(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	// Optional filter by user_id.
	if userIDStr := c.QueryParam("user_id"); userIDStr != "" {
		userID, parseErr := uuid.Parse(userIDStr)
		if parseErr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "user_id must be a valid UUID")
		}
		tokens, listErr := h.cibaPushTokens.ListForUser(ctx, orgID, userID)
		if listErr != nil {
			return echo.ErrInternalServerError
		}
		if tokens == nil {
			tokens = []*repository.CIBADeviceToken{}
		}
		return c.JSON(http.StatusOK, tokens)
	}

	tokens, err := h.cibaPushTokens.ListForOrg(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if tokens == nil {
		tokens = []*repository.CIBADeviceToken{}
	}
	return c.JSON(http.StatusOK, tokens)
}

// CIBARegisterDeviceToken registers a push device token for a user (admin).
//
//	POST /api/v1/organizations/:org_id/ciba/device-tokens
//	{"user_id": "<uuid>", "platform": "apns"|"fcm", "device_token": "<token>"}
func (h *OIDCHandler) CIBARegisterDeviceToken(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	var body struct {
		UserID      string `json:"user_id"      validate:"required"`
		Platform    string `json:"platform"     validate:"required"`
		DeviceToken string `json:"device_token" validate:"required"`
	}
	if err := bindAndValidate(c, &body); err != nil {
		return err
	}
	userID, parseErr := uuid.Parse(body.UserID)
	if parseErr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "user_id must be a valid UUID")
	}
	if body.Platform != "apns" && body.Platform != "fcm" {
		return echo.NewHTTPError(http.StatusBadRequest, "platform must be \"apns\" or \"fcm\"")
	}

	dt, err := h.cibaPushTokens.Register(c.Request().Context(), orgID, userID, body.Platform, body.DeviceToken)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, dt)
}

// CIBADeleteDeviceToken removes a push device token (admin).
//
//	DELETE /api/v1/organizations/:org_id/ciba/device-tokens/:token_id
func (h *OIDCHandler) CIBADeleteDeviceToken(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	tokenID, err := uuidParam(c, "token_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	// Verify the token belongs to this org before deleting.
	existing, err := h.cibaPushTokens.GetByID(ctx, tokenID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if existing == nil || existing.OrgID != orgID {
		return echo.NewHTTPError(http.StatusNotFound, "device token not found")
	}

	if _, err := h.cibaPushTokens.DeleteByID(ctx, tokenID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Self-service endpoints (bearer token auth) ────────────────────────────────

// PushRegisterDeviceToken allows an authenticated user to register their own
// mobile device push token.
//
//	POST /{org}/push/device-token
//	Authorization: Bearer <access_token>
//	{"platform": "apns"|"fcm", "device_token": "<token>"}
func (h *OIDCHandler) PushRegisterDeviceToken(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	ctx := c.Request().Context()

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "org not found")
	}

	userID, err := h.extractUserIDFromBearer(c, orgSlug)
	if err != nil {
		return err
	}

	var body struct {
		Platform    string `json:"platform"     validate:"required"`
		DeviceToken string `json:"device_token" validate:"required"`
	}
	if err := bindAndValidate(c, &body); err != nil {
		return err
	}
	if body.Platform != "apns" && body.Platform != "fcm" {
		return echo.NewHTTPError(http.StatusBadRequest, "platform must be \"apns\" or \"fcm\"")
	}

	dt, err := h.cibaPushTokens.Register(ctx, org.ID, userID, body.Platform, body.DeviceToken)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, dt)
}

// PushDeleteDeviceToken allows an authenticated user to unregister their own
// mobile device push token.
//
//	DELETE /{org}/push/device-token
//	Authorization: Bearer <access_token>
//	{"platform": "apns"|"fcm", "device_token": "<token>"}
func (h *OIDCHandler) PushDeleteDeviceToken(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	ctx := c.Request().Context()

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "org not found")
	}

	userID, err := h.extractUserIDFromBearer(c, orgSlug)
	if err != nil {
		return err
	}

	var body struct {
		Platform    string `json:"platform"     validate:"required"`
		DeviceToken string `json:"device_token" validate:"required"`
	}
	if err := bindAndValidate(c, &body); err != nil {
		return err
	}
	if body.Platform != "apns" && body.Platform != "fcm" {
		return echo.NewHTTPError(http.StatusBadRequest, "platform must be \"apns\" or \"fcm\"")
	}

	found, err := h.cibaPushTokens.DeleteByToken(ctx, org.ID, userID, body.Platform, body.DeviceToken)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if !found {
		return echo.NewHTTPError(http.StatusNotFound, "device token not found")
	}
	return c.NoContent(http.StatusNoContent)
}

// extractUserIDFromBearer validates the bearer access token for the given org
// and returns the authenticated user's UUID.
func (h *OIDCHandler) extractUserIDFromBearer(c echo.Context, orgSlug string) (uuid.UUID, error) {
	tc := h.newTC(h.issuerFromRequest(c, orgSlug))

	rawToken := extractBearer(c.Request())
	if rawToken == "" {
		return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "missing bearer token")
	}

	tok, jti, _, err := tc.VerifyAccessToken(rawToken)
	if err != nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
	}
	if revoked, _ := h.store.IsRevoked(c.Request().Context(), jti); revoked {
		return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "token revoked")
	}

	sub := tok.Subject()
	if sub == "" {
		return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "token has no subject")
	}

	userID, parseErr := uuid.Parse(sub)
	if parseErr != nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid subject claim")
	}
	return userID, nil
}
