package handler

// Admin API endpoints for per-org CIBA notification channel configuration.
//
// Routes:
//   GET    /api/v1/organizations/:org_id/ciba/notification-config
//   PUT    /api/v1/organizations/:org_id/ciba/notification-config
//   DELETE /api/v1/organizations/:org_id/ciba/notification-config
//
// These endpoints are protected by the standard admin API middleware
// (bearer token + org membership check).

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/labstack/echo/v4"
)

// GetCIBANotificationConfig returns the CIBA notification configuration for an org.
//
//	GET /api/v1/organizations/:org_id/ciba/notification-config
func (h *OIDCHandler) GetCIBANotificationConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	cfg, err := h.cibaNotifyCfg.Get(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if cfg == nil {
		return c.JSON(http.StatusOK, map[string]any{
			"org_id":                  orgID,
			"webhook_url":             nil,
			"webhook_secret":          nil,
			"webhook_headers":         map[string]string{},
			"email_enabled":           false,
			"sms_enabled":             false,
			"base_url":                nil,
			"push_enabled":            false,
			"apns_key_set":            false,
			"apns_key_id":             nil,
			"apns_team_id":            nil,
			"apns_bundle_id":          nil,
			"apns_production":         false,
			"fcm_service_account_set": false,
		})
	}
	return c.JSON(http.StatusOK, cibaNotifyCfgResponse(cfg))
}

// UpsertCIBANotificationConfig creates or replaces the CIBA notification configuration for an org.
//
//	PUT /api/v1/organizations/:org_id/ciba/notification-config
func (h *OIDCHandler) UpsertCIBANotificationConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	var body struct {
		WebhookURL     *string           `json:"webhook_url"`
		WebhookSecret  *string           `json:"webhook_secret"`
		WebhookHeaders map[string]string `json:"webhook_headers"`
		EmailEnabled   bool              `json:"email_enabled"`
		SMSEnabled     bool              `json:"sms_enabled"`
		BaseURL        *string           `json:"base_url"`
		// Push (APNs + FCM)
		PushEnabled           bool    `json:"push_enabled"`
		APNsKeyP8             *string `json:"apns_key_p8"`
		APNsKeyID             *string `json:"apns_key_id"`
		APNsTeamID            *string `json:"apns_team_id"`
		APNsBundleID          *string `json:"apns_bundle_id"`
		APNsProduction        bool    `json:"apns_production"`
		FCMServiceAccountJSON *string `json:"fcm_service_account_json"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	// Validation: webhook_url must be HTTPS when set.
	if body.WebhookURL != nil && *body.WebhookURL != "" {
		url := *body.WebhookURL
		if len(url) < 8 || url[:8] != "https://" {
			return echo.NewHTTPError(http.StatusBadRequest, "webhook_url must use HTTPS")
		}
	}

	cfg := repository.CIBANotificationConfig{
		OrgID:                 orgID,
		WebhookURL:            body.WebhookURL,
		WebhookSecret:         body.WebhookSecret,
		WebhookHeaders:        body.WebhookHeaders,
		EmailEnabled:          body.EmailEnabled,
		SMSEnabled:            body.SMSEnabled,
		BaseURL:               body.BaseURL,
		PushEnabled:           body.PushEnabled,
		APNsKeyP8:             body.APNsKeyP8,
		APNsKeyID:             body.APNsKeyID,
		APNsTeamID:            body.APNsTeamID,
		APNsBundleID:          body.APNsBundleID,
		APNsProduction:        body.APNsProduction,
		FCMServiceAccountJSON: body.FCMServiceAccountJSON,
	}
	if cfg.WebhookHeaders == nil {
		cfg.WebhookHeaders = map[string]string{}
	}

	if err := h.cibaNotifyCfg.Upsert(c.Request().Context(), cfg); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, cibaNotifyCfgResponse(&cfg))
}

// DeleteCIBANotificationConfig removes the CIBA notification configuration for an org.
//
//	DELETE /api/v1/organizations/:org_id/ciba/notification-config
func (h *OIDCHandler) DeleteCIBANotificationConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	if err := h.cibaNotifyCfg.Delete(c.Request().Context(), orgID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// cibaNotifyCfgResponse serialises a CIBANotificationConfig into a JSON-friendly map
// with the webhook_secret and APNs/FCM credentials redacted (replaced with booleans).
func cibaNotifyCfgResponse(cfg *repository.CIBANotificationConfig) map[string]any {
	hasSecret := cfg.WebhookSecret != nil && *cfg.WebhookSecret != ""
	hasAPNsKey := cfg.APNsKeyP8 != nil && *cfg.APNsKeyP8 != ""
	hasFCMKey := cfg.FCMServiceAccountJSON != nil && *cfg.FCMServiceAccountJSON != ""
	headers := cfg.WebhookHeaders
	if headers == nil {
		headers = map[string]string{}
	}
	return map[string]any{
		"org_id":                 cfg.OrgID,
		"webhook_url":            cfg.WebhookURL,
		"webhook_secret_set":     hasSecret,
		"webhook_headers":        headers,
		"email_enabled":          cfg.EmailEnabled,
		"sms_enabled":            cfg.SMSEnabled,
		"base_url":               cfg.BaseURL,
		"push_enabled":           cfg.PushEnabled,
		"apns_key_set":           hasAPNsKey,
		"apns_key_id":            cfg.APNsKeyID,
		"apns_team_id":           cfg.APNsTeamID,
		"apns_bundle_id":         cfg.APNsBundleID,
		"apns_production":        cfg.APNsProduction,
		"fcm_service_account_set": hasFCMKey,
	}
}
