package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/connectorregistry"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// SMSSettingsHandler manages per-org SMS gateway provider configuration.
// Restricted to org admins via the "sms" resource permission (see server routes).
type SMSSettingsHandler struct {
	repo *repository.SMSSettingsRepository
}

func NewSMSSettingsHandler(pool *pgxpool.Pool) *SMSSettingsHandler {
	return &SMSSettingsHandler{repo: repository.NewSMSSettingsRepository(pool)}
}

// smsSettingsResponse is the redacted view returned to the admin UI.
// Password-type config fields are blanked so secrets never leave the server.
type smsSettingsResponse struct {
	Provider string                 `json:"provider"`
	Config   map[string]interface{} `json:"config"`
	IsActive bool                   `json:"is_active"`
}

// Get returns the current SMS settings for an org with secret fields redacted.
// Returns an empty object when SMS is not configured yet.
// GET /api/v1/organizations/:org_id/sms
func (h *SMSSettingsHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	s, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil {
		// Not configured yet — return empty object (matches SMTP handler behaviour).
		return c.JSON(http.StatusOK, map[string]interface{}{})
	}
	return c.JSON(http.StatusOK, smsSettingsResponse{
		Provider: s.Provider,
		Config:   redactSMSSecrets(s.Provider, s.Config),
		IsActive: s.IsActive,
	})
}

type updateSMSRequest struct {
	Provider string                 `json:"provider"  validate:"required"`
	Config   map[string]interface{} `json:"config"    validate:"required"`
	IsActive bool                   `json:"is_active"`
}

// Put creates or updates the SMS provider config for an org.
// Password-type fields left empty in the request preserve the stored secret
// (so the redacted GET response can be saved back without re-entering secrets).
// The config is validated by instantiating the provider before persisting.
// PUT /api/v1/organizations/:org_id/sms
func (h *SMSSettingsHandler) Put(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req updateSMSRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	def := connectorregistry.GetSMS(req.Provider)
	if def == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "unknown SMS provider: "+req.Provider)
	}

	// Preserve stored secrets when the corresponding password field is left blank.
	merged := mergeSMSSecrets(req.Provider, req.Config, func() map[string]interface{} {
		if existing, gErr := h.repo.Get(ctx, orgID); gErr == nil {
			return existing.Config
		}
		return nil
	})

	// Validate the config by constructing the provider (checks required fields).
	if _, err := connectorregistry.NewSMSProvider(req.Provider, merged); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid SMS configuration: "+err.Error())
	}

	if err := h.repo.Upsert(ctx, orgID, req.Provider, merged, req.IsActive); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, smsSettingsResponse{
		Provider: req.Provider,
		Config:   redactSMSSecrets(req.Provider, merged),
		IsActive: req.IsActive,
	})
}

type testSMSRequest struct {
	To string `json:"to" validate:"required,e164"`
}

// Test sends a test SMS using the stored configuration.
// POST /api/v1/organizations/:org_id/sms/test
func (h *SMSSettingsHandler) Test(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req testSMSRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	s, err := h.repo.Get(ctx, orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "SMS not configured for this organization")
	}
	provider, err := connectorregistry.NewSMSProvider(s.Provider, s.Config)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid SMS configuration: "+err.Error())
	}
	if err := provider.Send(ctx, req.To, "Clavex SMS test — your SMS gateway is configured correctly."); err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "SMS test failed: "+err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Test SMS sent successfully"})
}

// ── helpers ────────────────────────────────────────────────────────────────────

// redactSMSSecrets returns a copy of config with all password-type fields blanked.
func redactSMSSecrets(providerID string, config map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(config))
	for k, v := range config {
		out[k] = v
	}
	def := connectorregistry.GetSMS(providerID)
	if def == nil {
		return out
	}
	for _, f := range def.ConfigSchema {
		if f.Type == "password" {
			if _, ok := out[f.Key]; ok {
				out[f.Key] = ""
			}
		}
	}
	return out
}

// mergeSMSSecrets carries over stored secret values for password-type fields that
// are blank or absent in the incoming config. existing is fetched lazily so the
// DB is only hit when a secret needs preserving.
func mergeSMSSecrets(providerID string, incoming map[string]interface{}, existing func() map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(incoming))
	for k, v := range incoming {
		out[k] = v
	}
	def := connectorregistry.GetSMS(providerID)
	if def == nil {
		return out
	}
	var prev map[string]interface{}
	for _, f := range def.ConfigSchema {
		if f.Type != "password" {
			continue
		}
		if s, _ := out[f.Key].(string); s != "" {
			continue // a new secret was provided
		}
		if prev == nil {
			prev = existing()
		}
		if prev != nil {
			if old, ok := prev[f.Key]; ok {
				out[f.Key] = old
			}
		}
	}
	return out
}
