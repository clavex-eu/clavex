package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/attestation"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// WebAuthnPolicyHandler manages per-org WebAuthn attestation enforcement policies.
// These policies allow enterprise admins to restrict passkey enrollment to specific
// authenticator models, attestation formats, or transports (e.g. "only managed iPhones").
type WebAuthnPolicyHandler struct {
	repo    *repository.WebAuthnPolicyRepository
	mdsRepo *repository.MDSRepository
}

func NewWebAuthnPolicyHandler(pool *pgxpool.Pool) *WebAuthnPolicyHandler {
	return &WebAuthnPolicyHandler{
		repo:    repository.NewWebAuthnPolicyRepository(pool),
		mdsRepo: repository.NewMDSRepository(pool),
	}
}

// GetWebAuthnPolicy returns the current attestation policy for an organization.
//
// GET /api/v1/organizations/:org_id/webauthn-policy
func (h *WebAuthnPolicyHandler) Get(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	policy, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, policy)
}

// UpsertWebAuthnPolicy creates or replaces the attestation policy for an organization.
// Sending an empty allowed_aaguids/allowed_formats/allowed_transports array removes
// that restriction (accept any value).  Set enabled=false to disable enforcement
// without deleting the configuration.
//
// PUT /api/v1/organizations/:org_id/webauthn-policy
func (h *WebAuthnPolicyHandler) Upsert(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	var req attestation.Policy
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}

	// Normalise nil slices to empty slices — pgx treats nil as NULL which
	// would break the NOT NULL DEFAULT '{}' constraint.
	if req.AllowedFormats == nil {
		req.AllowedFormats = []string{}
	}
	if req.AllowedAAGUIDs == nil {
		req.AllowedAAGUIDs = []string{}
	}
	if req.AllowedTransports == nil {
		req.AllowedTransports = []string{}
	}

	saved, err := h.repo.Upsert(c.Request().Context(), orgID, &req)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, saved)
}

// DeleteWebAuthnPolicy removes the attestation policy for an organization,
// resetting it to the default pass-through behaviour (no restrictions).
//
// DELETE /api/v1/organizations/:org_id/webauthn-policy
func (h *WebAuthnPolicyHandler) Delete(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	if err := h.repo.Delete(c.Request().Context(), orgID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// PreviewPolicy returns the set of MDS3 authenticators that would satisfy
// the given certification-level constraints, without saving any policy.
//
// This implements the explicit eligibility query:
//
//	SELECT aaguid, description, certification_level
//	FROM fido_mds_entries
//	WHERE certification_level IN ($qualifying_levels)
//	  AND NOT status_reports @> '["REVOKED"]'   -- when exclude_revoked=true
//
// An enterprise admin can select "FIDO2 L2+" and immediately see
// how many catalog entries qualify, without knowing any AAGUIDs.
//
// GET /api/v1/organizations/:org_id/webauthn-policy/preview
//
//	Query params:
//	  min_cert_level   string  (e.g. "L2", "L2+", "L3") — required
//	  exclude_revoked  bool    (default true)
func (h *WebAuthnPolicyHandler) PreviewPolicy(c echo.Context) error {
	_, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	minCertLevel := c.QueryParam("min_cert_level")
	if minCertLevel == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "min_cert_level is required")
	}

	excludeRevoked := c.QueryParam("exclude_revoked") != "false"

	entries, err := h.mdsRepo.QueryEligibleAAGUIDs(c.Request().Context(), minCertLevel, excludeRevoked)
	if err != nil {
		return echo.ErrInternalServerError
	}

	type previewDevice struct {
		AAGUID             string  `json:"aaguid"`
		Description        string  `json:"description"`
		CertificationLevel *string `json:"certification_level"`
		AuthenticatorType  string  `json:"authenticator_type"`
	}
	devices := make([]previewDevice, len(entries))
	for i, e := range entries {
		devices[i] = previewDevice{
			AAGUID:             e.AAGUID,
			Description:        e.Description,
			CertificationLevel: e.CertificationLevel,
			AuthenticatorType:  e.AuthenticatorType,
		}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"min_cert_level":  minCertLevel,
		"exclude_revoked": excludeRevoked,
		"total":           len(devices),
		"devices":         devices,
	})
}

// ListScoped returns all scoped attestation policies for an organization.
//
// GET /api/v1/organizations/:org_id/webauthn-policy/scoped
func (h *WebAuthnPolicyHandler) ListScoped(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	policies, err := h.repo.ListScoped(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if policies == nil {
		policies = make([]*repository.ScopedPolicy, 0)
	}
	return c.JSON(http.StatusOK, policies)
}

// GetScoped returns a single scoped attestation policy.
//
// GET /api/v1/organizations/:org_id/webauthn-policy/scoped/:scope_type/:scope_id
func (h *WebAuthnPolicyHandler) GetScoped(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	scopeType := c.Param("scope_type")
	if scopeType != "group" && scopeType != "role" {
		return echo.NewHTTPError(http.StatusBadRequest, "scope_type must be 'group' or 'role'")
	}
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid scope_id")
	}
	p, err := h.repo.GetScoped(c.Request().Context(), orgID, scopeType, scopeID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if p == nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, p)
}

// UpsertScoped creates or replaces a scoped attestation policy for a group or role.
//
// PUT /api/v1/organizations/:org_id/webauthn-policy/scoped/:scope_type/:scope_id
func (h *WebAuthnPolicyHandler) UpsertScoped(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	scopeType := c.Param("scope_type")
	if scopeType != "group" && scopeType != "role" {
		return echo.NewHTTPError(http.StatusBadRequest, "scope_type must be 'group' or 'role'")
	}
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid scope_id")
	}

	var req attestation.Policy
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}
	if req.AllowedFormats == nil {
		req.AllowedFormats = []string{}
	}
	if req.AllowedAAGUIDs == nil {
		req.AllowedAAGUIDs = []string{}
	}
	if req.AllowedTransports == nil {
		req.AllowedTransports = []string{}
	}

	saved, err := h.repo.UpsertScoped(c.Request().Context(), orgID, scopeType, scopeID, &req)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, saved)
}

// DeleteScoped removes a scoped attestation policy for a group or role.
//
// DELETE /api/v1/organizations/:org_id/webauthn-policy/scoped/:scope_type/:scope_id
func (h *WebAuthnPolicyHandler) DeleteScoped(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	scopeType := c.Param("scope_type")
	if scopeType != "group" && scopeType != "role" {
		return echo.NewHTTPError(http.StatusBadRequest, "scope_type must be 'group' or 'role'")
	}
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid scope_id")
	}
	if err := h.repo.DeleteScoped(c.Request().Context(), orgID, scopeType, scopeID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Policy presets ────────────────────────────────────────────────────────────

// ListPresets handles GET /api/v1/organizations/:org_id/webauthn-policy/presets
//
// Returns the catalogue of built-in attestation policy presets. Presets let
// administrators apply a fully-configured zero-trust policy without needing to
// know AAGUID values, transport identifiers, or MDS3 certification levels.
//
// Available presets:
//   - hardware-key-only   — USB/NFC physical keys only; blocks Face ID, Windows Hello
//   - phishing-resistant  — hardware + managed platform authenticators (MDS3 L1+)
//   - fido2-certified     — any FIDO2 L1+ certified authenticator, any transport
func (h *WebAuthnPolicyHandler) ListPresets(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"presets": attestation.BuiltInPresets,
	})
}

// ApplyPreset handles POST /api/v1/organizations/:org_id/webauthn-policy/presets/:preset_name
//
// Looks up the named preset and writes it to the org's attestation policy via
// the same upsert path used by the manual PUT endpoint.  Returns the saved policy.
//
// Path param:
//
//	preset_name — one of: hardware-key-only, phishing-resistant, fido2-certified
func (h *WebAuthnPolicyHandler) ApplyPreset(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	presetName := c.Param("preset_name")
	preset := attestation.GetPreset(presetName)
	if preset == nil {
		return echo.NewHTTPError(http.StatusNotFound, "unknown preset: "+presetName)
	}
	saved, err := h.repo.Upsert(c.Request().Context(), orgID, preset.Policy)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]any{
		"preset":  preset.Name,
		"policy":  saved,
	})
}
