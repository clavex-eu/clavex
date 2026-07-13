package handler

// KeyRotationHandler exposes the scheduled-rotation policy for the global
// signing keys (OIDC/PQC). Per-org BYOK keys are surfaced read-only: automatic
// rotation is never available for them.
//
// Endpoints (under /api/v1/organizations/:org_id):
//
//	GET /key-rotation          — policy + schedulability for every key category
//	PUT /key-rotation/:kind     — set policy for oidc|pqc (rejects BYOK)

import (
	"errors"
	"net/http"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// byokRotationMessage is returned when a caller tries to enable automatic
// rotation for an organization-provided key.
const byokRotationMessage = "Automatic rotation is not available for organization-provided (BYOK) keys — rotate manually through your own key management process."

// KeyRotationHandler serves the global key rotation policy API.
type KeyRotationHandler struct {
	repo     *repository.KeyRotationPolicyRepository
	signRepo *repository.SigningKeyRepository
	auditor  *audit.Emitter
}

// NewKeyRotationHandler builds the handler.
func NewKeyRotationHandler(cfg *config.Config, pool *pgxpool.Pool) *KeyRotationHandler {
	baseURL := cfg.Auth.IssuerBase
	if baseURL == "" {
		baseURL = cfg.HTTP.BaseDomain
	}
	return &KeyRotationHandler{
		repo:     repository.NewKeyRotationPolicyRepository(pool),
		signRepo: repository.NewSigningKeyRepository(pool),
		auditor:  audit.NewEmitter(baseURL, repository.NewAuditRepository(pool)),
	}
}

// keyRotationEntry is one key category's rotation status in the GET response.
type keyRotationEntry struct {
	KeyKind        string  `json:"key_kind"`
	RotationPolicy string  `json:"rotation_policy"`
	IntervalDays   int     `json:"rotation_interval_days"`
	LastRotatedAt  *string `json:"last_rotated_at"`
	Schedulable    bool    `json:"schedulable"`
	Reason         string  `json:"reason,omitempty"`
}

// orgHasBYOK reports whether the org has its own active signing key.
func (h *KeyRotationHandler) orgHasBYOK(c echo.Context, orgID uuid.UUID) (bool, error) {
	_, err := h.signRepo.GetActiveForOrg(c.Request().Context(), orgID)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return false, err
}

// policyEntry loads a kind's stored policy (defaulting to manual) and stamps
// schedulability.
func (h *KeyRotationHandler) policyEntry(c echo.Context, kind string, schedulable bool, reason string) keyRotationEntry {
	entry := keyRotationEntry{
		KeyKind:        kind,
		RotationPolicy: repository.RotationPolicyManual,
		IntervalDays:   90,
		Schedulable:    schedulable,
		Reason:         reason,
	}
	p, err := h.repo.Get(c.Request().Context(), kind)
	if err == nil {
		entry.RotationPolicy = p.RotationPolicy
		entry.IntervalDays = p.IntervalDays
		if p.LastRotatedAt != nil {
			s := p.LastRotatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
			entry.LastRotatedAt = &s
		}
	}
	return entry
}

// Status handles GET /key-rotation.
func (h *KeyRotationHandler) Status(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	hasBYOK, err := h.orgHasBYOK(c, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// OIDC: schedulable only when the org is NOT using a BYOK key (a BYOK org's
	// OIDC signing key IS its own key, which we never auto-rotate).
	oidcReason := ""
	if hasBYOK {
		oidcReason = byokRotationMessage
	}
	entries := []keyRotationEntry{
		h.policyEntry(c, repository.KeyKindOIDC, !hasBYOK, oidcReason),
		h.policyEntry(c, repository.KeyKindPQC, true, ""),
	}

	// BYOK is always read-only.
	byokReason := "No organization-provided (BYOK) key is configured."
	if hasBYOK {
		byokReason = byokRotationMessage
	}
	entries = append(entries, keyRotationEntry{
		KeyKind:        "byok",
		RotationPolicy: repository.RotationPolicyManual,
		Schedulable:    false,
		Reason:         byokReason,
	})

	return c.JSON(http.StatusOK, map[string]any{"keys": entries, "byok_active": hasBYOK})
}

type setPolicyBody struct {
	RotationPolicy string `json:"rotation_policy"`
	IntervalDays   int    `json:"rotation_interval_days"`
}

// InstallationStatus handles GET /superadmin/signing-keys (superadmin): the
// global OIDC/PQC rotation policy, independent of any org.
func (h *KeyRotationHandler) InstallationStatus(c echo.Context) error {
	entries := []keyRotationEntry{
		h.policyEntry(c, repository.KeyKindOIDC, true, ""),
		h.policyEntry(c, repository.KeyKindPQC, true, ""),
	}
	return c.JSON(http.StatusOK, map[string]any{"keys": entries})
}

// InstallationSetPolicy handles PUT /superadmin/signing-keys/:kind (superadmin).
// These keys are process-global singletons shared by every org, so only a
// superadmin may change their rotation policy.
func (h *KeyRotationHandler) InstallationSetPolicy(c echo.Context) error {
	ctx := c.Request().Context()
	kind := c.Param("kind")
	if kind != repository.KeyKindOIDC && kind != repository.KeyKindPQC {
		return echo.NewHTTPError(http.StatusBadRequest, "kind must be 'oidc' or 'pqc'")
	}
	var body setPolicyBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if body.RotationPolicy != repository.RotationPolicyManual && body.RotationPolicy != repository.RotationPolicyScheduled {
		return echo.NewHTTPError(http.StatusBadRequest, "rotation_policy must be 'manual' or 'scheduled'")
	}
	if body.RotationPolicy == repository.RotationPolicyScheduled && (body.IntervalDays < 1 || body.IntervalDays > 3650) {
		return echo.NewHTTPError(http.StatusBadRequest, "rotation_interval_days must be between 1 and 3650")
	}
	if body.IntervalDays == 0 {
		body.IntervalDays = 90
	}
	if err := h.repo.Upsert(ctx, kind, body.RotationPolicy, body.IntervalDays); err != nil {
		return echo.ErrInternalServerError
	}

	resourceType := "signing_key"
	resourceID := kind
	if claims := middleware.GetClaims(c); claims != nil {
		if orgID, perr := uuid.Parse(claims.OrgID); perr == nil {
			var actorID *uuid.UUID
			if id, aerr := uuid.Parse(claims.Subject); aerr == nil {
				actorID = &id
			}
			h.auditor.Emit(ctx, audit.EmitParams{
				OrgID:        orgID,
				ActorID:      actorID,
				Action:       "key.rotation.policy.updated",
				ResourceType: &resourceType,
				ResourceID:   &resourceID,
				Status:       "success",
				Metadata: map[string]interface{}{
					"rotation_policy":        body.RotationPolicy,
					"rotation_interval_days": body.IntervalDays,
					"scope":                  "installation",
					"via":                    "superadmin_console",
				},
			})
		}
	}
	return c.JSON(http.StatusOK, map[string]any{
		"key_kind":               kind,
		"rotation_policy":        body.RotationPolicy,
		"rotation_interval_days": body.IntervalDays,
	})
}

// SetPolicy handles PUT /key-rotation/:kind.
func (h *KeyRotationHandler) SetPolicy(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	kind := c.Param("kind")
	if kind != repository.KeyKindOIDC && kind != repository.KeyKindPQC {
		return echo.NewHTTPError(http.StatusBadRequest, byokRotationMessage)
	}

	var body setPolicyBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if body.RotationPolicy != repository.RotationPolicyManual && body.RotationPolicy != repository.RotationPolicyScheduled {
		return echo.NewHTTPError(http.StatusBadRequest, "rotation_policy must be 'manual' or 'scheduled'")
	}
	if body.RotationPolicy == repository.RotationPolicyScheduled {
		if body.IntervalDays < 1 || body.IntervalDays > 3650 {
			return echo.NewHTTPError(http.StatusBadRequest, "rotation_interval_days must be between 1 and 3650")
		}
		// Reject scheduled rotation for a BYOK-backed OIDC key.
		if kind == repository.KeyKindOIDC {
			hasBYOK, err := h.orgHasBYOK(c, orgID)
			if err != nil {
				return echo.ErrInternalServerError
			}
			if hasBYOK {
				return echo.NewHTTPError(http.StatusConflict, byokRotationMessage)
			}
		}
	}
	if body.IntervalDays == 0 {
		body.IntervalDays = 90
	}

	if err := h.repo.Upsert(ctx, kind, body.RotationPolicy, body.IntervalDays); err != nil {
		return echo.ErrInternalServerError
	}

	// Audit.
	action := "key.rotation.policy.updated"
	resourceType := "signing_key"
	resourceID := kind
	var actorID *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, perr := uuid.Parse(claims.Subject); perr == nil {
			actorID = &id
		}
	}
	h.auditor.Emit(ctx, audit.EmitParams{
		OrgID:        orgID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Status:       "success",
		Metadata: map[string]interface{}{
			"rotation_policy":        body.RotationPolicy,
			"rotation_interval_days": body.IntervalDays,
		},
	})

	return c.JSON(http.StatusOK, map[string]any{
		"key_kind":               kind,
		"rotation_policy":        body.RotationPolicy,
		"rotation_interval_days": body.IntervalDays,
	})
}
