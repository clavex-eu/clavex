package handler

// KeyRotationHandler exposes the scheduled-rotation policy for signing keys.
//
// OIDC and PQC keys are now both per-org (every org has its own key), so their
// rotation policy is org-scoped and managed by the org's security admins.
// Imported (BYOK / external-custody) org keys are surfaced read-only: Clavex
// cannot auto-rotate material it does not hold. (Global installation-wide
// policies remain manageable via the superadmin console.)
//
// Endpoints (under /api/v1/organizations/:org_id):
//
//	GET /key-rotation          — policy + schedulability for every key category
//	PUT /key-rotation/:kind     — set org policy for oidc | pqc
//	POST /key-rotation/:kind/rotate — rotate a generated tenant key now

import (
	"context"
	"errors"
	"net/http"
	"time"

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
type orgKeyRotator interface {
	RotateForOrg(context.Context, uuid.UUID) (string, error)
}

type KeyRotationHandler struct {
	oidcRotator orgKeyRotator
	pqcRotator  orgKeyRotator
	repo        *repository.KeyRotationPolicyRepository
	signRepo    *repository.SigningKeyRepository
	auditor     *audit.Emitter
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
	Rotatable      bool    `json:"rotatable"`
	KID            string  `json:"kid,omitempty"`
}

// orgKeyImported reports whether the org's active signing key is imported
// (BYOK / external custody), i.e. material Clavex does not hold and must never
// regenerate. Auto-provisioned ("generated") keys, or the absence of any key
// yet, are not imported. hasKey distinguishes "generated" from "no key yet".
func (h *KeyRotationHandler) orgKeyImported(c echo.Context, orgID uuid.UUID) (imported, hasKey bool, err error) {
	src, e := h.signRepo.GetActiveKeySourceForOrg(c.Request().Context(), orgID)
	if e == nil {
		return src == "imported", true, nil
	}
	if errors.Is(e, pgx.ErrNoRows) {
		return false, false, nil
	}
	return false, false, e
}

// policyEntry loads a kind's stored policy (defaulting to manual) and stamps
// schedulability. When orgID is non-nil the org-scoped policy is read (OIDC);
// when nil the global policy is read (PQC, legacy global OIDC).
func (h *KeyRotationHandler) policyEntry(c echo.Context, kind string, orgID *uuid.UUID, schedulable bool, reason string) keyRotationEntry {
	entry := keyRotationEntry{
		KeyKind:        kind,
		RotationPolicy: repository.RotationPolicyManual,
		IntervalDays:   90,
		Schedulable:    schedulable,
		Reason:         reason,
	}
	var (
		p   *repository.KeyRotationPolicy
		err error
	)
	if orgID != nil {
		p, err = h.repo.GetForOrg(c.Request().Context(), kind, *orgID)
	} else {
		p, err = h.repo.Get(c.Request().Context(), kind)
	}
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
	imported, _, err := h.orgKeyImported(c, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// OIDC is per-org: schedulable unless the org runs an imported (BYOK / HSM)
	// key, whose material Clavex does not hold and therefore cannot auto-rotate.
	oidcReason := ""
	if imported {
		oidcReason = byokRotationMessage
	}
	entries := []keyRotationEntry{
		h.policyEntry(c, repository.KeyKindOIDC, &orgID, !imported, oidcReason),
		// PQC is now per-org too (auto-provisioned, always server-generated), so
		// its rotation policy is org-scoped and org-manageable.
		h.policyEntry(c, repository.KeyKindPQC, &orgID, true, ""),
	}

	// The BYOK card reflects imported / external-custody material only. A plain
	// auto-provisioned org key is NOT BYOK — that isolation is now free.
	byokReason := "No imported key is configured — Clavex generates and manages this org's OIDC key automatically."
	if imported {
		byokReason = byokRotationMessage
	}
	entries = append(entries, keyRotationEntry{
		KeyKind:        "byok",
		RotationPolicy: repository.RotationPolicyManual,
		Schedulable:    false,
		Reason:         byokReason,
	})

	for i := range entries {
		switch entries[i].KeyKind {
		case repository.KeyKindOIDC:
			entries[i].Rotatable = !imported && h.oidcRotator != nil
			if row, e := h.signRepo.GetActiveForOrg(c.Request().Context(), orgID); e == nil {
				entries[i].KID = row.KID
				if entries[i].LastRotatedAt == nil {
					date := row.CreatedAt.UTC().Format(time.RFC3339)
					entries[i].LastRotatedAt = &date
				}
			}
			if h.oidcRotator == nil {
				entries[i].Schedulable = false
				entries[i].Reason = "Tenant signing-key rotation requires the database key backend."
			}
		case repository.KeyKindPQC:
			entries[i].Rotatable = h.pqcRotator != nil
			if row, e := h.signRepo.GetActivePQCForOrg(c.Request().Context(), orgID); e == nil {
				entries[i].KID = row.KID
				if entries[i].LastRotatedAt == nil {
					date := row.CreatedAt.UTC().Format(time.RFC3339)
					entries[i].LastRotatedAt = &date
				}
			}
			if h.pqcRotator == nil {
				entries[i].Schedulable = false
				entries[i].Reason = "Tenant PQC rotation requires PQC and the database key backend."
			}
		}
	}
	return c.JSON(http.StatusOK, map[string]any{"keys": entries, "byok_active": imported, "can_manage": tenantKeysWritable(c)})
}

type setPolicyBody struct {
	RotationPolicy string `json:"rotation_policy"`
	IntervalDays   int    `json:"rotation_interval_days"`
}

// InstallationStatus handles GET /superadmin/signing-keys (superadmin): the
// global OIDC/PQC rotation policy, independent of any org.
func (h *KeyRotationHandler) InstallationStatus(c echo.Context) error {
	entries := []keyRotationEntry{
		h.policyEntry(c, repository.KeyKindOIDC, nil, true, ""),
		h.policyEntry(c, repository.KeyKindPQC, nil, true, ""),
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

	if (kind == repository.KeyKindOIDC && h.oidcRotator == nil) || (kind == repository.KeyKindPQC && h.pqcRotator == nil) {
		return echo.NewHTTPError(http.StatusConflict, "tenant key rotation is unavailable for this key backend")
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
		// Reject scheduled rotation for an imported (BYOK / HSM) OIDC key: Clavex
		// cannot regenerate material it does not hold.
		if kind == repository.KeyKindOIDC {
			imported, _, err := h.orgKeyImported(c, orgID)
			if err != nil {
				return echo.ErrInternalServerError
			}
			if imported {
				return echo.NewHTTPError(http.StatusConflict, byokRotationMessage)
			}
		}
	}
	if body.IntervalDays == 0 {
		body.IntervalDays = 90
	}

	// Both OIDC and PQC are now per-org: each org has its own key, so its
	// rotation policy is org-scoped.
	if err := h.repo.UpsertForOrg(ctx, kind, orgID, body.RotationPolicy, body.IntervalDays); err != nil {
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

// WithOrgRotators configures the tenant operations independently of global keys.
func (h *KeyRotationHandler) WithOrgRotators(rsa, pqc orgKeyRotator) *KeyRotationHandler {
	h.oidcRotator = rsa
	h.pqcRotator = pqc
	return h
}

// Rotate handles POST /key-rotation/:kind/rotate. Imported keys require explicit
// replacement through the tenant signing-key endpoint, never silent generation.
func (h *KeyRotationHandler) Rotate(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var rotator orgKeyRotator
	kind := c.Param("kind")
	switch kind {
	case repository.KeyKindOIDC:
		rotator = h.oidcRotator
	case repository.KeyKindPQC:
		rotator = h.pqcRotator
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "kind must be 'oidc' or 'pqc'")
	}
	if rotator == nil {
		return echo.NewHTTPError(http.StatusConflict, "tenant key rotation is unavailable for this key backend")
	}
	ctx := c.Request().Context()
	kid, err := rotator.RotateForOrg(ctx, orgID)
	if errors.Is(err, repository.ErrImportedSigningKey) {
		return echo.NewHTTPError(http.StatusConflict, byokRotationMessage)
	}
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	// Record the event independently of whether a rotation policy was set.
	resourceType, resourceID := "signing_key", kid
	var actorID *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, e := uuid.Parse(claims.Subject); e == nil {
			actorID = &id
		}
	}
	h.auditor.Emit(ctx, audit.EmitParams{OrgID: orgID, ActorID: actorID, Action: "key.rotated", ResourceType: &resourceType, ResourceID: &resourceID, Status: "success", Metadata: map[string]interface{}{"key_kind": kind, "scope": "tenant"}})
	if err := h.repo.MarkRotatedForOrg(ctx, kind, orgID, time.Now()); err != nil {
		c.Logger().Errorf("key rotated but policy timestamp update failed: %v", err)
	}
	return c.JSON(http.StatusOK, map[string]string{"kid": kid, "key_kind": kind})
}

func tenantKeysWritable(c echo.Context) bool {
	claims := middleware.GetClaims(c)
	if claims == nil || !claims.IsAdmin || claims.IsSuperAdmin || claims.OrgID != c.Param("org_id") {
		return false
	}
	if claims.Permissions == nil {
		return true
	}
	for _, perm := range claims.Permissions {
		if perm == middleware.PermSecurityWrite {
			return true
		}
	}
	return false
}
