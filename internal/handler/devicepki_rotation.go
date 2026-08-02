package handler

// DevicePKIRotationHandler drives the staged Device CA rotation state
// machine — the X.509 counterpart to PAMSSHCARotationHandler.
//
// Authorization split (identical rationale to the SSH CA rotation handler):
//   - start / status / abort  → admin session (org-scoped admin JWT).
//   - mark-ready / complete    → Agent Token ONLY, bearing the dedicated scope
//     device_pki:ca_rotation:manage. These are the steps an external consumer
//     (e.g. the MQTT broker operator) performs once the new Device CA has
//     been propagated to the broker's trust store.
//
// The scheduler may trigger START automatically, but NEVER mark-ready/complete.

import (
	"context"
	"net/http"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/devicepki"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"
)

// ScopeDeviceCARotationManage authorises an Agent Token to advance the Device
// CA rotation state machine (mark-ready, complete).
const ScopeDeviceCARotationManage = "device_pki:ca_rotation:manage"

// DevicePKIRotationHandler serves the Device CA rotation endpoints.
type DevicePKIRotationHandler struct {
	repo      *repository.DevicePKIRepository
	svc       *devicepki.Service
	agentRepo agentTokenLookup
	signer    caSignerKey
	auditor   auditEmitter
}

// NewDevicePKIRotationHandler builds the handler. disp may be nil.
func NewDevicePKIRotationHandler(cfg *config.Config, pool *pgxpool.Pool, enc *crypto.Encryptor, signer oidc.Signer, disp devicepki.Dispatcher) *DevicePKIRotationHandler {
	baseURL := cfg.Auth.IssuerBase
	if baseURL == "" {
		baseURL = cfg.HTTP.BaseDomain
	}
	repo := repository.NewDevicePKIRepository(pool)
	return &DevicePKIRotationHandler{
		repo:      repo,
		svc:       devicepki.NewService(repo, enc, disp),
		agentRepo: repository.NewAgentTokenRepository(pool),
		signer:    signer,
		auditor:   audit.NewEmitter(baseURL, repository.NewAuditRepository(pool)),
	}
}

// RequireAgentScope verifies a PS256 Agent Token bearing the required scope.
// Admin session cookies/HMAC JWTs are intentionally NOT accepted here.
func (h *DevicePKIRotationHandler) RequireAgentScope(scope string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			raw := bearerToken(c.Request())
			if raw == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "agent token required")
			}
			tok, err := jwtlib.Parse([]byte(raw),
				jwtlib.WithKey(jwa.PS256, h.signer.PublicKey()),
				jwtlib.WithValidate(true))
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid agent token")
			}
			if getClaim(tok, "token_type") != "agent" {
				return echo.NewHTTPError(http.StatusForbidden, "not an agent token")
			}
			orgID, err := uuidParam(c, "org_id")
			if err != nil {
				return err
			}
			if getClaim(tok, "org_id") != orgID.String() {
				return echo.NewHTTPError(http.StatusForbidden, "token not valid for this organization")
			}
			if !scopeContains(getClaim(tok, "scope"), scope) {
				return echo.NewHTTPError(http.StatusForbidden, "missing required scope: "+scope)
			}
			rec, err := h.agentRepo.GetByJTI(c.Request().Context(), tok.JwtID())
			if err != nil {
				return echo.ErrInternalServerError
			}
			if rec == nil || rec.IsRevoked {
				return echo.NewHTTPError(http.StatusUnauthorized, "agent token revoked")
			}

			c.Set(ctxAgentID, getClaim(tok, "agent_id"))
			c.Set(ctxDelegatedBy, getClaim(tok, "delegated_by"))
			return next(c)
		}
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────

// Start handles POST /devices/ca/rotation/start (admin).
func (h *DevicePKIRotationHandler) Start(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	startedBy := "admin"
	var actorID *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		startedBy = claims.Subject
		if id, perr := uuid.Parse(claims.Subject); perr == nil {
			actorID = &id
		}
	}

	rot, newCert, err := h.svc.StartRotation(ctx, orgID, startedBy, "manual", nil)
	if err != nil {
		return deviceRotationError(err)
	}

	h.emit(ctx, orgID, actorID, "device_ca.rotation.started", rot.ID.String(), nil)
	return c.JSON(http.StatusCreated, map[string]any{
		"rotation":    rot,
		"new_ca_cert": newCert,
	})
}

// Status handles GET /devices/ca/rotation (admin).
func (h *DevicePKIRotationHandler) Status(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	rot, err := h.repo.GetActiveDeviceCARotation(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if rot == nil {
		return c.JSON(http.StatusOK, map[string]any{"state": repository.DeviceCARotationIdle})
	}
	return c.JSON(http.StatusOK, rot)
}

// MarkReady handles POST /devices/ca/rotation/:rotation_id/mark-ready (agent).
func (h *DevicePKIRotationHandler) MarkReady(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	rotID, err := uuidParam(c, "rotation_id")
	if err != nil {
		return err
	}
	rot, err := h.repo.MarkDeviceCACutoverReady(ctx, orgID, rotID)
	if err != nil {
		return deviceRotationError(err)
	}
	h.emitRotationAction(c, ctx, orgID, "device_ca.rotation.marked_ready", rotID.String())
	return c.JSON(http.StatusOK, rot)
}

// Complete handles POST /devices/ca/rotation/:rotation_id/complete (agent).
func (h *DevicePKIRotationHandler) Complete(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	rotID, err := uuidParam(c, "rotation_id")
	if err != nil {
		return err
	}
	rot, err := h.svc.CompleteRotation(ctx, orgID, rotID)
	if err != nil {
		return deviceRotationError(err)
	}
	if rot == nil {
		return echo.NewHTTPError(http.StatusNotFound, "rotation not found")
	}
	h.emitRotationAction(c, ctx, orgID, "device_ca.rotation.completed", rotID.String())
	return c.JSON(http.StatusOK, rot)
}

// Abort handles POST /devices/ca/rotation/:rotation_id/abort (admin).
func (h *DevicePKIRotationHandler) Abort(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	rotID, err := uuidParam(c, "rotation_id")
	if err != nil {
		return err
	}
	var actorID *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, perr := uuid.Parse(claims.Subject); perr == nil {
			actorID = &id
		}
	}
	rot, err := h.svc.AbortRotation(ctx, orgID, rotID)
	if err != nil {
		return deviceRotationError(err)
	}
	if rot == nil {
		return echo.NewHTTPError(http.StatusNotFound, "rotation not found")
	}
	h.emit(ctx, orgID, actorID, "device_ca.rotation.aborted", rotID.String(), nil)
	return c.JSON(http.StatusOK, rot)
}

// ── helpers ──────────────────────────────────────────────────────────────

func deviceRotationError(err error) error {
	switch err {
	case devicepki.ErrNotConfigured:
		return echo.NewHTTPError(http.StatusNotFound, "Device CA not configured")
	case devicepki.ErrVaultMountCapability:
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	case repository.ErrActiveDeviceCARotationExists:
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	case repository.ErrInvalidDeviceCARotationTransition:
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	default:
		return echo.NewHTTPError(http.StatusBadGateway, "rotation failed: "+err.Error())
	}
}

func (h *DevicePKIRotationHandler) emit(ctx context.Context, orgID uuid.UUID, actorID *uuid.UUID, action, resourceID string, extra map[string]any) {
	resourceType := "device_ca_rotation"
	meta := map[string]interface{}{}
	for k, v := range extra {
		meta[k] = v
	}
	h.auditor.Emit(ctx, audit.EmitParams{
		OrgID:        orgID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Status:       "success",
		Metadata:     meta,
	})
}

// emitRotationAction records the audit entry for a mark-ready/complete call,
// distinguishing an Agent Token call from an admin manually forcing the step —
// same provenance distinction as PAMSSHCARotationHandler.emitRotationAction.
func (h *DevicePKIRotationHandler) emitRotationAction(c echo.Context, ctx context.Context, orgID uuid.UUID, action, resourceID string) {
	if agentID, _ := c.Get(ctxAgentID).(string); agentID != "" {
		h.emitAgent(c, ctx, orgID, action, resourceID)
		return
	}
	var actorID *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, err := uuid.Parse(claims.Subject); err == nil {
			actorID = &id
		}
	}
	h.emit(ctx, orgID, actorID, action, resourceID, map[string]any{
		"via":    "admin_console",
		"forced": true,
		"note":   "manually forced via admin console",
	})
}

func (h *DevicePKIRotationHandler) emitAgent(c echo.Context, ctx context.Context, orgID uuid.UUID, action, resourceID string) {
	agentID, _ := c.Get(ctxAgentID).(string)
	delegatedBy, _ := c.Get(ctxDelegatedBy).(string)
	var actorID *uuid.UUID
	if id, err := uuid.Parse(delegatedBy); err == nil {
		actorID = &id
	}
	resourceType := "device_ca_rotation"
	h.auditor.Emit(ctx, audit.EmitParams{
		OrgID:        orgID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Status:       "success",
		Metadata: map[string]interface{}{
			"agent_id":     agentID,
			"delegated_by": delegatedBy,
			"via":          "agent_token",
		},
	})
}
