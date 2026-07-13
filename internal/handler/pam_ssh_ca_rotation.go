package handler

// PAMSSHCARotationHandler drives the staged SSH CA rotation state machine.
//
// Authorization split:
//   - start / status / abort  → admin session (org-scoped admin JWT).
//   - mark-ready / complete    → Agent Token ONLY, bearing the dedicated scope
//     pam:ssh_ca:rotation:manage. These are the steps an external consumer
//     (e.g. Keel) performs once it has propagated the new CA across its fleet.
//
// The scheduler may trigger START automatically, but NEVER mark-ready/complete.

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/sshca"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"
)

// caSignerKey is the signer subset the agent-token middleware needs (narrowed
// for unit-testing without a full oidc.Signer).
type caSignerKey interface{ PublicKey() *rsa.PublicKey }

// agentTokenLookup is the agent-token repository subset used for revocation
// checks (narrowed for unit-testing).
type agentTokenLookup interface {
	GetByJTI(ctx context.Context, jti string) (*models.AgentToken, error)
}

// auditEmitter is the audit subset used by the rotation handler (narrowed for
// unit-testing the provenance distinction).
type auditEmitter interface {
	Emit(ctx context.Context, p audit.EmitParams)
}

// ScopeSSHCARotationManage authorises an Agent Token to advance the SSH CA
// rotation state machine (mark-ready, complete).
const ScopeSSHCARotationManage = "pam:ssh_ca:rotation:manage"

// echo context keys populated by the agent-token middleware.
const (
	ctxAgentID     = "agent_id"
	ctxDelegatedBy = "delegated_by"
)

// PAMSSHCARotationHandler serves the rotation endpoints.
type PAMSSHCARotationHandler struct {
	repo      *repository.PAMRepository
	svc       *sshca.Service
	agentRepo agentTokenLookup
	signer    caSignerKey
	auditor   auditEmitter
}

// NewPAMSSHCARotationHandler builds the handler. disp may be nil.
func NewPAMSSHCARotationHandler(cfg *config.Config, pool *pgxpool.Pool, enc *crypto.Encryptor, signer oidc.Signer, disp sshca.Dispatcher) *PAMSSHCARotationHandler {
	baseURL := cfg.Auth.IssuerBase
	if baseURL == "" {
		baseURL = cfg.HTTP.BaseDomain
	}
	repo := repository.NewPAMRepository(pool)
	return &PAMSSHCARotationHandler{
		repo:      repo,
		svc:       sshca.NewService(repo, enc, disp),
		agentRepo: repository.NewAgentTokenRepository(pool),
		signer:    signer,
		auditor:   audit.NewEmitter(baseURL, repository.NewAuditRepository(pool)),
	}
}

// ── Agent-token middleware ────────────────────────────────────────────────────

// RequireAgentScope verifies a PS256 Agent Token bearing the required scope.
// Admin session cookies/HMAC JWTs are intentionally NOT accepted here — these
// endpoints are agent-token only by design.
func (h *PAMSSHCARotationHandler) RequireAgentScope(scope string) echo.MiddlewareFunc {
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
			// Tenant isolation: the token's org must match the path org.
			orgID, err := uuidParam(c, "org_id")
			if err != nil {
				return err
			}
			if getClaim(tok, "org_id") != orgID.String() {
				return echo.NewHTTPError(http.StatusForbidden, "token not valid for this organization")
			}
			// Scope check.
			if !scopeContains(getClaim(tok, "scope"), scope) {
				return echo.NewHTTPError(http.StatusForbidden, "missing required scope: "+scope)
			}
			// Revocation check (expiry already validated by WithValidate).
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

func bearerToken(r *http.Request) string {
	h := r.Header.Get(echo.HeaderAuthorization)
	if idx := strings.IndexByte(h, ' '); idx > 0 && strings.EqualFold(h[:idx], "bearer") {
		return h[idx+1:]
	}
	return ""
}

func getClaim(tok jwtlib.Token, key string) string {
	if v, ok := tok.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func scopeContains(scopeClaim, want string) bool {
	for _, s := range strings.Fields(scopeClaim) {
		if s == want {
			return true
		}
	}
	return false
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// Start handles POST /pam/ssh-ca/rotation/start (admin).
func (h *PAMSSHCARotationHandler) Start(c echo.Context) error {
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

	rot, newPub, err := h.svc.Start(ctx, orgID, startedBy, "manual", nil)
	if err != nil {
		return rotationError(err)
	}

	h.emit(ctx, orgID, actorID, "pam.ssh_ca.rotation.started", rot.ID.String(), nil)
	return c.JSON(http.StatusCreated, map[string]any{
		"rotation":          rot,
		"new_ca_public_key": newPub,
	})
}

// Status handles GET /pam/ssh-ca/rotation (admin).
func (h *PAMSSHCARotationHandler) Status(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	rot, err := h.repo.GetActiveRotation(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if rot == nil {
		return c.JSON(http.StatusOK, map[string]any{"state": repository.SSHCARotationIdle})
	}
	return c.JSON(http.StatusOK, rot)
}

// MarkReady handles POST /pam/ssh-ca/rotation/:rotation_id/mark-ready (agent).
func (h *PAMSSHCARotationHandler) MarkReady(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	rotID, err := uuidParam(c, "rotation_id")
	if err != nil {
		return err
	}
	rot, err := h.repo.MarkCutoverReady(ctx, orgID, rotID)
	if err != nil {
		return rotationError(err)
	}
	h.emitRotationAction(c, ctx, orgID, "pam.ssh_ca.rotation.marked_ready", rotID.String())
	return c.JSON(http.StatusOK, rot)
}

// Complete handles POST /pam/ssh-ca/rotation/:rotation_id/complete (agent).
func (h *PAMSSHCARotationHandler) Complete(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	rotID, err := uuidParam(c, "rotation_id")
	if err != nil {
		return err
	}
	rot, err := h.svc.Complete(ctx, orgID, rotID)
	if err != nil {
		return rotationError(err)
	}
	if rot == nil {
		return echo.NewHTTPError(http.StatusNotFound, "rotation not found")
	}
	h.emitRotationAction(c, ctx, orgID, "pam.ssh_ca.rotation.completed", rotID.String())
	return c.JSON(http.StatusOK, rot)
}

// Abort handles POST /pam/ssh-ca/rotation/:rotation_id/abort (admin).
func (h *PAMSSHCARotationHandler) Abort(c echo.Context) error {
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
	rot, err := h.svc.Abort(ctx, orgID, rotID)
	if err != nil {
		return rotationError(err)
	}
	if rot == nil {
		return echo.NewHTTPError(http.StatusNotFound, "rotation not found")
	}
	h.emit(ctx, orgID, actorID, "pam.ssh_ca.rotation.aborted", rotID.String(), nil)
	return c.JSON(http.StatusOK, rot)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func rotationError(err error) error {
	switch err {
	case sshca.ErrNotConfigured:
		return echo.NewHTTPError(http.StatusNotFound, "SSH CA not configured")
	case sshca.ErrVaultMountCapability:
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	case repository.ErrActiveRotationExists:
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	case repository.ErrInvalidRotationTransition:
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	default:
		return echo.NewHTTPError(http.StatusBadGateway, "rotation failed: "+err.Error())
	}
}

func (h *PAMSSHCARotationHandler) emit(ctx context.Context, orgID uuid.UUID, actorID *uuid.UUID, action, resourceID string, extra map[string]any) {
	resourceType := "ssh_ca_rotation"
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
// distinguishing the two provenances: an Agent Token (records agent_id/
// delegated_by) vs an admin manually forcing the step via the console (records
// the admin identity and flags it as manually forced). The agent-token
// middleware sets ctxAgentID; its absence means the request authenticated as an
// admin session.
func (h *PAMSSHCARotationHandler) emitRotationAction(c echo.Context, ctx context.Context, orgID uuid.UUID, action, resourceID string) {
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

// emitAgent records an audit entry for an agent-token call, populating agent_id
// and delegated_by from the middleware-verified token.
func (h *PAMSSHCARotationHandler) emitAgent(c echo.Context, ctx context.Context, orgID uuid.UUID, action, resourceID string) {
	agentID, _ := c.Get(ctxAgentID).(string)
	delegatedBy, _ := c.Get(ctxDelegatedBy).(string)
	var actorID *uuid.UUID
	if id, err := uuid.Parse(delegatedBy); err == nil {
		actorID = &id
	}
	resourceType := "ssh_ca_rotation"
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
