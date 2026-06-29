// Package handler — AuthZen authorization API (OpenID AuthZen 1.0).
//
// Specification: https://openid.net/specs/authorization-api-1_0.html
//
// AuthZen decouples the Policy Decision Point (PDP) from the Policy Enforcement
// Point (PEP). A resource server calls POST /:org_slug/access/v1/evaluation
// to ask "can this subject perform this action on this resource?" and Clavex
// answers with {"decision": true|false} by running the org's auth-flow policy
// engine.
//
// # Request / Response (AuthZen §5)
//
//	POST /:org_slug/access/v1/evaluation
//	Authorization: Bearer <access-token>
//
//	{
//	  "subject":  {"type": "user", "id": "<sub>"},
//	  "resource": {"type": "document", "id": "doc-123"},
//	  "action":   {"name": "read"},
//	  "context":  {"ip": "1.2.3.4", "country": "IT"}
//	}
//
//	→ 200 {"decision": true, "context": {"reason": "no rule matched"}}
//
// # Auth
//
// The calling resource server must present a valid Clavex access token in the
// Authorization header (Bearer scheme). The token must be issued by the same
// org (matching issuer URL) that is being queried.
//
// # Policy mapping
//
// AuthZen's generic subject/resource/action is mapped to the existing policy
// EvalInput as follows:
//
//   - subject.id        → user lookup (by sub; also accepts email)
//   - action.name       → client_id in EvalInput (scope the rule to an app)
//   - context.ip        → IPAddress
//   - context.country   → Country (ISO 3166-1 alpha-2)
//   - user signals      → MFAEnrolled, NewCountry, LastLoginAt (live DB lookup)
//
// A policy ActionAllow → decision true; ActionDeny → decision false.
// ActionRequireMFA / ActionStepUp → decision false (step-up required, PEP must
// redirect the user through MFA before granting access).
package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/policy"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/risk"
	"github.com/clavex-eu/clavex/internal/shield"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// AuthZenHandler serves the OpenID AuthZen 1.0 authorization evaluation API.
type AuthZenHandler struct {
	cfg     *config.Config
	keys    oidc.Signer
	store   *session.Store
	policy  *policy.Repository
	users   *repository.UserRepository
	orgs    *repository.OrgRepository
	mfa     *repository.MFARepository
	history *repository.LoginHistoryRepository
	groups  *repository.GroupRepository
	risk         *risk.Scorer
	shieldClient *shield.Client
	feedClient   *shield.FeedClient
	// auditEmitter fans out authzen.evaluation events to the live SSE stream
	// and persists them in the structured audit log. May be nil (best-effort).
	auditEmitter *audit.Emitter
}

// NewAuthZenHandler constructs an AuthZenHandler.
func NewAuthZenHandler(cfg *config.Config, pool *pgxpool.Pool, store *session.Store, keys oidc.Signer) *AuthZenHandler {
	historyRepo := repository.NewLoginHistoryRepository(pool)
	auditRepo := repository.NewAuditRepository(pool)
	source := cfg.Auth.IssuerBase
	if source == "" {
		source = "http://" + cfg.HTTP.Addr
	}
	return &AuthZenHandler{
		cfg:          cfg,
		keys:         keys,
		store:        store,
		policy:       policy.NewRepository(pool),
		users:        repository.NewUserRepository(pool),
		orgs:         repository.NewOrgRepository(pool),
		mfa:          repository.NewMFARepository(pool),
		history:      historyRepo,
		groups:       repository.NewGroupRepository(pool),
		risk:         risk.NewScorer(historyRepo, nil, nil),
		auditEmitter: audit.NewEmitter(source, auditRepo),
	}
}

// WithShieldClient enables Clavex Shield threat-intelligence for the risk scorer.
func (h *AuthZenHandler) WithShieldClient(c *shield.Client) *AuthZenHandler {
	h.shieldClient = c
	h.risk = risk.NewScorer(h.history, c, h.feedClient)
	return h
}

// WithFeedClient attaches the Clavex Shield distributed threat feed client.
func (h *AuthZenHandler) WithFeedClient(f *shield.FeedClient) *AuthZenHandler {
	h.feedClient = f
	h.risk = risk.NewScorer(h.history, h.shieldClient, f)
	return h
}

// ── AuthZen request / response types ─────────────────────────────────────────

// azSubject is the AuthZen §5.1 Subject object.
type azSubject struct {
	// Type is the subject type identifier (e.g. "user", "service_account").
	// Clavex currently handles "user" subjects only.
	Type string `json:"type"`
	// ID is the subject's identity. For "user" subjects this is the OIDC sub claim
	// or the user's email address.
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// azResource is the AuthZen §5.2 Resource object.
type azResource struct {
	Type       string         `json:"type,omitempty"`
	ID         string         `json:"id,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// azAction is the AuthZen §5.3 Action object.
type azAction struct {
	// Name is the action identifier (e.g. "read", "write", "delete").
	// Mapped to EvalInput.ClientID so org policies can scope rules per-app.
	Name       string         `json:"name,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// azContext holds optional request context signals supplied by the PEP.
// Fields are merged into EvalInput to enrich policy evaluation.
type azContext struct {
	// IP is the end-user's IP address (overrides the HTTP request IP).
	IP string `json:"ip,omitempty"`
	// Country is the ISO 3166-1 alpha-2 country code of the request origin.
	Country string `json:"country,omitempty"`
	// UserAgent is the end-user's User-Agent string.
	UserAgent string `json:"user_agent,omitempty"`
	// Time overrides the evaluation timestamp (ISO 8601). Useful for testing.
	Time string `json:"time,omitempty"`
}

// azEvalRequest is the body of POST /access/v1/evaluation (AuthZen §5).
type azEvalRequest struct {
	Subject  azSubject  `json:"subject"`
	Resource azResource `json:"resource"`
	Action   azAction   `json:"action"`
	Context  azContext  `json:"context,omitempty"`
}

// azEvalResponse is the AuthZen §6 evaluation response.
type azEvalResponse struct {
	// Decision is true when the subject is allowed to perform the action.
	Decision bool           `json:"decision"`
	// Context carries optional diagnostics (rule name, reason, etc.).
	Context  map[string]any `json:"context,omitempty"`
}

// ── Batch request / response types ───────────────────────────────────────────

// azBatchEvalRequest is the body of POST /access/v1/evaluations (AuthZen §8).
// Each item in Evaluations is an independent single-evaluation request; they
// share the same authenticated token but may have different subjects, resources
// and actions.
type azBatchEvalRequest struct {
	Evaluations []azEvalRequest `json:"evaluations"`
}

// azBatchEvalResponse is returned by POST /access/v1/evaluations.
// The Evaluations slice is ordered and length-matched to the request slice.
type azBatchEvalResponse struct {
	Evaluations []azEvalResponse `json:"evaluations"`
}

// ── Evaluation endpoint ───────────────────────────────────────────────────────

// evalOne resolves a single AuthZen evaluation request against the org's policy.
//
// Resource-type dispatch (Zanzibar pattern):
//
//	resource.type == "role"
//	  action "has" | "member"                  — does subject hold this role? (composite traversal)
//	  action "assign" | "unassign" | "manage"  — subject must itself hold the "admin" role
//
//	resource.type == "group"
//	  action "has" | "member"                  — is subject a member of this group?
//	  action "manage" | "add" | "remove"       — subject must hold the "admin" role
//
// For any other resource.type the request falls through to the generic
// org auth-flow policy engine.
//
// Parameters:
//   - ctx: request context
//   - org: the already-resolved, active organisation
//   - fallbackIP: IP to use when req.Context.IP is empty (typically c.RealIP())
//   - p: the org's loaded policy (loaded once per request to avoid repeated DB calls)
//   - req: the individual evaluation request
func (h *AuthZenHandler) evalOne(
	ctx context.Context,
	org *models.Organization,
	fallbackIP string,
	p *policy.Policy,
	req azEvalRequest,
) azEvalResponse {
	deny := func(reason string) azEvalResponse {
		return azEvalResponse{Decision: false, Context: map[string]any{"reason": reason}}
	}

	if req.Subject.ID == "" {
		return deny("subject.id is required")
	}

	// ── Resolve subject user ──────────────────────────────────────────────────
	var (
		userMFAEnrolled bool
		userLastLogin   *time.Time
		userActive      bool
		userID          uuid.UUID
	)

	subjectID := req.Subject.ID
	parsed, parseErr := uuid.Parse(subjectID)
	if parseErr != nil {
		u, err := h.users.GetByEmail(ctx, org.ID, subjectID)
		if err != nil {
			return deny("subject not found")
		}
		userID = u.ID
		userActive = u.IsActive
		userLastLogin = u.LastLoginAt
	} else {
		userID = parsed
		u, err := h.users.GetByID(ctx, userID)
		if err != nil {
			return deny("subject not found")
		}
		userActive = u.IsActive
		userLastLogin = u.LastLoginAt
	}

	if !userActive {
		return deny("subject account is disabled")
	}

	if count, err := h.mfa.CountConfirmedByUser(ctx, userID); err == nil {
		userMFAEnrolled = count > 0
	}

	// ── RBAC short-circuit (Zanzibar pattern) ─────────────────────────────────
	// For well-known resource types ("role", "group") we resolve decisions
	// directly from the RBAC graph instead of the generic policy engine.
	// The resource.id may be a UUID or a human-readable name.
	switch req.Resource.Type {
	case "role":
		return h.rbacEvalRole(ctx, org, userID, req.Resource, req.Action)
	case "group":
		return h.rbacEvalGroup(ctx, org, userID, req.Resource, req.Action)
	}

	// ── Build EvalInput ───────────────────────────────────────────────────────
	ip := req.Context.IP
	if ip == "" {
		ip = fallbackIP
	}
	country := req.Context.Country

	anomaly, anomalyErr := h.history.GetAnomalySignals(ctx, userID, ip, country)
	newCountry := anomalyErr == nil && anomaly.NewCountry

	evalTime := time.Now().UTC()
	if req.Context.Time != "" {
		if t, err := time.Parse(time.RFC3339, req.Context.Time); err == nil {
			evalTime = t.UTC()
		}
	}

	in := policy.EvalInput{
		IPAddress:   ip,
		Country:     country,
		UserAgent:   req.Context.UserAgent,
		ClientID:    req.Action.Name, // action.name → client_id for per-app policy scoping
		UserID:      userID.String(),
		MFAEnrolled: userMFAEnrolled,
		NewCountry:  newCountry,
		LastLoginAt: userLastLogin,
		RequestTime: evalTime,
	}

	// ── Evaluate policy ───────────────────────────────────────────────────────
	outcome := policy.Evaluate(p, in)
	decision := outcome.Action == policy.ActionAllow

	respCtx := map[string]any{
		"rule":   outcome.RuleName,
		"reason": outcome.Reason,
	}
	if outcome.MFAForced {
		respCtx["mfa_required"] = true
	}

	return azEvalResponse{Decision: decision, Context: respCtx}
}

// ── RBAC helpers ──────────────────────────────────────────────────────────────

// rbacEvalRole evaluates an AuthZen request whose resource.type is "role".
//
// Supported actions:
//   - "has" | "member"                 → true if subject holds the role (incl. composite inheritance)
//   - "assign" | "unassign" | "manage" → true if subject holds the built-in "admin" role
//
// resource.id may be a UUID or a role name.
func (h *AuthZenHandler) rbacEvalRole(
	ctx context.Context,
	org *models.Organization,
	subjectID uuid.UUID,
	res azResource,
	action azAction,
) azEvalResponse {
	deny := func(reason string) azEvalResponse {
		return azEvalResponse{Decision: false, Context: map[string]any{"reason": reason}}
	}
	allow := func(detail map[string]any) azEvalResponse {
		return azEvalResponse{Decision: true, Context: detail}
	}

	if res.ID == "" {
		return deny("resource.id is required for type=role")
	}

	actionName := strings.ToLower(action.Name)

	// Resolve the role (by UUID or by name).
	var roleName string
	if roleID, err := uuid.Parse(res.ID); err == nil {
		// Lookup by UUID — pull just the name from the DB.
		role, err := h.users.GetRoleByID(ctx, roleID)
		if err != nil || role == nil {
			return deny("role not found")
		}
		if role.OrgID != org.ID {
			return deny("role not found") // cross-org access attempt
		}
		roleName = role.Name
	} else {
		// Treat as a name — verify it exists in this org.
		role, err := h.users.GetRoleByName(ctx, org.ID, res.ID)
		if err != nil || role == nil {
			return deny("role not found")
		}
		roleName = role.Name
	}

	switch actionName {
	case "has", "member":
		// Does the subject hold this role (directly or via composite inheritance)?
		ok, err := h.users.HasRoleFlattened(ctx, org.ID, subjectID, roleName)
		if err != nil {
			return deny("internal error evaluating role membership")
		}
		if !ok {
			return deny("subject does not hold role " + roleName)
		}
		return allow(map[string]any{
			"resource_type": "role",
			"role":          roleName,
			"action":        actionName,
		})

	case "assign", "unassign", "manage":
		// Privilege action — caller must be an org admin.
		isAdmin, err := h.users.HasRoleFlattened(ctx, org.ID, subjectID, "admin")
		if err != nil {
			return deny("internal error evaluating admin role")
		}
		if !isAdmin {
			return deny("subject is not an org admin")
		}
		return allow(map[string]any{
			"resource_type": "role",
			"role":          roleName,
			"action":        actionName,
		})

	default:
		return deny("unsupported action for resource type role: " + action.Name)
	}
}

// rbacEvalGroup evaluates an AuthZen request whose resource.type is "group".
//
// Supported actions:
//   - "has" | "member"          → true if subject is a direct member of the group
//   - "manage" | "add" | "remove" → true if subject holds the built-in "admin" role
//
// resource.id may be a UUID or a group name.
func (h *AuthZenHandler) rbacEvalGroup(
	ctx context.Context,
	org *models.Organization,
	subjectID uuid.UUID,
	res azResource,
	action azAction,
) azEvalResponse {
	deny := func(reason string) azEvalResponse {
		return azEvalResponse{Decision: false, Context: map[string]any{"reason": reason}}
	}
	allow := func(detail map[string]any) azEvalResponse {
		return azEvalResponse{Decision: true, Context: detail}
	}

	if res.ID == "" {
		return deny("resource.id is required for type=group")
	}

	actionName := strings.ToLower(action.Name)

	// Resolve the group (by UUID or by name).
	var groupID uuid.UUID
	var groupName string
	if gid, err := uuid.Parse(res.ID); err == nil {
		g, err := h.groups.GetByID(ctx, gid)
		if err != nil || g == nil {
			return deny("group not found")
		}
		if g.OrgID != org.ID {
			return deny("group not found") // cross-org
		}
		groupID = g.ID
		groupName = g.Name
	} else {
		g, err := h.groups.GetByName(ctx, org.ID, res.ID)
		if err != nil || g == nil {
			return deny("group not found")
		}
		groupID = g.ID
		groupName = g.Name
	}

	switch actionName {
	case "has", "member":
		ok, err := h.groups.IsMember(ctx, groupID, subjectID)
		if err != nil {
			return deny("internal error evaluating group membership")
		}
		if !ok {
			return deny("subject is not a member of group " + groupName)
		}
		return allow(map[string]any{
			"resource_type": "group",
			"group":         groupName,
			"action":        actionName,
		})

	case "manage", "add", "remove":
		isAdmin, err := h.users.HasRoleFlattened(ctx, org.ID, subjectID, "admin")
		if err != nil {
			return deny("internal error evaluating admin role")
		}
		if !isAdmin {
			return deny("subject is not an org admin")
		}
		return allow(map[string]any{
			"resource_type": "group",
			"group":         groupName,
			"action":        actionName,
		})

	default:
		return deny("unsupported action for resource type group: " + action.Name)
	}
}

// ── Decision audit log ────────────────────────────────────────────────────────

// emitDecision writes an authzen.evaluation event to the structured audit log
// and fans it out to the live SSE stream. It is fire-and-forget: errors are
// swallowed so a failing audit path never blocks the authorization response.
//
// Event type: com.clavex.audit.authzen.evaluation
// Metadata fields visible in /audit/stream and SIEM integrations:
//
//	subject_id, subject_type, resource_type, resource_id,
//	action, decision, rule, reason, ip
func (h *AuthZenHandler) emitDecision(
	ctx context.Context,
	orgID uuid.UUID,
	req azEvalRequest,
	resp azEvalResponse,
	ip string,
) {
	if h.auditEmitter == nil {
		return
	}
	status := "success"
	if !resp.Decision {
		status = "failure"
	}
	resType := req.Resource.Type
	resID := req.Resource.ID
	meta := map[string]any{
		"subject_id":    req.Subject.ID,
		"subject_type":  req.Subject.Type,
		"resource_type": resType,
		"resource_id":   resID,
		"action":        req.Action.Name,
		"decision":      resp.Decision,
	}
	if resp.Context != nil {
		if rule, ok := resp.Context["rule"]; ok && rule != nil {
			meta["rule"] = rule
		}
		if reason, ok := resp.Context["reason"]; ok && reason != nil {
			meta["reason"] = reason
		}
		if mfaReq, ok := resp.Context["mfa_required"]; ok {
			meta["mfa_required"] = mfaReq
		}
	}
	var resourceTypePt *string
	var resourceIDPt *string
	if resType != "" {
		resourceTypePt = &resType
	}
	if resID != "" {
		resourceIDPt = &resID
	}
	ipStr := ip
	h.auditEmitter.Emit(ctx, audit.EmitParams{
		OrgID:        orgID,
		Action:       "authzen.evaluation",
		ResourceType: resourceTypePt,
		ResourceID:   resourceIDPt,
		Status:       status,
		IPAddress:    &ipStr,
		Metadata:     meta,
	})
}

// Evaluate handles POST /:org_slug/access/v1/evaluation.
//
// The calling resource server presents a valid access token; Clavex runs the
// org's auth-flow policy against the requested subject and returns a boolean
// decision.
func (h *AuthZenHandler) Evaluate(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	// ── 1. Authenticate the PEP ─────────────────────────────────────────────
	rawToken := authzenExtractBearer(c)
	if rawToken == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing Bearer token")
	}

	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug)
	tc := &oidc.TokenConfig{Keys: h.keys, Issuer: issuer}
	_, jti, _, err := tc.VerifyAccessToken(rawToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired access token")
	}
	if revoked, _ := h.store.IsRevoked(ctx, jti); revoked {
		return echo.NewHTTPError(http.StatusUnauthorized, "token has been revoked")
	}

	// ── 2. Parse body ────────────────────────────────────────────────────────
	var req azEvalRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	// ── 3. Resolve org ───────────────────────────────────────────────────────
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	// ── 4. Load policy once ──────────────────────────────────────────────────
	p, err := h.policy.LoadPolicy(ctx, org.ID, nil)
	if err != nil {
		c.Logger().Errorf("authzen: load policy org=%s: %v", org.ID, err)
		return echo.ErrInternalServerError
	}

	// ── 5. Evaluate ──────────────────────────────────────────────────────────
	result := h.evalOne(ctx, org, c.RealIP(), p, req)
	h.emitDecision(ctx, org.ID, req, result, c.RealIP())
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, result)
}

// EvaluateBatch handles POST /:org_slug/access/v1/evaluations (AuthZen §8).
//
// Evaluates multiple subject/resource/action decisions in a single request,
// eliminating round-trips for resource servers with many parallel decisions.
// The policy is loaded once; each item is evaluated independently.
// The response slice is ordered and length-matched to the request slice.
func (h *AuthZenHandler) EvaluateBatch(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	// ── 1. Authenticate the PEP ─────────────────────────────────────────────
	rawToken := authzenExtractBearer(c)
	if rawToken == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing Bearer token")
	}

	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug)
	tc := &oidc.TokenConfig{Keys: h.keys, Issuer: issuer}
	_, jti, _, err := tc.VerifyAccessToken(rawToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired access token")
	}
	if revoked, _ := h.store.IsRevoked(ctx, jti); revoked {
		return echo.NewHTTPError(http.StatusUnauthorized, "token has been revoked")
	}

	// ── 2. Parse body ────────────────────────────────────────────────────────
	var req azBatchEvalRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if len(req.Evaluations) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "evaluations array must not be empty")
	}
	if len(req.Evaluations) > 100 {
		return echo.NewHTTPError(http.StatusBadRequest, "evaluations array exceeds maximum of 100 items")
	}

	// ── 3. Resolve org ───────────────────────────────────────────────────────
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	// ── 4. Load policy once for all items ───────────────────────────────────
	p, err := h.policy.LoadPolicy(ctx, org.ID, nil)
	if err != nil {
		c.Logger().Errorf("authzen: load policy org=%s: %v", org.ID, err)
		return echo.ErrInternalServerError
	}

	// ── 5. Evaluate each item ────────────────────────────────────────────────
	fallbackIP := c.RealIP()
	results := make([]azEvalResponse, len(req.Evaluations))
	for i, item := range req.Evaluations {
		results[i] = h.evalOne(ctx, org, fallbackIP, p, item)
		h.emitDecision(ctx, org.ID, item, results[i], fallbackIP)
	}

	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, azBatchEvalResponse{Evaluations: results})
}

// authzenExtractBearer extracts the Bearer token from the Authorization header.
func authzenExtractBearer(c echo.Context) string {
	auth := c.Request().Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// ── Policy Information Point (PIP) ────────────────────────────────────────────

// azSubjectAttributes is the response body for GET /access/v1/subject/:sub/attributes.
//
// It follows the AuthZen PIP convention (draft §9): a flat map of well-known
// attribute names alongside a typed breakdown for structured consumers.
//
// Resource servers can fetch these attributes once per session and embed them
// in subsequent evaluation requests via the subject.properties field, reducing
// the number of DB lookups per evaluation.
type azSubjectAttributes struct {
	// Subject identity echoed back for correlation.
	SubjectID   string `json:"subject_id"`
	SubjectType string `json:"subject_type"` // always "user" for now

	// ── Identity ───────────────────────────────────────────────────────────
	Email     string  `json:"email"`
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`

	// ── Account state ──────────────────────────────────────────────────────
	IsActive        bool       `json:"is_active"`
	IsEmailVerified bool       `json:"is_email_verified"`
	MFAEnrolled     bool       `json:"mfa_enrolled"`
	MFARequired     bool       `json:"mfa_required"`
	RequiredActions []string   `json:"required_actions"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`

	// ── Authorisation ──────────────────────────────────────────────────────
	// Roles assigned directly to the user.
	Roles []string `json:"roles"`
	// Groups the user belongs to.
	Groups []string `json:"groups"`

	// ── Risk & anomaly ─────────────────────────────────────────────────────
	RiskScore  int      `json:"risk_score"`  // 0-100
	RiskLevel  string   `json:"risk_level"`  // "low"|"medium"|"high"|"critical"
	RiskReason []string `json:"risk_reason"` // human-readable contributing factors

	// ── Identity Assurance (OpenID Connect for Identity Assurance 1.0) ────
	// Nil when no IDA evidence has been stored for this user.
	IDA *azIDAAttributes `json:"ida,omitempty"`

	// ── Arbitrary user metadata ────────────────────────────────────────────
	// All custom fields stored in user.Metadata, excluding internal keys
	// prefixed with "_" (e.g. "_ida", "_breach").
	CustomAttributes map[string]any `json:"custom_attributes,omitempty"`
}

// azIDAAttributes is the IDA sub-object inside azSubjectAttributes.
type azIDAAttributes struct {
	TrustFramework string `json:"trust_framework"`
	AssuranceLevel string `json:"assurance_level"`
}

// SubjectAttributes handles GET /:org_slug/access/v1/subject/:sub/attributes.
//
// This is the Policy Information Point (PIP) endpoint. It returns all
// authorisation-relevant attributes for a subject, allowing resource servers
// to cache user state and enrich AuthZen evaluation requests.
//
// :sub may be a UUID (OIDC sub claim) or an email address.
//
// The caller must present a valid Clavex access token in the Authorization
// header (same token accepted by Evaluate / EvaluateBatch).
//
// Response fields:
//   - roles / groups           — direct entitlements for ABAC/RBAC
//   - risk_score / risk_level  — live risk assessment (0-100 composite score)
//   - ida                      — trust_framework + assurance_level when set
//   - custom_attributes        — all non-internal user.Metadata fields
//   - required_actions         — pending actions (verify_email, reset_password…)
//
// This pattern is used by Zanzibar (Google), OPA, and Topaz to separate
// attribute loading from policy evaluation.
func (h *AuthZenHandler) SubjectAttributes(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	subParam := c.Param("sub")

	// ── 1. Authenticate the caller ───────────────────────────────────────────
	rawToken := authzenExtractBearer(c)
	if rawToken == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing Bearer token")
	}
	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug)
	tc := &oidc.TokenConfig{Keys: h.keys, Issuer: issuer}
	_, jti, _, err := tc.VerifyAccessToken(rawToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired access token")
	}
	if revoked, _ := h.store.IsRevoked(ctx, jti); revoked {
		return echo.NewHTTPError(http.StatusUnauthorized, "token has been revoked")
	}

	// ── 2. Resolve org ───────────────────────────────────────────────────────
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	// ── 3. Resolve subject ───────────────────────────────────────────────────
	var user *models.User
	if uid, parseErr := uuid.Parse(subParam); parseErr == nil {
		user, err = h.users.GetByID(ctx, uid)
	} else {
		user, err = h.users.GetByEmail(ctx, org.ID, subParam)
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "subject not found")
	}
	// Ensure the user belongs to the requested org.
	if user.OrgID != org.ID {
		return echo.NewHTTPError(http.StatusNotFound, "subject not found")
	}

	// ── 4. Fetch roles ───────────────────────────────────────────────────────
	rawRoles, _ := h.users.ListRolesByUser(ctx, user.ID)
	roleNames := make([]string, 0, len(rawRoles))
	for _, r := range rawRoles {
		roleNames = append(roleNames, r.Name)
	}

	// ── 5. Fetch groups ──────────────────────────────────────────────────────
	groupNames, _ := h.groups.GroupsForUser(ctx, user.ID)
	if groupNames == nil {
		groupNames = []string{}
	}

	// ── 6. MFA enrollment ────────────────────────────────────────────────────
	mfaCount, _ := h.mfa.CountConfirmedByUser(ctx, user.ID)
	mfaEnrolled := mfaCount > 0

	// ── 7. Risk score ────────────────────────────────────────────────────────
	riskScore := &risk.Score{Score: 0, Level: "low", Reason: []string{}}
	if computed, riskErr := h.risk.Compute(ctx, org.ID, user.ID); riskErr == nil {
		riskScore = computed
	}
	if riskScore.Reason == nil {
		riskScore.Reason = []string{}
	}

	// ── 8. IDA evidence ──────────────────────────────────────────────────────
	var idaAttrs *azIDAAttributes
	if ida := oidc.ExtractIDAMetadata(user.Metadata); ida != nil {
		idaAttrs = &azIDAAttributes{
			TrustFramework: ida.TrustFramework,
			AssuranceLevel: ida.AssuranceLevel,
		}
	}

	// ── 9. Custom attributes (strip internal "_" keys) ───────────────────────
	customAttrs := make(map[string]any)
	for k, v := range user.Metadata {
		if !strings.HasPrefix(k, "_") {
			customAttrs[k] = v
		}
	}
	if len(customAttrs) == 0 {
		customAttrs = nil
	}

	// ── 10. Build and return response ────────────────────────────────────────
	attrs := &azSubjectAttributes{
		SubjectID:        user.ID.String(),
		SubjectType:      "user",
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		IsActive:         user.IsActive,
		IsEmailVerified:  user.IsEmailVerified,
		MFAEnrolled:      mfaEnrolled,
		MFARequired:      user.MFARequired,
		RequiredActions:  user.RequiredActions,
		LastLoginAt:      user.LastLoginAt,
		Roles:            roleNames,
		Groups:           groupNames,
		RiskScore:        riskScore.Score,
		RiskLevel:        riskScore.Level,
		RiskReason:       riskScore.Reason,
		IDA:              idaAttrs,
		CustomAttributes: customAttrs,
	}

	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, attrs)
}
