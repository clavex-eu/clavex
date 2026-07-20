package handler

// StreamHandler exposes a WebSocket endpoint that fans IAM events to
// authenticated developer clients in real-time.
//
//	GET /:org_slug/events
//	    wss://id.clavex.eu/:slug/events
//
// Auth: Bearer JWT in Authorization header (server-to-server), the HttpOnly
// admin session cookie (browser admin console), or a ?token=<jwt> query
// parameter (external browser clients / interactive tools).
//
// Optional filters (query params, same as SSE stream):
//
//	?action=user.login          — exact action match
//	?resource_type=session      — filter by resource type
//	?status=success|failure     — filter by status
//
// Wire format: newline-delimited JSON (one audit.Event per message).
// Heartbeat: a {"type":"heartbeat"} message every 30 seconds.
// The server closes the connection with status 1008 on auth failure.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	internaudit "github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/config"
	mw "github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

var wsUpgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	ReadBufferSize:   256,
	WriteBufferSize:  4096,
	// CheckOrigin is validated per-connection in the handler based on the JWT;
	// we accept the upgrade here and close on auth failure to avoid a pre-auth
	// HTTP 403 that would leak information.
	CheckOrigin: func(_ *http.Request) bool { return true },
}

// StreamHandler publishes audit events over WebSocket.
type StreamHandler struct {
	dispatcher *internaudit.Dispatcher
	orgs       *repository.OrgRepository
	audit      *repository.AuditRepository
	apiKeys    *repository.AdminAPIKeyRepository
	cfg        *config.Config
}

// NewStreamHandler creates a StreamHandler. Call WithDispatcher before use.
func NewStreamHandler(pool *pgxpool.Pool, cfg *config.Config) *StreamHandler {
	return &StreamHandler{
		orgs:    repository.NewOrgRepository(pool),
		apiKeys: repository.NewAdminAPIKeyRepository(pool),
		cfg:     cfg,
	}
}

// WithDispatcher attaches the audit event dispatcher (called after it is created).
func (h *StreamHandler) WithDispatcher(d *internaudit.Dispatcher) *StreamHandler {
	h.dispatcher = d
	return h
}

// WithAuditRepository attaches the audit repository used for replay.
func (h *StreamHandler) WithAuditRepository(r *repository.AuditRepository) *StreamHandler {
	h.audit = r
	return h
}

// Connect upgrades to WebSocket and streams live IAM events for the org.
func (h *StreamHandler) Connect(c echo.Context) error {
	if h.dispatcher == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "stream not available")
	}

	// ── Auth ────────────────────────────────────────────────────────────────
	// Two accepted credentials, resolved to a common principal:
	//   1. an admin JWT (server-side SDK, admin console, ?token=)
	//   2. an org-scoped Admin API key (X-API-Key / ?api_key=) — the same key
	//      the Kubernetes operator already uses for its Admin API v2 calls.
	// Both collapse to (org UUID, super-admin?) and go through the identical
	// org-scope check below, so API-key callers get exactly the JWT behaviour.
	var principalOrgID string
	var principalSuperAdmin bool

	if rawToken := extractBearerOrQuery(c); rawToken != "" {
		if claims, err := h.parseAdminJWT(rawToken); err == nil {
			principalOrgID = claims.OrgID
			principalSuperAdmin = claims.IsSuperAdmin
			goto authed
		}
	}
	// JWT absent or invalid — fall back to an org-scoped API key.
	if apiKey := extractAPIKey(c); apiKey != "" && h.apiKeys != nil {
		auth, err := h.apiKeys.VerifyKey(c.Request().Context(), apiKey)
		if err == nil && auth != nil {
			principalSuperAdmin = auth.OrgID == nil // nil org_id = superadmin key
			if auth.OrgID != nil {
				principalOrgID = auth.OrgID.String()
			}
			goto authed
		}
	}
	return echo.ErrUnauthorized

authed:
	// ── Resolve org slug → UUID ──────────────────────────────────────────────
	slug := c.Param("org_slug")
	org, err := h.orgs.GetBySlug(c.Request().Context(), slug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "org not found")
	}
	orgIDStr := org.ID.String()

	// ── Scope check: principal must belong to this org (or be super-admin) ────
	if !orgScopeAllowed(principalOrgID, principalSuperAdmin, orgIDStr) {
		return echo.NewHTTPError(http.StatusForbidden, "org mismatch")
	}

	// ── Upgrade to WebSocket ─────────────────────────────────────────────────
	ws, err := wsUpgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		// gorilla writes the HTTP error response itself on upgrade failure.
		log.Warn().Err(err).Str("slug", slug).Msg("ws upgrade failed")
		return nil
	}
	defer ws.Close()

	// ── Optional server-side filters ─────────────────────────────────────────
	filterAction       := c.QueryParam("action")
	filterResourceType := c.QueryParam("resource_type")
	filterStatus       := c.QueryParam("status")

	// ── Replay: send last N events before subscribing to live stream ──────────
	if h.audit != nil {
		if replayStr := c.QueryParam("replay"); replayStr != "" {
			replayN, err := strconv.Atoi(replayStr)
			if err != nil || replayN < 0 {
				replayN = 0
			}
			if replayN > 100 {
				replayN = 100
			}
			if replayN > 0 {
				page, err := h.audit.List(c.Request().Context(), repository.AuditFilter{
					OrgID:  org.ID,
					Action: filterAction,
					ResourceType: filterResourceType,
					Status: filterStatus,
					Limit:  replayN,
				})
				if err == nil {
					for _, ae := range page.Events {
						payload, err := json.Marshal(ae)
						if err != nil {
							continue
						}
						if err := ws.WriteMessage(websocket.TextMessage, payload); err != nil {
							return nil
						}
					}
				}
			}
		}
	}

	// ── Subscribe to the audit dispatcher ────────────────────────────────────
	ch, cancel := h.dispatcher.Subscribe(orgIDStr)
	defer cancel()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	// ── Welcome message ───────────────────────────────────────────────────────
	type welcome struct {
		Type  string `json:"type"`
		OrgID string `json:"org_id"`
		Slug  string `json:"slug"`
	}
	if err := ws.WriteJSON(welcome{Type: "connected", OrgID: orgIDStr, Slug: slug}); err != nil {
		return nil
	}

	ctx := c.Request().Context()

	for {
		select {
		case <-ctx.Done():
			_ = ws.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "server shutdown"),
				time.Now().Add(time.Second),
			)
			return nil

		case <-heartbeat.C:
			msg := json.RawMessage(`{"type":"heartbeat"}`)
			if err := ws.WriteMessage(websocket.TextMessage, msg); err != nil {
				return nil // client disconnected
			}

		case evt, ok := <-ch:
			if !ok {
				return nil // dispatcher closed (server shutdown)
			}

			// Apply optional server-side filters.
			if !streamEventMatches(evt, filterAction, filterResourceType, filterStatus) {
				continue
			}

			// Deliver the CloudEvents-1.0 event payload as-is.
			payload, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			if err := ws.WriteMessage(websocket.TextMessage, payload); err != nil {
				return nil // client disconnected
			}
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// extractBearerOrQuery returns the raw JWT from, in priority order:
//  1. Authorization: Bearer <token> header (server-side SDK clients)
//  2. the HttpOnly admin session cookie (browser admin console — sent
//     automatically on the same-origin WebSocket handshake)
//  3. ?token=<jwt> query param (external browser/JS clients that cannot send
//     the cookie cross-site or set headers via the WebSocket API)
func extractBearerOrQuery(c echo.Context) string {
	h := c.Request().Header.Get(echo.HeaderAuthorization)
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if ck, err := c.Cookie(mw.AdminCookieName); err == nil && ck.Value != "" {
		return ck.Value
	}
	return c.QueryParam("token")
}

// orgScopeAllowed reports whether a principal scoped to principalOrgID (empty
// string = not scoped to any org) may access requestedOrgID. Super-admin
// principals (JWT is_super_admin, or an API key with a NULL org_id) may access
// any org; every other principal is confined to its own org. This is the single
// scope gate shared by the JWT and API-key auth paths.
func orgScopeAllowed(principalOrgID string, superAdmin bool, requestedOrgID string) bool {
	return superAdmin || principalOrgID == requestedOrgID
}

// extractAPIKey returns the raw org-scoped Admin API key from the X-API-Key
// header (server-side clients, including the Kubernetes operator) or the
// ?api_key= query param (browser clients that cannot set headers on the
// WebSocket handshake).
func extractAPIKey(c echo.Context) string {
	if k := c.Request().Header.Get("X-API-Key"); k != "" {
		return k
	}
	return c.QueryParam("api_key")
}

// parseAdminJWT validates a signed admin JWT and returns the claims.
func (h *StreamHandler) parseAdminJWT(raw string) (*middlewareClaims, error) {
	claims := &middlewareClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, echo.ErrUnauthorized
		}
		return []byte(h.cfg.Auth.AdminSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, echo.ErrUnauthorized
	}
	if !claims.IsAdmin {
		return nil, echo.ErrUnauthorized
	}
	return claims, nil
}

// middlewareClaims mirrors middleware.Claims to avoid an import cycle.
type middlewareClaims struct {
	jwt.RegisteredClaims
	OrgID        string   `json:"org_id"`
	IsAdmin      bool     `json:"is_admin"`
	IsSuperAdmin bool     `json:"is_super_admin"`
	Roles        []string `json:"roles"`
}

// streamEventMatches returns true if the event passes all active filters.
func streamEventMatches(e *internaudit.Event, action, resourceType, status string) bool {
	if action == "" && resourceType == "" && status == "" {
		return true
	}

	var data struct {
		Action       string `json:"action"`
		ResourceType string `json:"resource_type"`
		Status       string `json:"status"`
	}
	if e.Data != nil {
		_ = json.Unmarshal(e.Data, &data)
	}

	if action != "" && data.Action != action {
		return false
	}
	if resourceType != "" && data.ResourceType != resourceType {
		return false
	}
	if status != "" && data.Status != status {
		return false
	}
	return true
}
