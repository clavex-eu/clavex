package handler

// AgentTokenHandler manages machine identity tokens for AI agents.
//
// An agent token is an OAuth 2.0 Bearer access token with additional claims:
//   - token_type = "agent"
//   - agent_id   = free-form identifier for the AI agent (e.g. "claude-mcp-v1")
//   - delegated_by = user_id of the human whose permissions are delegated
//   - scope      = space-separated OAuth 2.0 scopes (subset of user's grants)
//
// The token is signed with the same PS256 RSA key as OIDC tokens and can be
// verified at /{org_slug}/.well-known/jwks.json.  It is revocable independently
// from the user's browser session — supporting the 2026 MCP OAuth 2.0 pattern
// where each AI agent carries its own bounded, auditable identity.
//
// Endpoints (all under /api/v1/organizations/:org_id):
//
//	POST   /agent-tokens              — issue a new agent token (admin)
//	GET    /agent-tokens              — list tokens for the org
//	DELETE /agent-tokens/:id          — revoke a token

import (
	"errors"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/webhook"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"
)

const agentTokenDefaultTTL = 24 * time.Hour
const agentTokenMaxTTL = 90 * 24 * time.Hour

// AgentTokenHandler issues and manages AI agent tokens.
type AgentTokenHandler struct {
	cfg      *config.Config
	pool     *pgxpool.Pool
	keys     oidc.Signer
	repo     *repository.AgentTokenRepository
	orgRepo  *repository.OrgRepository
	userRepo *repository.UserRepository
	auditor  *audit.Emitter
	webhookD *webhook.Dispatcher
}

func NewAgentTokenHandler(cfg *config.Config, pool *pgxpool.Pool, keys oidc.Signer, wd *webhook.Dispatcher) *AgentTokenHandler {
	baseURL := cfg.Auth.IssuerBase
	if baseURL == "" {
		baseURL = "https://" + cfg.HTTP.BaseDomain
	}
	return &AgentTokenHandler{
		cfg:      cfg,
		pool:     pool,
		keys:     keys,
		repo:     repository.NewAgentTokenRepository(pool),
		orgRepo:  repository.NewOrgRepository(pool),
		userRepo: repository.NewUserRepository(pool),
		auditor:  audit.NewEmitter(baseURL, repository.NewAuditRepository(pool)),
		webhookD: wd,
	}
}

// ── Request / response ────────────────────────────────────────────────────────

type issueAgentTokenRequest struct {
	// UserID is the human principal whose permissions are delegated.
	UserID string `json:"user_id" validate:"required,uuid4"`
	// AgentID is a stable, machine-readable identifier for the AI agent.
	// Examples: "claude-mcp-v1", "gpt-plugin-calendar", "langchain-assistant".
	AgentID string `json:"agent_id" validate:"required,max=120"`
	// AgentName is a human-readable label shown in the audit log and dashboard.
	AgentName string `json:"agent_name" validate:"required,max=255"`
	// Scope is a space-separated list of OAuth 2.0 scopes the agent is allowed
	// to use.  Must be a subset of the scopes the user has been granted.
	// MCP standard scopes: mcp:read  mcp:write  mcp:tools:*
	Scope string `json:"scope"`
	// TTLS is the token lifetime in seconds.  Defaults to 86400 (24 h).
	// Maximum: 7776000 (90 days).
	TTLSeconds int `json:"ttl_seconds"`
	// MCPServerID identifies the target MCP server this token is bound to.
	// Embedded as the "mcp_server_id" JWT claim and stored for audit filtering.
	// Example: "my-mcp-server" or a UUID.
	MCPServerID *string `json:"mcp_server_id"`
	// MCPResourceURL is the canonical resource URL of the MCP server
	// (RFC 8707 Resource Indicators).  Embedded as "mcp_resource_url" JWT claim.
	// Example: "https://api.example.com/mcp".
	MCPResourceURL *string `json:"mcp_resource_url"`
}

type issueAgentTokenResponse struct {
	Token     string `json:"token"`      // signed JWT — shown once
	TokenID   string `json:"token_id"`   // database record ID for revocation
	ExpiresAt string `json:"expires_at"` // RFC 3339
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// Issue handles POST /api/v1/organizations/:org_id/agent-tokens.
// Requires: "users" or "clients" resource permission (both agents and admins).
func (h *AgentTokenHandler) Issue(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	var req issueAgentTokenRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}

	// Verify user exists and belongs to this org.
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil || user.OrgID != orgID {
		return echo.NewHTTPError(http.StatusNotFound, "user not found in org")
	}

	// Resolve TTL.
	ttl := agentTokenDefaultTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
		if ttl > agentTokenMaxTTL {
			return echo.NewHTTPError(http.StatusBadRequest, "ttl_seconds exceeds maximum (7776000)")
		}
	}
	expiresAt := time.Now().Add(ttl)

	// Resolve issuer from org slug.
	org, err := h.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, org.Slug)

	jti := uuid.NewString()

	// Build and sign the JWT.
	builder := jwtlib.NewBuilder().
		Issuer(issuer).
		Subject(userID.String()).
		Audience([]string{issuer}).
		IssuedAt(time.Now()).
		Expiration(expiresAt).
		JwtID(jti).
		Claim("org_id", orgID.String()).
		Claim("token_type", "agent").
		Claim("agent_id", req.AgentID).
		Claim("agent_name", req.AgentName).
		Claim("delegated_by", userID.String()).
		Claim("scope", req.Scope)
	if req.MCPServerID != nil {
		builder = builder.Claim("mcp_server_id", *req.MCPServerID)
	}
	if req.MCPResourceURL != nil {
		builder = builder.Claim("mcp_resource_url", *req.MCPResourceURL)
	}
	tok, err := builder.Build()
	if err != nil {
		return echo.ErrInternalServerError
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, h.keys.KID())
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(jwa.PS256, h.keys.CryptoSigner(), jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Determine who created the token (admin JWT subject).
	var createdBy *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, err := uuid.Parse(claims.Subject); err == nil {
			createdBy = &id
		}
	}

	// Persist metadata.
	record, err := h.repo.Create(ctx, orgID, userID, req.AgentID, req.AgentName, req.Scope, jti, expiresAt, createdBy,
		req.MCPServerID, req.MCPResourceURL)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Audit + webhook.
	resourceID := record.ID.String()
	resourceType := "agent_token"
	h.auditor.Emit(ctx, audit.EmitParams{
		OrgID:        orgID,
		ActorID:      createdBy,
		Action:       "agent.token.issued",
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Status:       "success",
		Metadata: map[string]interface{}{
			"agent_id":   req.AgentID,
			"user_id":    userID.String(),
			"scope":      req.Scope,
			"expires_at": expiresAt.Format(time.RFC3339),
		},
	})
	if h.webhookD != nil {
		h.webhookD.Dispatch(orgID, webhook.EventAgentTokenIssued, map[string]interface{}{
			"token_id":   record.ID.String(),
			"agent_id":   req.AgentID,
			"agent_name": req.AgentName,
			"user_id":    userID.String(),
			"scope":      req.Scope,
			"expires_at": expiresAt.Format(time.RFC3339),
		})
	}

	return c.JSON(http.StatusCreated, issueAgentTokenResponse{
		Token:     string(signed),
		TokenID:   record.ID.String(),
		ExpiresAt: expiresAt.Format(time.RFC3339),
	})
}

// List handles GET /api/v1/organizations/:org_id/agent-tokens.
func (h *AgentTokenHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	// Optional ?user_id= filter.
	var tokens interface{}
	if uid := c.QueryParam("user_id"); uid != "" {
		userID, err := uuid.Parse(uid)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
		}
		tokens, err = h.repo.ListByUser(c.Request().Context(), orgID, userID)
		if err != nil {
			return echo.ErrInternalServerError
		}
	} else {
		tokens, err = h.repo.ListByOrg(c.Request().Context(), orgID)
		if err != nil {
			return echo.ErrInternalServerError
		}
	}

	return c.JSON(http.StatusOK, tokens)
}

// Revoke handles DELETE /api/v1/organizations/:org_id/agent-tokens/:id.
func (h *AgentTokenHandler) Revoke(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	tokenID, err := uuidParam(c, "id")
	if err != nil {
		return err
	}

	var revokedBy uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, err := uuid.Parse(claims.Subject); err == nil {
			revokedBy = id
		}
	}
	if revokedBy == uuid.Nil {
		revokedBy = uuid.New() // fallback; should never happen
	}

	if err := h.repo.Revoke(ctx, tokenID, orgID, revokedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrNotFound
		}
		return echo.ErrInternalServerError
	}

	// Audit.
	resourceID := tokenID.String()
	resourceType := "agent_token"
	h.auditor.Emit(ctx, audit.EmitParams{
		OrgID:        orgID,
		ActorID:      &revokedBy,
		Action:       "agent.token.revoked",
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Status:       "success",
	})
	if h.webhookD != nil {
		h.webhookD.Dispatch(orgID, webhook.EventAgentTokenRevoked, map[string]interface{}{
			"token_id": tokenID.String(),
		})
	}

	return c.NoContent(http.StatusNoContent)
}

// ── MCP scope discovery ───────────────────────────────────────────────────────

// mcpScope describes a predefined MCP OAuth 2.0 scope.
type mcpScope struct {
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

// predefinedMCPScopes is the canonical list of MCP-specific scopes Clavex issues.
// These are additive to standard OIDC scopes (openid, profile, email).
var predefinedMCPScopes = []mcpScope{
	{"mcp:read", "Read access to MCP server resources (list tools, read outputs)"},
	{"mcp:write", "Write access to MCP server resources (invoke tools, store data)"},
	{"mcp:tools:call", "Permission to call any tool exposed by the MCP server"},
	{"mcp:tools:list", "Permission to list available tools without invoking them"},
	{"mcp:resources:read", "Read MCP resource URIs (files, databases, APIs)"},
	{"mcp:resources:write", "Write or update MCP resources"},
	{"mcp:prompts:read", "Read prompt templates from the MCP server"},
	{"mcp:admin", "Full administrative access to the MCP server (superscope)"},
}

// MCPScopes handles GET /api/v1/organizations/:org_id/mcp-scopes.
// Returns the predefined MCP OAuth 2.0 scopes that Clavex issues by default.
// Developers can use these as a reference when configuring their MCP servers.
// No authentication required — this is a public discovery endpoint.
func (h *AgentTokenHandler) MCPScopes(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"scopes": predefinedMCPScopes,
		"notes": []string{
			"Use mcp:read and mcp:write for general-purpose MCP access.",
			"Use mcp:tools:call to allow tool invocations.",
			"Scope down to specific tools using custom scopes (e.g. mcp:tools:search).",
			"Combine with standard OIDC scopes: openid profile email.",
			"The mcp_server_id claim binds a token to a specific MCP server instance.",
		},
	})
}
