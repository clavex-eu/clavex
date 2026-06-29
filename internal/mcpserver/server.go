// Package mcpserver implements a Model Context Protocol (MCP) server over HTTP.
//
// It exposes the clavex_audit_copilot tool so that MCP-compatible AI clients
// (Claude.ai, Cursor, etc.) can query the Clavex audit database using natural language.
//
// Transport: stateless streamable HTTP (POST /api/v1/organizations/:org_id/mcp)
// Auth:      same Bearer JWT / admin API key as all other org-scoped endpoints
//
// Protocol reference: https://modelcontextprotocol.io/specification
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/clavex-eu/clavex/internal/handler"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ── MCP JSON-RPC 2.0 wire types ──────────────────────────────────────────────

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	errCodeParse          = -32700
	errCodeInvalidRequest = -32600
	errCodeMethodNotFound = -32601
	errCodeInvalidParams  = -32602
	errCodeInternal       = -32603
)

// ── Tool schemas ──────────────────────────────────────────────────────────────

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

var tools = []mcpTool{
	{
		Name: "clavex_audit_copilot",
		Description: "Query the Clavex identity platform audit database in natural language. " +
			"Automatically generates and executes a read-only SQL query with full org context " +
			"(users, roles, groups, PAM resources). Returns results and a compliance interpretation " +
			"for CISOs and auditors.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"org_id": map[string]any{
					"type":        "string",
					"format":      "uuid",
					"description": "UUID of the organisation to query.",
				},
				"query": map[string]any{
					"type":        "string",
					"description": "Natural language compliance question, e.g. 'Show all PAM access requests to production resources in the last 48h from users not in the approved group.'",
				},
				"context": map[string]any{
					"type":        "string",
					"description": "Optional extra context such as approved user lists or resource names.",
				},
				"lang": map[string]any{
					"type":        "string",
					"description": "BCP-47 language tag for the interpretation (e.g. 'it', 'fr'). Defaults to English.",
				},
			},
			"required": []string{"org_id", "query"},
		},
	},
	{
		Name: "clavex_identity_advisor",
		Description: "Generate an AI-powered weekly identity risk report for an organisation. " +
			"Analyses login anomalies (unusual countries, Tor/malicious IPs), admin hygiene " +
			"(admins without MFA), OAuth2 client security (wildcard redirect URIs), conformance " +
			"score, and NIS2 policy drift. Returns a structured CISO-level executive summary " +
			"with the top-5 prioritised risks and concrete remediation actions. " +
			"Requires an Anthropic API key configured for the organisation.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"org_id": map[string]any{
					"type":        "string",
					"format":      "uuid",
					"description": "UUID of the organisation to analyse.",
				},
				"period_days": map[string]any{
					"type":        "integer",
					"description": "Analysis window in days. Default: 7.",
					"minimum":     1,
					"maximum":     90,
				},
			},
			"required": []string{"org_id"},
		},
	},
}

// ── Handler ───────────────────────────────────────────────────────────────────

// Handler handles MCP JSON-RPC 2.0 requests.
// Handler handles MCP JSON-RPC 2.0 requests.
type Handler struct {
	orgs    *repository.OrgRepository
	aiH     *handler.AIHandler
	pool    *pgxpool.Pool
}

// New creates a new MCP Handler.
func New(pool *pgxpool.Pool) *Handler {
	return &Handler{
		orgs: repository.NewOrgRepository(pool),
		aiH:  handler.NewAIHandler(pool),
		pool: pool,
	}
}

// Handle is the echo handler for POST /api/v1/organizations/:org_id/mcp.
//
//	POST /api/v1/organizations/:org_id/mcp
func (h *Handler) Handle(c echo.Context) error {
	var req jsonRPCRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusOK, errorResp(nil, errCodeParse, "parse error"))
	}
	if req.JSONRPC != "2.0" {
		return c.JSON(http.StatusOK, errorResp(req.ID, errCodeInvalidRequest, "jsonrpc must be '2.0'"))
	}

	ctx := c.Request().Context()

	switch req.Method {
	case "initialize": //nolint:misspell // MCP protocol method name — must match spec verbatim
		return c.JSON(http.StatusOK, okResp(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]any{
				"name":    "clavex-mcp",
				"version": "1.0.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		}))

	case "tools/list":
		return c.JSON(http.StatusOK, okResp(req.ID, map[string]any{
			"tools": tools,
		}))

	case "tools/call":
		return h.handleToolCall(c, ctx, req)

	default:
		return c.JSON(http.StatusOK, errorResp(req.ID, errCodeMethodNotFound,
			fmt.Sprintf("method not found: %s", req.Method)))
	}
}

func (h *Handler) handleToolCall(c echo.Context, ctx context.Context, req jsonRPCRequest) error {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return c.JSON(http.StatusOK, errorResp(req.ID, errCodeInvalidParams, "invalid params"))
	}

	switch params.Name {
	case "clavex_audit_copilot":
		return h.callAuditCopilot(c, ctx, req.ID, params.Arguments)
	case "clavex_identity_advisor":
		return h.callIdentityAdvisor(c, ctx, req.ID, params.Arguments)
	default:
		return c.JSON(http.StatusOK, errorResp(req.ID, errCodeMethodNotFound,
			fmt.Sprintf("unknown tool: %s", params.Name)))
	}
}

func (h *Handler) callAuditCopilot(c echo.Context, ctx context.Context, id json.RawMessage, args map[string]any) error {
	orgIDStr, _ := args["org_id"].(string)
	query, _ := args["query"].(string)
	extraContext, _ := args["context"].(string)
	lang, _ := args["lang"].(string)

	if orgIDStr == "" || query == "" {
		return c.JSON(http.StatusOK, errorResp(id, errCodeInvalidParams, "org_id and query are required"))
	}

	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return c.JSON(http.StatusOK, errorResp(id, errCodeInvalidParams, "org_id must be a valid UUID"))
	}

	// Fetch the org's Anthropic API key.
	apiKey, err := h.orgs.GetAIKey(ctx, orgID)
	if err != nil || apiKey == nil || *apiKey == "" {
		return c.JSON(http.StatusOK, errorResp(id, errCodeInternal,
			"AI features require an Anthropic API key configured for this organisation"))
	}
	client := anthropic.NewClient(option.WithAPIKey(*apiKey))

	result, err := h.aiH.RunAuditCopilot(ctx, orgID, query, extraContext, lang, &client)
	if err != nil {
		return c.JSON(http.StatusOK, errorResp(id, errCodeInternal, err.Error()))
	}

	// MCP tool result format.
	return c.JSON(http.StatusOK, okResp(id, map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": fmt.Sprintf(
					"**Compliance Query Results**\n\n**Question:** %s\n\n**SQL:** ```sql\n%s\n```\n\n**Rows returned:** %d\n\n**Interpretation:**\n%s",
					result.Query, result.GeneratedSQL, result.RowCount, result.Interpretation,
				),
			},
			{
				"type": "text",
				"text": jsonMarshalPretty(map[string]any{
					"columns":  result.Columns,
					"results":  result.Results,
					"metadata": map[string]any{"sql_attempts": result.SQLAttempts},
				}),
			},
		},
	}))
}

// callIdentityAdvisor implements the clavex_identity_advisor MCP tool.
// It gathers security signals for the requested org+period and asks Claude
// to produce a prioritised CISO-level risk report on the fly.
func (h *Handler) callIdentityAdvisor(c echo.Context, ctx context.Context, id json.RawMessage, args map[string]any) error {
	orgIDStr, _ := args["org_id"].(string)
	if orgIDStr == "" {
		return c.JSON(http.StatusOK, errorResp(id, errCodeInvalidParams, "org_id is required"))
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return c.JSON(http.StatusOK, errorResp(id, errCodeInvalidParams, "org_id must be a valid UUID"))
	}

	periodDays := 7
	if pd, ok := args["period_days"].(float64); ok && pd > 0 {
		periodDays = int(pd)
		if periodDays > 90 {
			periodDays = 90
		}
	}

	report, signals, err := worker.GenerateAdvisorReport(ctx, h.pool, orgID, periodDays)
	if err != nil {
		return c.JSON(http.StatusOK, errorResp(id, errCodeInternal, err.Error()))
	}

	statsText := fmt.Sprintf(
		"**Signals collected** — Period: past %d days | Logins: %d | Failed: %d | "+
			"Malicious IPs: %d | Tor exits: %d | Unusual countries: %d | "+
			"Admins without MFA: %d | Wildcard redirect clients: %d",
		periodDays,
		signals.TotalLogins, signals.FailedLogins,
		signals.MaliciousIPLogins, signals.TorExitLogins,
		len(signals.UnusualCountries),
		len(signals.AdminsWithoutMFA),
		len(signals.WildcardRedirectClients),
	)

	return c.JSON(http.StatusOK, okResp(id, map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": statsText},
			{"type": "text", "text": report},
		},
	}))
}

// ── helpers ───────────────────────────────────────────────────────────────────

func okResp(id json.RawMessage, result any) jsonRPCResponse {
	return jsonRPCResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func errorResp(id json.RawMessage, code int, msg string) jsonRPCResponse {
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: msg},
	}
}

func jsonMarshalPretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
