package handler

// AIHandler provides AI-assisted features powered by the org-configured Anthropic API key.
//
// Endpoints (all scoped under /api/v1/organizations/:org_id/ai):
//
//   GET  /ai/config                     — check whether an API key is configured
//   PUT  /ai/config                     — set or clear the Anthropic API key
//   POST /ai/suggest-policy             — NL → structured auth-flow policy JSON
//   POST /ai/suggest-fga-model          — NL → OpenFGA 1.1 authorization model JSON
//   POST /ai/explain-anomaly            — risk signals → NL explanation (NIS2 Art.21)
//   POST /ai/nl-audit-query             — NL → audit query results (structured filters)
//   POST /ai/audit-copilot              — NL → SQL → audit results + compliance interpretation
//   POST /ai/explain-error              — OAuth2/OIDC error code → plain-language explanation
//   POST /ai/suggest-access-review      — campaign items → pre-filled keep/revoke decisions
//   POST /ai/suggest-lifecycle-rule     — NL → JML lifecycle rule JSON
//   POST /ai/suggest-dpia               — processing activity → GDPR Art.35 DPIA draft
//   POST /ai/suggest-dcql               — NL → OID4VP DCQL query (eIDAS 2 credential verifier)
//   POST /ai/explain-conformance        — OIDF test failure log → spec violation + Go fix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// AIHandler holds dependencies for all AI assistant endpoints.
type AIHandler struct {
	orgs   *repository.OrgRepository
	audit  *repository.AuditRepository
	arRepo *repository.AccessReviewRepository
	users  *repository.UserRepository
	groups *repository.GroupRepository
	pam    *repository.PAMRepository
	pool   *pgxpool.Pool // for audit copilot raw SQL execution
}

// NewAIHandler creates an AIHandler.
func NewAIHandler(pool *pgxpool.Pool) *AIHandler {
	return &AIHandler{
		orgs:   repository.NewOrgRepository(pool),
		audit:  repository.NewAuditRepository(pool),
		arRepo: repository.NewAccessReviewRepository(pool),
		users:  repository.NewUserRepository(pool),
		groups: repository.NewGroupRepository(pool),
		pam:    repository.NewPAMRepository(pool),
		pool:   pool,
	}
}

// ── Key config ────────────────────────────────────────────────────────────────

// GetAIConfig returns whether an Anthropic API key is configured for the org.
//
//	GET /api/v1/organizations/:org_id/ai/config
func (h *AIHandler) GetAIConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	key, err := h.orgs.GetAIKey(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]any{
		"configured": key != nil && *key != "",
	})
}

// UpsertAIConfig sets or clears the Anthropic API key for the org.
//
//	PUT /api/v1/organizations/:org_id/ai/config
//
// Body: { "anthropic_api_key": "sk-ant-..." }  — pass null or "" to clear.
func (h *AIHandler) UpsertAIConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Key *string `json:"anthropic_api_key"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	// Normalise: treat empty string as nil.
	key := req.Key
	if key != nil && *key == "" {
		key = nil
	}
	if key != nil && !strings.HasPrefix(*key, "sk-ant-") {
		return echo.NewHTTPError(http.StatusBadRequest, "anthropic_api_key must start with 'sk-ant-'")
	}
	if err := h.orgs.SetAIKey(c.Request().Context(), orgID, key); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]any{"configured": key != nil})
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// aiClient returns an Anthropic client using the org's configured key.
// Returns (nil, echo error) if the key is not configured.
func (h *AIHandler) aiClient(ctx context.Context, orgID uuid.UUID) (*anthropic.Client, error) {
	key, err := h.orgs.GetAIKey(ctx, orgID)
	if err != nil || key == nil || *key == "" {
		return nil, echo.NewHTTPError(http.StatusUnprocessableEntity,
			"AI features require an Anthropic API key. Configure it via PUT /ai/config.")
	}
	client := anthropic.NewClient(option.WithAPIKey(*key))
	return &client, nil
}

// ask sends a single message to Claude and returns the full text response.
// systemPrompt is set as the top-level system parameter (supports prompt caching).
func ask(ctx context.Context, client *anthropic.Client, systemPrompt, userMsg string, maxTokens int64) (string, error) {
	msg, err := client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeOpus4_7,
		MaxTokens: maxTokens,
		System: []anthropic.TextBlockParam{
			{
				Type: "text",
				Text: systemPrompt,
				CacheControl: anthropic.CacheControlEphemeralParam{
					Type: "ephemeral",
				},
			},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("anthropic: %w", err)
	}
	for _, block := range msg.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			return tb.Text, nil
		}
	}
	return "", fmt.Errorf("anthropic: no text block in response")
}

// langInstruction returns an instruction to respond in the requested language.
// It is appended to the system prompt when lang is a recognised BCP-47 tag.
// An empty string or "en" returns "" (no extra instruction needed).
func langInstruction(lang string) string {
	names := map[string]string{
		"it": "Italian", "fr": "French", "de": "German",
		"es": "Spanish", "pt": "Portuguese", "nl": "Dutch",
		"pl": "Polish", "sv": "Swedish", "da": "Danish",
		"fi": "Finnish", "nb": "Norwegian", "cs": "Czech",
		"ro": "Romanian", "hu": "Hungarian", "sk": "Slovak",
	}
	if name, ok := names[strings.ToLower(lang)]; ok {
		return "\n\nRespond in " + name + "."
	}
	return ""
}

// extractJSON extracts the first JSON object or array from a response that may
// contain markdown fences (```json ... ```) or plain JSON.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	// Strip ```json ... ``` fences.
	if idx := strings.Index(s, "```json"); idx >= 0 {
		s = s[idx+7:]
		if end := strings.Index(s, "```"); end >= 0 {
			s = s[:end]
		}
	} else if idx := strings.Index(s, "```"); idx >= 0 {
		s = s[idx+3:]
		if end := strings.Index(s, "```"); end >= 0 {
			s = s[:end]
		}
	}
	return strings.TrimSpace(s)
}

// ── suggest-policy ────────────────────────────────────────────────────────────

const suggestPolicySystem = `You are an identity platform policy engine expert.
Convert natural language access control requirements into a Clavex auth-flow policy JSON object.

Output ONLY valid JSON — no markdown, no explanation, no wrapper text.

The JSON must conform to this schema:
{
  "rules": [
    {
      "name": "<string>",
      "priority": <int — lower = evaluated first>,
      "enabled": true,
      "action": "allow" | "deny" | "require_mfa",
      "conditions": {
        "ip_cidr":          ["<CIDR>", ...],            // optional
        "country":          ["<ISO-3166-1-alpha-2>", ...], // optional — allowlist
        "country_not":      ["<ISO-3166-1-alpha-2>", ...], // optional — denylist
        "client_id":        ["<client-id>", ...],        // optional
        "mfa_enrolled":     true | false,                // optional
        "new_country":      true | false,                // optional
        "day_of_week":      ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"], // optional
        "hour_range":       { "from": 0, "to": 23 },     // optional — UTC inclusive
        "last_login_before":"<Go duration, e.g. '720h'>" // optional
      }
    }
  ]
}

Conditions are ANDed. A rule with empty conditions {} matches all requests.
Produce the minimum set of rules needed to express the requirement.`

// SuggestPolicy converts a natural-language description into a Clavex auth-flow policy JSON.
//
//	POST /api/v1/organizations/:org_id/ai/suggest-policy
//
// Body: { "description": "Block logins from Russia and China; require MFA for admin users." }
func (h *AIHandler) SuggestPolicy(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Description string `json:"description"`
		Lang        string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Description) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "description is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	raw, err := ask(c.Request().Context(), client, suggestPolicySystem+langInstruction(req.Lang), req.Description, 4096)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: suggest-policy")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var policy json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &policy); err != nil {
		// Return as text so the caller can see the raw model output for debugging.
		return c.JSON(http.StatusOK, map[string]any{
			"raw":   raw,
			"error": "model returned non-JSON; review and adjust the description",
		})
	}
	return c.JSON(http.StatusOK, map[string]any{"policy": policy})
}

// ── suggest-fga-model ─────────────────────────────────────────────────────────

const suggestFGAModelSystem = `You are an OpenFGA (Google Zanzibar) authorization model expert.
Convert natural language access control requirements into a valid OpenFGA 1.1 authorization model JSON.

Output ONLY valid JSON — no markdown, no explanation.

The JSON must conform to OpenFGA authorization model schema version 1.1:
{
  "schema_version": "1.1",
  "type_definitions": [
    {
      "type": "<type-name>",
      "relations": {
        "<relation-name>": {
          "this": {},          // direct assignment
          // OR:
          "union": { "child": [...] },
          "intersection": { "child": [...] },
          "difference": { "base": {...}, "subtract": {...} },
          "computedUserset": { "relation": "<other-relation>" },
          "tupleToUserset": { "tupleset": { "relation": "<rel>" }, "computedUserset": { "relation": "<rel>" } }
        }
      },
      "metadata": {
        "relations": {
          "<relation-name>": {
            "directly_related_user_types": [{ "type": "<type>" }]
          }
        }
      }
    }
  ]
}

Produce a complete, minimal model. Always include a "user" type definition.`

// SuggestFGAModel converts a natural language description into an OpenFGA 1.1 authorization model.
//
//	POST /api/v1/organizations/:org_id/ai/suggest-fga-model
//
// Body: { "description": "A document system where owners can read/write, editors can write, viewers can only read." }
func (h *AIHandler) SuggestFGAModel(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Description string `json:"description"`
		Lang        string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Description) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "description is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	raw, err := ask(c.Request().Context(), client, suggestFGAModelSystem+langInstruction(req.Lang), req.Description, 8192)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: suggest-fga-model")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var model json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &model); err != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"raw":   raw,
			"error": "model returned non-JSON; review and adjust the description",
		})
	}
	return c.JSON(http.StatusOK, map[string]any{"model": model})
}

// ── explain-anomaly ───────────────────────────────────────────────────────────

const explainAnomalySystem = `You are a cybersecurity analyst writing incident reports for NIS2 Art.21 compliance.
Given a set of risk signals from an identity platform login attempt, produce:
1. A concise risk summary (1-2 sentences) suitable for a security alert email.
2. A detailed NIS2-ready explanation (3-5 sentences) describing the anomaly, its context, potential impact, and recommended action.
3. A suggested action: "allow", "require_mfa", or "block".

Output as JSON:
{
  "summary": "<one-liner>",
  "explanation": "<detailed text>",
  "suggested_action": "allow" | "require_mfa" | "block",
  "confidence": "low" | "medium" | "high"
}`

// ExplainAnomaly converts risk signals into a NL explanation suitable for NIS2 reporting.
//
//	POST /api/v1/organizations/:org_id/ai/explain-anomaly
//
// Body: { "signals": { "risk_score": 85, "country": "RU", "new_country": true, "user_email": "alice@example.com", ... } }
func (h *AIHandler) ExplainAnomaly(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Signals map[string]any `json:"signals"`
		Lang    string         `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || len(req.Signals) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "signals object is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	signalsJSON, _ := json.Marshal(req.Signals)
	userMsg := fmt.Sprintf("Risk signals from login attempt:\n%s", string(signalsJSON))

	raw, err := ask(c.Request().Context(), client, explainAnomalySystem+langInstruction(req.Lang), userMsg, 2048)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: explain-anomaly")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var result json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &result); err != nil {
		return c.JSON(http.StatusOK, map[string]any{"explanation": raw})
	}
	return c.JSON(http.StatusOK, result)
}

// ── nl-audit-query ────────────────────────────────────────────────────────────

const nlAuditQuerySystemTemplate = `You are an audit log query assistant for an identity platform.
Given a natural language query, extract structured filter parameters for the audit log API.

Output ONLY valid JSON — no markdown, no explanation:
{
  "action":        "<exact action string or prefix>",
  "action_prefix": true | false,
  "resource_type": "<resource type string>",
  "resource_id":   "<resource UUID or identifier>",
  "actor_id":      "<user UUID>",
  "status":        "success" | "failure",
  "since":         "<RFC3339 datetime>",
  "until":         "<RFC3339 datetime>",
  "limit":         <int, max 500>
}

Only include fields that the query explicitly asks for. Omit all others.
For relative times (e.g. "last 7 days", "yesterday"), compute RFC3339 assuming current time is %s.
Common action prefixes: "user.", "client.", "session.", "token.", "org.", "scim.", "mfa.", "policy."
Common action values: "user.login", "user.login.failure", "user.logout", "user.created", "user.deleted", "client.created", "mfa.enrolled", "password.reset"`

func nlAuditQuerySystem() string {
	return fmt.Sprintf(nlAuditQuerySystemTemplate, time.Now().UTC().Format(time.RFC3339))
}

// NLAuditQuery converts a natural-language question into an audit log query and returns results.
//
//	POST /api/v1/organizations/:org_id/ai/nl-audit-query
//
// Body: { "query": "show me all failed logins from the last 24 hours" }
func (h *AIHandler) NLAuditQuery(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Query string `json:"query"`
		Lang  string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Query) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "query is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	raw, err := ask(c.Request().Context(), client, nlAuditQuerySystem()+langInstruction(req.Lang), req.Query, 1024)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: nl-audit-query")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var params struct {
		Action       string  `json:"action"`
		ActionPrefix bool    `json:"action_prefix"`
		ResourceType string  `json:"resource_type"`
		ResourceID   string  `json:"resource_id"`
		ActorID      string  `json:"actor_id"`
		Status       string  `json:"status"`
		Since        string  `json:"since"`
		Until        string  `json:"until"`
		Limit        int     `json:"limit"`
	}
	if err := json.Unmarshal([]byte(extractJSON(raw)), &params); err != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"raw_query_params": raw,
			"error":            "could not parse AI filter params; showing raw output",
		})
	}

	f := repository.AuditFilter{
		OrgID:        orgID,
		ResourceType: params.ResourceType,
		ResourceID:   params.ResourceID,
		ActorID:      params.ActorID,
		Status:       params.Status,
		Limit:        params.Limit,
	}
	if params.ActionPrefix {
		f.ActionPrefix = params.Action
	} else {
		f.Action = params.Action
	}
	if params.Since != "" {
		if t, err := time.Parse(time.RFC3339, params.Since); err == nil {
			f.Since = &t
		}
	}
	if params.Until != "" {
		if t, err := time.Parse(time.RFC3339, params.Until); err == nil {
			f.Until = &t
		}
	}

	ctx := c.Request().Context()
	page, err := h.audit.List(ctx, f)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]any{
		"nl_query":       req.Query,
		"applied_filter": f,
		"results":        page,
	})
}

// ── suggest-access-review ─────────────────────────────────────────────────────

const suggestAccessReviewSystem = `You are an access certification assistant for an identity governance platform.
Given a list of user-role assignments pending review in an access certification campaign, suggest a decision for each item.

Base your decisions on:
- Whether the role name suggests it's a high-privilege role (admin, owner, superuser → scrutinise more)
- How recently the user's access was last used (if last_login_at is far in the past or absent → suggest revoke)
- Whether the assignment looks anomalous (service accounts with human-style names, etc.)

Output ONLY valid JSON array — no markdown, no explanation:
[
  {
    "item_id": "<UUID>",
    "suggestion": "keep" | "revoke",
    "reason": "<one-sentence rationale>"
  }
]`

// SuggestAccessReview returns AI-pre-filled keep/revoke suggestions for a campaign's pending items.
//
//	POST /api/v1/organizations/:org_id/ai/suggest-access-review
//
// Body: { "campaign_id": "<uuid>" }
func (h *AIHandler) SuggestAccessReview(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		CampaignID string `json:"campaign_id"`
		Lang       string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "campaign_id is required")
	}
	campaignID, err := uuid.Parse(req.CampaignID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "campaign_id must be a valid UUID")
	}

	ctx := c.Request().Context()
	items, err := h.arRepo.ListItems(ctx, campaignID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	// Filter to pending items only.
	pending := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if item.Decision != "pending" {
			continue
		}
		// Only pass safe, anonymised fields to the model — no secrets.
		entry := map[string]any{
			"item_id":   item.ID.String(),
			"user_name": item.UserName,
			"role_name": item.RoleName,
			"org_id":    orgID.String(),
		}
		// Include last_login_at if available via user lookup — omit if not.
		pending = append(pending, entry)
	}

	if len(pending) == 0 {
		return c.JSON(http.StatusOK, map[string]any{
			"suggestions": []any{},
			"message":     "No pending items to review.",
		})
	}

	client, err := h.aiClient(ctx, orgID)
	if err != nil {
		return err
	}

	itemsJSON, _ := json.Marshal(pending)
	userMsg := fmt.Sprintf("Pending access review items for campaign %s:\n%s", req.CampaignID, string(itemsJSON))

	raw, err := ask(ctx, client, suggestAccessReviewSystem+langInstruction(req.Lang), userMsg, 8192)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: suggest-access-review")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var suggestions json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &suggestions); err != nil {
		return c.JSON(http.StatusOK, map[string]any{"raw": raw})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"campaign_id":  req.CampaignID,
		"item_count":   len(pending),
		"suggestions":  suggestions,
	})
}

// ── suggest-lifecycle-rule ────────────────────────────────────────────────────

const suggestLifecycleSystem = `You are a JML (Joiner/Mover/Leaver) lifecycle automation expert for an identity platform.
Convert a natural language description into a structured Clavex lifecycle rule JSON.

Output ONLY valid JSON — no markdown, no explanation:
{
  "name": "<rule name>",
  "description": "<optional description>",
  "trigger": "user.created" | "user.updated" | "user.deactivated" | "user.activated" | "user.deleted" | "scim.user.provisioned" | "scim.user.deprovisioned",
  "is_active": true,
  "conditions": [
    {
      "field": "<user field: department, title, email, is_active, metadata.*>",
      "op": "eq" | "neq" | "contains" | "starts_with" | "ends_with" | "exists" | "not_exists",
      "value": "<string value>"
    }
  ],
  "actions": [
    {
      "type": "assign_role" | "remove_role" | "assign_group" | "remove_group" | "deactivate_user" | "send_email" | "webhook",
      "role_id":   "<UUID — for assign_role/remove_role>",
      "group_id":  "<UUID — for assign_group/remove_group>",
      "url":       "<URL — for webhook>",
      "template":  "<email template name — for send_email>"
    }
  ]
}`

// SuggestLifecycleRule converts a natural language description into a JML lifecycle rule.
//
//	POST /api/v1/organizations/:org_id/ai/suggest-lifecycle-rule
//
// Body: { "description": "When a new user joins the Engineering department, assign them to the Dev group and give them the Developer role." }
func (h *AIHandler) SuggestLifecycleRule(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Description string `json:"description"`
		Lang        string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Description) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "description is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	raw, err := ask(c.Request().Context(), client, suggestLifecycleSystem+langInstruction(req.Lang), req.Description, 4096)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: suggest-lifecycle-rule")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var rule json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &rule); err != nil {
		return c.JSON(http.StatusOK, map[string]any{"raw": raw, "error": "non-JSON output"})
	}
	return c.JSON(http.StatusOK, map[string]any{"rule": rule})
}

// ── suggest-dpia ──────────────────────────────────────────────────────────────

const suggestDPIASystem = `You are a GDPR Data Protection Officer assistant.
Given a description of a data processing activity, produce a GDPR Art.35 Data Protection Impact Assessment (DPIA) draft.

Output a structured JSON document:
{
  "title": "<DPIA title>",
  "processing_activity": "<one-paragraph description>",
  "purposes": ["<purpose 1>", ...],
  "legal_basis": "<Art.6 / Art.9 GDPR legal basis>",
  "data_categories": ["<category>", ...],
  "data_subjects": ["<category of data subjects>", ...],
  "recipients": ["<who receives the data>", ...],
  "retention_period": "<how long data is kept>",
  "transfers_outside_eu": true | false,
  "transfer_safeguards": "<SCCs / adequacy decision / etc. — if applicable>",
  "necessity_proportionality": "<assessment of whether processing is necessary and proportionate>",
  "risks": [
    {
      "risk": "<risk description>",
      "likelihood": "low" | "medium" | "high",
      "severity": "low" | "medium" | "high",
      "mitigation": "<proposed mitigation>"
    }
  ],
  "residual_risk": "low" | "medium" | "high",
  "dpo_consultation_required": true | false,
  "supervisory_authority_consultation": true | false,
  "technical_measures": ["<measure>", ...],
  "organisational_measures": ["<measure>", ...],
  "review_date": "<ISO 8601 date — typically 1 year from now>",
  "status": "draft"
}`

// SuggestDPIA generates a GDPR Art.35 DPIA draft from a processing activity description.
//
//	POST /api/v1/organizations/:org_id/ai/suggest-dpia
//
// Body: { "description": "We process employee biometric data for time-and-attendance using facial recognition..." }
func (h *AIHandler) SuggestDPIA(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Description string `json:"description"`
		Lang        string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Description) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "description is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	raw, err := ask(c.Request().Context(), client, suggestDPIASystem+langInstruction(req.Lang), req.Description, 8192)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: suggest-dpia")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var dpia json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &dpia); err != nil {
		return c.JSON(http.StatusOK, map[string]any{"raw": raw})
	}
	return c.JSON(http.StatusOK, map[string]any{"dpia": dpia})
}

// ── suggest-dcql ─────────────────────────────────────────────────────────────

// suggestDCQLSystem is the system prompt for the NL → DCQL generator.
// DCQL (Digital Credentials Query Language) is defined in OID4VP 1.0 Final §6.
// It is the preferred alternative to Presentation Exchange for eIDAS 2 / ARF 1.4 wallets.
const suggestDCQLSystem = `You are an expert in OID4VP (OpenID for Verifiable Presentations) and eIDAS 2.0 / EUDIW ARF 1.4.
Convert a natural language verifier requirement into a valid DCQL query object (OID4VP §6).

Output ONLY valid JSON — no markdown, no explanation, no wrapper text.

DCQL top-level structure:
{
  "credentials": [
    {
      "id":     "<snake_case identifier, unique within this query>",
      "format": "vc+sd-jwt" | "mso_mdoc" | "jwt_vc_json",
      "meta":   { "vct_values": ["<vct URI>"] },           // for vc+sd-jwt
      // or  { "doctype_value": "<mdoc doctype>" },         // for mso_mdoc
      "claims": [
        {
          "id":        "<snake_case claim id>",
          "path":      ["<namespace>", "<element>"],       // for mso_mdoc
          // or  "path": ["<claim name>"],                  // for vc+sd-jwt
          "values":    ["<exact match value>"],             // optional — filter by value
          "namespace": "<mdoc namespace>"                   // only for mso_mdoc
        }
      ]
    }
  ],
  "credential_sets": [                                     // OPTIONAL — logical AND/OR of credentials
    {
      "options": [["<credential_id>"], ["<alt1>", "<alt2>"]],
      "required": true                                     // default true
    }
  ]
}

Known credential types and their claims:

## EU PID (Person Identification Data) — vct: "https://example.bmi.bund.de/credential/pid/1.0"
SD-JWT-VC claims: given_name, family_name, birth_date, birth_place, nationality, address,
  age_in_years, age_over_18, age_over_21, resident_country, document_number,
  issuance_date, expiry_date, issuing_country, issuing_authority

## Italian PID (SPID / CIE) — vct: "https://idserver.servizicie.interno.gov.it/vc/pid/1.0"
or vct: "urn:eu.europa.ec.eudi.pid.1"
SD-JWT-VC claims: given_name, family_name, birth_date, fiscal_code, birth_place,
  age_in_years, age_over_18, age_over_21, resident_address, document_number,
  expiry_date, issuing_country, issuing_authority

## ISO 18013-5 mDL (Mobile Driving Licence) — doctype: "org.iso.18013.5.1.mDL"
Namespace: "org.iso.18013.5.1" — elements: family_name, given_name, birth_date, issue_date,
  expiry_date, issuing_country, issuing_authority, document_number, portrait,
  driving_privileges, age_in_years, age_over_18, age_over_21, sex, nationality,
  resident_address, weight, height, eye_colour, hair_colour, birth_place

## IT mDL (Italy) — doctype: "org.iso.18013.5.1.mDL" (same namespace)

## EUDI QEAA (Qualified Electronic Attestation of Attributes)
  Various VCT URIs per member state

Constraints guidance:
- To require minimum age: use claim "age_over_18" / "age_over_21" with values: [true]
  (preferred) OR "age_in_years" — do NOT put a numeric filter directly on birth_date
- For nationality/issuing_country filtering (e.g. "Italian only"): use issuing_country values: ["IT"]
- For document validity: add expiry_date to claims but do NOT add values — the wallet verifies expiry itself
- Prefer vc+sd-jwt over mso_mdoc unless the requirement specifically mentions mDL or driving licence
- Omit credential_sets when only one credential type is required
- "id" values must be snake_case ASCII (e.g. "italian_pid", "eu_mdl")

Examples:
1. "accept only Italian driving licences with age ≥ 21"
   → format mso_mdoc, doctype org.iso.18013.5.1.mDL, claims: age_over_21 values:[true], issuing_country values:["IT"]

2. "verify that the holder is an EU citizen over 18"
   → format vc+sd-jwt, vct EU PID, claims: age_over_18 values:[true], issuing_country values:["AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU","IE","IT","LV","LT","LU","MT","NL","PL","PT","RO","SK","SI","ES","SE"]

3. "accept SPID or CIE PID from Italy, need name and fiscal code"
   → format vc+sd-jwt, vct Italian PID, claims: given_name, family_name, fiscal_code, issuing_country values:["IT"]
`

// SuggestDCQL converts a natural language verifier requirement into an OID4VP DCQL query.
//
//	POST /api/v1/organizations/:org_id/ai/suggest-dcql
//
// Body: { "description": "voglio accettare solo patenti italiane valide con età > 21" }
func (h *AIHandler) SuggestDCQL(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Description string `json:"description"`
		Lang        string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Description) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "description is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	raw, err := ask(c.Request().Context(), client, suggestDCQLSystem+langInstruction(req.Lang), req.Description, 4096)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: suggest-dcql")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var dcql json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &dcql); err != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"raw":   raw,
			"error": "model returned non-JSON; review and adjust the description",
		})
	}
	return c.JSON(http.StatusOK, map[string]any{"dcql_query": dcql})
}

// ── explain-error ─────────────────────────────────────────────────────────────

const explainErrorSystem = `You are an expert in identity protocols: OAuth 2.0 (RFC 6749, RFC 6750, RFC 7636, RFC 9126),
OpenID Connect (Core, Discovery, FAPI 1.0/2.0), OID4VCI, OID4VP, SAML 2.0, and SCIM 2.0.

A developer received an error from an OAuth2/OIDC/identity API endpoint and needs your help.

Given an error code and optional context (which endpoint, what flow, raw error description), produce:
1. A clear plain-English explanation of what the error means
2. The most likely root cause given the context
3. Concrete steps to fix it
4. Relevant spec references (RFC number and section)

Output ONLY valid JSON — no markdown, no preamble:
{
  "code": "<the error code>",
  "explanation": "<1-2 sentence plain English explanation>",
  "likely_cause": "<most probable root cause given the context, 1-2 sentences>",
  "how_to_fix": ["<step 1>", "<step 2>", ...],
  "references": ["RFC 6749 §5.2", "RFC 9126 §2.3", ...]
}`

// ExplainError explains an OAuth2/OIDC error code in natural language.
//
//	POST /api/v1/organizations/:org_id/ai/explain-error
//
// Body: { "code": "invalid_request", "context": "PAR endpoint", "description": "...", "lang": "en" }
func (h *AIHandler) ExplainError(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Code        string `json:"code"`
		Context     string `json:"context"`
		Description string `json:"description"`
		Lang        string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "code is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	userMsg := fmt.Sprintf("Error code: %s", req.Code)
	if req.Context != "" {
		userMsg += "\nContext: " + req.Context
	}
	if req.Description != "" {
		userMsg += "\nRaw error description: " + req.Description
	}

	raw, err := ask(c.Request().Context(), client, explainErrorSystem+langInstruction(req.Lang), userMsg, 2048)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: explain-error")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var result json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &result); err != nil {
		return c.JSON(http.StatusOK, map[string]any{"raw": raw})
	}
	return c.JSON(http.StatusOK, result)
}

// ── audit-copilot ─────────────────────────────────────────────────────────────

// auditCopilotSystemTpl is the system prompt template for the audit copilot.
// It is formatted with: (1) current UTC time, (2) org context JSON.
// The prompt caching breakpoint is set on the static schema section so that the
// per-request org context refreshes on each call while the schema stays cached.
const auditCopilotSystemTpl = `You are an expert compliance and security analyst for an identity platform.
You have a tool called run_audit_query that executes a read-only PostgreSQL SELECT query against the audit database.

Use it to answer the user's compliance question. If the query fails, correct the SQL and try again (max 3 attempts total).
After retrieving results, provide a concise compliance interpretation for a CISO or auditor: who did what, when, anomalies, risk level, and recommended action.

── DATABASE SCHEMA ─────────────────────────────────────────────────────────────

PRIMARY TABLE: audit_logs
  id (bigserial), event_id (text), org_id (uuid), actor_email (text), action (text),
  resource_type (text), resource_id (text), status ('success'|'failure'),
  ip_address (inet), user_agent (text), country_code (char(2)),
  session_id (text), request_id (text), metadata (jsonb), created_at (timestamptz)

Action prefixes: user. | client. | session. | token. | org. | scim. | mfa. | policy. | pam.
Key actions: user.login, user.login.failure, user.logout, user.created, user.deleted,
  client.created, mfa.enrolled, password.reset,
  pam.access.requested, pam.access.approved, pam.access.denied,
  pam.session.started, pam.session.ended, pam.break_glass.activated

RELATED TABLES (all scoped to org_id):
  pam_access_requests: id, org_id, user_id (uuid), resource_type, resource_id, resource_name,
    status (pending/approved/denied/expired), approved_by (uuid), created_at, updated_at
  pam_sessions: id, org_id, user_id (uuid), request_id (→pam_access_requests.id),
    started_at (timestamptz), ended_at (timestamptz), status
  users: id (uuid), org_id (uuid), email (text), display_name (text),
    is_active (bool), created_at (timestamptz), last_login_at (timestamptz)
  groups: id (uuid), org_id (uuid), name (text)
  group_members: group_id (uuid), user_id (uuid)
  roles: id (uuid), org_id (uuid), name (text)
  user_roles: user_id (uuid), role_id (uuid), org_id (uuid)

SQL RULES:
  - Always filter by org_id = $1  ($1 is the org UUID, the only allowed parameter)
  - SELECT only — no INSERT/UPDATE/DELETE/DROP/TRUNCATE/CREATE/ALTER/GRANT
  - Default LIMIT 200 unless the user asks for a different count

── ORG CONTEXT ──────────────────────────────────────────────────────────────────

Current UTC time: %s

This organisation's known entities (use to write precise queries):
%s`

// AuditCopilot handles POST /api/v1/organizations/:org_id/ai/audit-copilot.
// Accepts a natural language compliance question, gathers full org context (users, roles,
// groups, PAM resources), and uses Claude tool-use to iteratively generate and execute
// read-only SQL against the audit database — returning results with a compliance interpretation.
func (h *AIHandler) AuditCopilot(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Query   string `json:"query"`
		Context string `json:"context"` // optional extra context
		Lang    string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Query) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "query is required")
	}

	ctx := c.Request().Context()
	client, err := h.aiClient(ctx, orgID)
	if err != nil {
		return err
	}

	result, err := h.RunAuditCopilot(ctx, orgID, req.Query, req.Context, req.Lang, client)
	if err != nil {
		if he, ok := err.(*echo.HTTPError); ok {
			return he
		}
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, result)
}

// AuditCopilotResult is the structured response from the audit copilot.
type AuditCopilotResult struct {
	Query          string           `json:"query"`
	GeneratedSQL   string           `json:"generated_sql"`
	Columns        []string         `json:"columns"`
	Results        []map[string]any `json:"results"`
	RowCount       int              `json:"row_count"`
	Interpretation string           `json:"interpretation"`
	SQLAttempts    int              `json:"sql_attempts"`
}

// RunAuditCopilot is the core logic shared by AuditCopilot (HTTP handler) and the MCP tool.
// It fetches org context, then runs a Claude tool-use loop (≤ maxSQLAttempts) to generate
// and execute a validated read-only SQL query, returning structured results.
func (h *AIHandler) RunAuditCopilot(
	ctx context.Context,
	orgID uuid.UUID,
	query, extraContext, lang string,
	client *anthropic.Client,
) (*AuditCopilotResult, error) {
	const maxSQLAttempts = 3

	// 1. Fetch org context in parallel.
	orgCtx, err := h.fetchOrgContext(ctx, orgID)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: audit-copilot fetch-context")
		// Non-fatal: continue with empty context rather than failing.
		orgCtx = "{}"
	}

	// 2. Build system prompt with schema + org context (org context section is NOT cached —
	//    it changes per org; the schema section IS marked for caching).
	systemPrompt := fmt.Sprintf(auditCopilotSystemTpl, time.Now().UTC().Format(time.RFC3339), orgCtx)
	if lang != "" {
		systemPrompt += langInstruction(lang)
	}

	// 3. Define the run_audit_query tool.
	auditTool := anthropic.ToolUnionParam{
		OfTool: &anthropic.ToolParam{
			Name:        "run_audit_query",
			Description: param.NewOpt("Execute a read-only PostgreSQL SELECT against the audit database. Returns column names and result rows as JSON. The query MUST use $1 as the org_id parameter."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{
					"sql": map[string]any{
						"type":        "string",
						"description": "A valid PostgreSQL SELECT statement. Must contain $1 (org_id filter). No DDL or DML permitted.",
					},
				},
				Required: []string{"sql"},
			},
			CacheControl: anthropic.CacheControlEphemeralParam{Type: "ephemeral"},
		},
	}

	// 4. Build initial user message.
	userMsg := query
	if extraContext != "" {
		userMsg += "\n\nAdditional context:\n" + extraContext
	}

	messages := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg)),
	}

	// 5. Tool-use agentic loop.
	var (
		lastSQL     string
		lastColumns []string
		lastResults []map[string]any
		attempts    int
		finalText   string
	)

	for attempts < maxSQLAttempts {
		msg, err := client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     anthropic.ModelClaudeOpus4_7,
			MaxTokens: 4096,
			System: []anthropic.TextBlockParam{
				{
					Type: "text",
					Text: systemPrompt,
					CacheControl: anthropic.CacheControlEphemeralParam{
						Type: "ephemeral",
					},
				},
			},
			Tools:      []anthropic.ToolUnionParam{auditTool},
			ToolChoice: anthropic.ToolChoiceUnionParam{OfAuto: &anthropic.ToolChoiceAutoParam{}},
			Messages:   messages,
		})
		if err != nil {
			log.Error().Err(err).Str("org_id", orgID.String()).Int("attempt", attempts).Msg("ai: audit-copilot claude")
			return nil, echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
		}

		if msg.StopReason == anthropic.StopReasonEndTurn {
			// Extract final text response.
			for _, block := range msg.Content {
				if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
					finalText = tb.Text
				}
			}
			break
		}

		if msg.StopReason != anthropic.StopReasonToolUse {
			break
		}

		// Add the assistant's tool-use turn to the conversation.
		assistantBlocks := make([]anthropic.ContentBlockParamUnion, 0, len(msg.Content))
		var toolResults []anthropic.ContentBlockParamUnion

		for _, block := range msg.Content {
			switch v := block.AsAny().(type) {
			case anthropic.TextBlock:
				assistantBlocks = append(assistantBlocks, anthropic.NewTextBlock(v.Text))
			case anthropic.ToolUseBlock:
				assistantBlocks = append(assistantBlocks, anthropic.NewToolUseBlock(v.ID, v.Input, v.Name))

				if v.Name != "run_audit_query" {
					toolResults = append(toolResults, anthropic.NewToolResultBlock(v.ID, "unknown tool", true))
					continue
				}
				attempts++

				// Parse the SQL from tool input.
				var toolInput struct {
					SQL string `json:"sql"`
				}
				if jsonErr := json.Unmarshal(v.Input, &toolInput); jsonErr != nil {
					toolResults = append(toolResults, anthropic.NewToolResultBlock(v.ID, "invalid tool input: "+jsonErr.Error(), true))
					continue
				}
				lastSQL = strings.TrimSpace(toolInput.SQL)

				// Validate SQL safety.
				if valErr := validateAuditSQL(lastSQL); valErr != nil {
					toolResults = append(toolResults, anthropic.NewToolResultBlock(v.ID, "SQL validation error: "+valErr.Error(), true))
					continue
				}

				// Execute query.
				cols, rows, execErr := h.executeAuditSQL(ctx, lastSQL, orgID)
				if execErr != nil {
					log.Warn().Err(execErr).Str("sql", lastSQL).Msg("ai: audit-copilot exec")
					toolResults = append(toolResults, anthropic.NewToolResultBlock(v.ID, "query execution error: "+execErr.Error(), true))
					continue
				}
				lastColumns = cols
				lastResults = rows

				// Return results as JSON to Claude.
				resultPayload := map[string]any{
					"columns":   cols,
					"rows":      rows,
					"row_count": len(rows),
				}
				resultJSON, _ := json.Marshal(resultPayload)
				toolResults = append(toolResults, anthropic.NewToolResultBlock(v.ID, string(resultJSON), false))
			}
		}

		messages = append(messages,
			anthropic.NewAssistantMessage(assistantBlocks...),
			anthropic.NewUserMessage(toolResults...),
		)
	}

	// 6. If Claude never produced a text interpretation (e.g. hit max attempts), synthesise one.
	if finalText == "" {
		if len(lastResults) > 0 {
			finalText = fmt.Sprintf("Query returned %d rows. Review the results above.", len(lastResults))
		} else if lastSQL != "" {
			finalText = "The query executed successfully but returned no results."
		} else {
			finalText = "Could not generate a valid query for this request."
		}
	}

	return &AuditCopilotResult{
		Query:          query,
		GeneratedSQL:   lastSQL,
		Columns:        lastColumns,
		Results:        lastResults,
		RowCount:       len(lastResults),
		Interpretation: finalText,
		SQLAttempts:    attempts,
	}, nil
}

// orgContextSummary holds light-weight org entity data injected into the system prompt.
type orgContextSummary struct {
	Users    []map[string]any `json:"users,omitempty"`
	Roles    []map[string]any `json:"roles,omitempty"`
	Groups   []map[string]any `json:"groups,omitempty"`
	PAMCreds []map[string]any `json:"pam_credentials,omitempty"`
}

// fetchOrgContext fetches users, roles, groups, and PAM credentials for an org in parallel.
// Returns a compact JSON string for inclusion in the system prompt.
func (h *AIHandler) fetchOrgContext(ctx context.Context, orgID uuid.UUID) (string, error) {
	var (
		mu      sync.Mutex
		summary orgContextSummary
		wg      sync.WaitGroup
	)

	fetch := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				log.Warn().Err(err).Str("fetch", name).Str("org_id", orgID.String()).Msg("ai: audit-copilot context fetch")
			}
		}()
	}

	fetch("users", func() error {
		users, err := h.users.ListByOrg(ctx, orgID)
		if err != nil {
			return err
		}
		items := make([]map[string]any, 0, min(len(users), 200))
		for _, u := range users {
			if len(items) >= 200 {
				break
			}
			entry := map[string]any{"id": u.ID.String(), "email": u.Email, "is_active": u.IsActive}
			if u.LastLoginAt != nil {
				entry["last_login_at"] = u.LastLoginAt.Format(time.RFC3339)
			}
			items = append(items, entry)
		}
		mu.Lock()
		summary.Users = items
		mu.Unlock()
		return nil
	})

	fetch("roles", func() error {
		roles, err := h.users.ListRoles(ctx, orgID)
		if err != nil {
			return err
		}
		items := make([]map[string]any, 0, len(roles))
		for _, r := range roles {
			items = append(items, map[string]any{"id": r.ID.String(), "name": r.Name})
		}
		mu.Lock()
		summary.Roles = items
		mu.Unlock()
		return nil
	})

	fetch("groups", func() error {
		groups, err := h.groups.ListByOrg(ctx, orgID)
		if err != nil {
			return err
		}
		items := make([]map[string]any, 0, len(groups))
		for _, g := range groups {
			items = append(items, map[string]any{"id": g.ID.String(), "name": g.Name, "member_count": g.MemberCount})
		}
		mu.Lock()
		summary.Groups = items
		mu.Unlock()
		return nil
	})

	fetch("pam_creds", func() error {
		creds, err := h.pam.ListCredentials(ctx, orgID)
		if err != nil {
			return err
		}
		items := make([]map[string]any, 0, min(len(creds), 50))
		for _, c := range creds {
			if len(items) >= 50 {
				break
			}
			entry := map[string]any{"id": c.ID.String(), "name": c.Name, "type": c.CredentialType, "is_active": c.IsActive}
			if c.TargetHost != nil {
				entry["target_host"] = *c.TargetHost
			}
			items = append(items, entry)
		}
		mu.Lock()
		summary.PAMCreds = items
		mu.Unlock()
		return nil
	})

	wg.Wait()

	b, err := json.Marshal(summary)
	if err != nil {
		return "{}", err
	}
	return string(b), nil
}

// validateAuditSQL checks that the generated SQL is a safe read-only SELECT.
func validateAuditSQL(sql string) error {
	upper := strings.ToUpper(strings.TrimSpace(sql))
	if !strings.HasPrefix(upper, "SELECT") {
		return fmt.Errorf("only SELECT queries are allowed")
	}
	for _, kw := range []string{"DROP ", "DELETE ", "UPDATE ", "INSERT ", "TRUNCATE ", "ALTER ", "CREATE ", "GRANT ", "REVOKE "} {
		if strings.Contains(upper, kw) {
			return fmt.Errorf("query contains forbidden keyword: %s", strings.TrimSpace(kw))
		}
	}
	if !strings.Contains(upper, "$1") {
		return fmt.Errorf("query must filter by org_id using $1 parameter")
	}
	return nil
}

// ── explain-conformance ───────────────────────────────────────────────────────

const explainConformanceSystem = `You are an expert in OpenID Foundation (OIDF) conformance testing and the following specifications:
- OID4VCI Final (2024) — OpenID for Verifiable Credential Issuance
- OID4VP Draft/Final — OpenID for Verifiable Presentations
- HAIP — High Assurance Interoperability Profile (HAIP for SD-JWT VC)
- SD-JWT VC (draft-ietf-oauth-sd-jwt-vc)
- ISO/IEC 18013-5 (mDL / mdoc)
- RFC 6749, RFC 9126 (PAR), RFC 7636 (PKCE), RFC 9449 (DPoP)
- eIDAS 2.0 / EUDIW ARF 1.4

A developer gave you a JSON log from a failed OIDF conformance test. Analyse it and produce:
1. Which specification section was violated (precise: "OID4VCI Final §11.2", "HAIP §5.4", etc.)
2. A plain English explanation of what went wrong
3. A concrete Go fix: the file, function name, approximate line (if detectable from error details), and a code snippet

Output ONLY valid JSON — no markdown, no preamble:
{
  "test_name":      "<test name / id from the log>",
  "result":         "failed" | "skipped" | "warning",
  "spec_violation": "<spec name and section — e.g. OID4VCI Final §11.2>",
  "explanation":    "<1-3 sentence plain explanation of the failure>",
  "fix": {
    "description":  "<what must change and why>",
    "file":         "<relative Go file path — e.g. internal/handler/oidc.go>",
    "function":     "<Go function or method name>",
    "line_hint":    "<approximate line number or empty string>",
    "code_snippet": "<suggested Go code change — can be multi-line>"
  },
  "references": ["<spec §section>", ...]
}

If you cannot determine the Go file/function from the log alone, leave those fields as empty strings and focus on the spec violation and description.
If the test is skipped (not a real failure), set result to "skipped" and explain why it was skipped and what needs to be implemented.`

// ExplainConformanceFailure analyses an OIDF test failure log and returns the violated spec
// section plus a concrete Go fix suggestion.
//
//	POST /api/v1/organizations/:org_id/ai/explain-conformance
//
// Body: { "test_log": { ...OIDF JSON log... }, "suite": "oidf|haip", "lang": "en" }
func (h *AIHandler) ExplainConformanceFailure(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		TestLog json.RawMessage `json:"test_log"`
		Suite   string          `json:"suite"`
		Lang    string          `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || len(req.TestLog) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "test_log is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	userMsg := "OIDF conformance test failure log:\n" + string(req.TestLog)
	if req.Suite != "" {
		userMsg = "Test suite: " + req.Suite + "\n\n" + userMsg
	}

	raw, err := ask(c.Request().Context(), client, explainConformanceSystem+langInstruction(req.Lang), userMsg, 4096)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: explain-conformance")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var result json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &result); err != nil {
		return c.JSON(http.StatusOK, map[string]any{"raw": raw})
	}
	return c.JSON(http.StatusOK, result)
}

// executeAuditSQL runs a validated SELECT query in a read-only transaction scoped to org_id ($1).
func (h *AIHandler) executeAuditSQL(ctx context.Context, sql string, orgID uuid.UUID) (columns []string, results []map[string]any, err error) {
	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	rows, err := tx.Query(ctx, sql, orgID)
	if err != nil {
		return nil, nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	fds := rows.FieldDescriptions()
	columns = make([]string, len(fds))
	for i, fd := range fds {
		columns[i] = string(fd.Name)
	}

	for rows.Next() {
		vals, scanErr := rows.Values()
		if scanErr != nil {
			return nil, nil, fmt.Errorf("scan: %w", scanErr)
		}
		row := make(map[string]any, len(columns))
		for i, col := range columns {
			v := vals[i]
			// Convert [16]byte (pgx UUID representation) to string.
			if b, ok := v.([16]byte); ok {
				if u, uErr := uuid.FromBytes(b[:]); uErr == nil {
					v = u.String()
				}
			}
			row[col] = v
		}
		results = append(results, row)
	}
	return columns, results, rows.Err()
}

// ── suggest-credential-schema ─────────────────────────────────────────────────

const suggestCredentialSchemaSystem = `You are a world-class expert in:
- W3C Verifiable Credentials and SD-JWT-VC (draft-ietf-oauth-sd-jwt-vc)
- OID4VCI Final and OID4VP 1.0 Final
- eIDAS 2.0 Architecture Reference Framework (ARF) and EUDIW
- Italian digital identity: SPID, CIE 3.0, IT-Wallet, codice fiscale
- GDPR (Reg. EU 2016/679) — especially Art.5(1)(c) data minimisation, Art.8 (minors), Art.9 (special categories)
- Credential schema design for wallets (Apple Wallet, Google Wallet, EUDI reference wallet)

Given a natural-language description of a Verifiable Credential type to issue, produce a
complete, production-ready credential configuration for the Clavex platform.

Output ONLY a single JSON object — no markdown fences, no explanation outside the JSON.

## Required output shape

{
  "vct": "<HTTPS URI — pattern: https://{issuer}/credentials/{kebab-slug}/1>",
  "display_name": "<concise human-readable name, ≤50 chars>",
  "description": "<one sentence describing the credential purpose>",
  "category": "<identity|training|qualification|badge>",
  "credential_format": "<vc+sd-jwt|mso_mdoc>",
  "ttl_seconds": <int — see TTL rules below>,
  "selective_disclosure": <bool>,
  "source_idp_type": "<spid|cie|null>",
  "schema_fields": [
    {"name": "<snake_case>", "label": "<label in the issuer's locale>", "type": "<string|date|number|url>", "mandatory": <bool>}
  ],
  "claims_mapping": {
    "<schema_field_name>": "<SPID/CIE attribute name or 'manual'>"
  },
  "adaptive_ttl": <bool>,
  "min_ttl_seconds": <int>,
  "max_ttl_seconds": <int>,
  "renewal_threshold": <float 0.0–1.0>,
  "inactivity_revoke_days": <int>,
  "dcql_query": {
    "credentials": [
      {
        "id": "<kebab-slug>",
        "format": "<vc+sd-jwt|mso_mdoc>",
        "meta": {"vct_values": ["<vct>"]},
        "claims": [{"path": ["<claim_name>"]}]
      }
    ]
  },
  "sd_policy": "<paragraph: which claims are individually disclosable and why>",
  "gdpr_notes": "<1-3 sentences: GDPR Art.5(1)(c) minimisation analysis; call out Art.8 for minors or Art.9 for special categories>",
  "wallet_dev_docs": "<Markdown documentation for wallet developers — include: ## Overview, ## Claims (markdown table: Claim | Type | Mandatory | Description), ## Selective Disclosure, ## Verification (DCQL), ## Example>",
  "rationale": "<2-3 sentences explaining format, TTL and SD choices>"
}

## SPID attribute names (use in claims_mapping when source_idp_type = 'spid')
name, familyName, dateOfBirth, placeOfBirth, countyOfBirth, fiscalNumber,
email, mobilePhone, address, digitalAddress, ivaCode, idCard

## CIE 3.0 attribute names (use in claims_mapping when source_idp_type = 'cie')
given_name, family_name, birth_date, birth_place, fiscal_code, address,
email, mobile_phone, document_number, expiry_date, portrait

## TTL rules
- badge (event attendance, one-time): 15_778_800 (6 months)
- training certificate: 31_536_000 (1 year)
- qualification / professional licence: 94_608_000 (3 years)
- identity document: 157_680_000 (5 years)
- medical / fitness certificate: 31_536_000 (1 year); adaptive_ttl=true

## Minimisation rules (strict)
1. Include ONLY claims strictly necessary for the stated purpose — no extras.
2. For age-gating, prefer age_over_18 (or age_over_N) over full date_of_birth.
3. For minors: note GDPR Art.8 in gdpr_notes; avoid fiscal_code unless legally required.
4. Biometric claims (portrait, fingerprint_template): note GDPR Art.9(1) in gdpr_notes.
5. If fiscal_code is needed, note in gdpr_notes that this is a unique national identifier.

## Format selection
- mso_mdoc: driving licences (org.iso.18013.5.1.mDL), travel documents — and ONLY these.
- vc+sd-jwt: everything else.

## Selective disclosure
- selective_disclosure: true for all credentials that contain more than two claims.
- The dcql_query MUST request only the minimum claims needed for verification — not all schema_fields.

## Adaptive TTL
- adaptive_ttl: true for: identity, qualification, medical/fitness credentials.
- adaptive_ttl: false for: one-time badges, event certificates.
- When adaptive_ttl=true: min_ttl_seconds=604800 (7d), renewal_threshold=0.8,
  inactivity_revoke_days appropriate for the credential type.

## VCT placeholder
Use the literal string {issuer} as a placeholder — the platform will substitute the actual issuer URL.
Example: "https://{issuer}/credentials/idoneita-sportiva/1"`

// SuggestCredentialSchema generates a complete production-ready credential configuration
// from a natural-language description.
//
//	POST /api/v1/organizations/:org_id/ai/suggest-credential-schema
//
//nolint:misspell // Body: { "description": "voglio emettere un certificato di idoneità sportiva per atleti minorenni", "lang": "it" } 
//
// Response: full credential schema JSON ready to review, edit, and POST to /oid4vci/configs.
func (h *AIHandler) SuggestCredentialSchema(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Description string `json:"description"`
		Lang        string `json:"lang"`
	}
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Description) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "description is required")
	}

	client, err := h.aiClient(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	raw, err := ask(c.Request().Context(), client,
		suggestCredentialSchemaSystem+langInstruction(req.Lang),
		req.Description, 8192)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("ai: suggest-credential-schema")
		return echo.NewHTTPError(http.StatusBadGateway, "AI request failed")
	}

	var schema json.RawMessage
	if err := json.Unmarshal([]byte(extractJSON(raw)), &schema); err != nil {
		// Return the raw text so the frontend can still display it.
		return c.JSON(http.StatusOK, map[string]any{
			"raw":   raw,
			"error": "model returned non-JSON; review and adjust the description",
		})
	}
	return c.JSON(http.StatusOK, schema)
}

