// Package flowengine executes the configured login flow steps for an
// organization during the OIDC authentication interaction.
//
// Each step is a pre-built, no-code action block that the admin configures
// in the visual flow builder. The engine runs the steps in position order
// and returns a FlowResult indicating whether the login should proceed and
// any extra claims to inject into the id_token.
package flowengine

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/sms"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// OID4VPChallengeSpec carries the credential requirements emitted by an
// oid4vp_challenge step. The login handler uses this to create a presentation
// session and redirect the user to a wallet QR challenge page.
type OID4VPChallengeSpec struct {
	// DCQLQuery is the OID4VP 1.0 Final DCQL credential query (§6).
	// Either DCQLQuery or PresentationDefinition must be non-nil.
	DCQLQuery map[string]any `json:"dcql_query,omitempty"`
	// PresentationDefinition is the legacy Presentation Exchange v2 query.
	PresentationDefinition map[string]any `json:"presentation_definition,omitempty"`
	// Message is shown to the user on the challenge page.
	Message string `json:"message"`
}

// FlowResult is returned by Engine.Run.
type FlowResult struct {
	// Deny is true when a step blocked the login.
	Deny bool
	// DenyReason is a human-readable message for the login error page.
	DenyReason string
	// ForceMFA is true when a step (require_mfa / check_ip_risk) mandates step-up.
	ForceMFA bool
	// ExtraClaims carries claims injected by enrich_claims / set_claim steps.
	ExtraClaims map[string]any
	// StepUpURL, when non-empty, instructs the login handler to redirect the
	// user to a stronger identity provider instead of rendering a denial page.
	// The login_session_id query parameter is appended by the caller so that
	// the IdP callback can resume the original OIDC flow after re-authentication.
	StepUpURL string
	// UpgradeSPIDLevel, when > 0, requests an in-session SPID level upgrade.
	// The login handler saves this level in the LoginSession and redirects the
	// user to /:org_slug/spid/upgrade, which re-initiates SAML SSO against the
	// same IdP at the higher level while preserving all original OIDC context
	// (client_id, scope, state, nonce, PKCE, PAR request).
	// Values: 1=L1, 2=L2, 3=L3.
	UpgradeSPIDLevel int
	// UpgradeCIE, when true, requests an in-session CIE re-authentication.
	// The login handler sets RequiredCIEUpgrade in the LoginSession and redirects
	// the user to /:org_slug/cie/upgrade, which re-initiates the CIE OIDC flow
	// while preserving all original OIDC context. CIE is always eIDAS High.
	UpgradeCIE bool
	// ForceReauth, when true, requests that the OIDC handler redirect the client
	// with error=login_required instead of showing a denial page. Used by
	// check_session_age with action:"require_reauth" to enforce OIDC Core
	// §3.1.2.1 max_age-style session freshness.
	ForceReauth bool
	// OID4VPChallenge, when non-nil, pauses the login and requires the user's
	// wallet to present a verifiable credential matching the configured query
	// before the login can complete. The login handler creates a presentation
	// session, shows a QR challenge page, and resumes once verified.
	OID4VPChallenge *OID4VPChallengeSpec
}

// UserContext is the information about the authenticating user available to steps.
type UserContext struct {
	User      *models.User
	OrgSlug   string
	ClientID  string
	IPAddress string
	RiskScore int // 0-100; 0 if not computed
	// AuthTime is the Unix timestamp of the initial authentication (password check
	// or IdP callback). Used by check_session_age to enforce freshness.
	AuthTime int64
}

// Engine runs a login flow for a given user/client context.
type Engine struct {
	flows      *repository.LoginFlowRepository
	users      *repository.UserRepository
	mfaRepo    MFACounter
	orgsRepo   *repository.OrgRepository // for ai_decision: Anthropic key lookup
	devicesRepo *repository.DeviceFactsRepository // for check_device step
	actionsRunner ActionsRunner              // for run_action step
	auditEM    *audit.Emitter            // for ai_decision: NIS2 audit trail
	smtpRepo   *repository.SMTPRepository        // optional: for notify email step
	smsRepo    *repository.SMSSettingsRepository // optional: for notify sms step
	httpClient *http.Client
}

// MFACounter is the minimal MFA interface the engine needs.
type MFACounter interface {
	CountConfirmedByUser(ctx context.Context, userID uuid.UUID) (int, error)
}

// ActionsRunner is the minimal interface the engine needs for run_action steps.
type ActionsRunner interface {
	RunSync(ctx context.Context, orgID uuid.UUID, eventType string, data map[string]any) (deny bool, denyReason string, claims map[string]any)
}

func New(
	flows *repository.LoginFlowRepository,
	users *repository.UserRepository,
	mfa MFACounter,
) *Engine {
	return &Engine{
		flows:   flows,
		users:   users,
		mfaRepo: mfa,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// WithOrgRepository attaches the org repo so the ai_decision step can look up
// the Anthropic API key. Without this, ai_decision steps are skipped.
func (e *Engine) WithOrgRepository(r *repository.OrgRepository) *Engine {
	e.orgsRepo = r
	return e
}

// WithDeviceFactsRepository attaches the fleet device-facts repo so the
// check_device step can evaluate device posture conditions.
func (e *Engine) WithDeviceFactsRepository(r *repository.DeviceFactsRepository) *Engine {
	e.devicesRepo = r
	return e
}

// WithActionsRunner attaches an ActionsRunner so the run_action step can invoke
// external HTTP hooks synchronously during the login flow.
func (e *Engine) WithActionsRunner(r ActionsRunner) *Engine {
	e.actionsRunner = r
	return e
}

// WithAuditEmitter attaches an audit emitter so ai_decision decisions are
// written to the structured audit log (NIS2 Art.21 traceability).
func (e *Engine) WithAuditEmitter(em *audit.Emitter) *Engine {
	e.auditEM = em
	return e
}

// WithSMTPRepository attaches an SMTP repository so the notify step can send
// email notifications during the login flow.
func (e *Engine) WithSMTPRepository(r *repository.SMTPRepository) *Engine {
	e.smtpRepo = r
	return e
}

// WithSMSSettingsRepository attaches an SMS settings repository so the notify
// step can send SMS messages during the login flow.
func (e *Engine) WithSMSSettingsRepository(r *repository.SMSSettingsRepository) *Engine {
	e.smsRepo = r
	return e
}

// Run fetches the active flow for the client/org and executes each step.
// Returns a zero FlowResult (Deny=false) if no flow is configured.
func (e *Engine) Run(ctx context.Context, orgID uuid.UUID, uc UserContext) FlowResult {
	flow, err := e.flows.GetActiveForClient(ctx, orgID, uc.ClientID)
	if err != nil || flow == nil {
		return FlowResult{} // no flow configured — pass through
	}

	result := FlowResult{}
	for _, step := range flow.Steps {
		if !step.IsActive {
			continue
		}
		r := e.runStep(ctx, step, uc)
		if r.ForceMFA {
			result.ForceMFA = true
		}
		if r.Deny {
			return r // short-circuit on first denial
		}
		// oid4vp_challenge: interrupt the flow so the login handler can show a QR
		// challenge page. Extra claims collected by preceding steps are preserved.
		if r.OID4VPChallenge != nil {
			result.OID4VPChallenge = r.OID4VPChallenge
			return result
		}
		// Merge extra claims.
		for k, v := range r.ExtraClaims {
			if result.ExtraClaims == nil {
				result.ExtraClaims = map[string]any{}
			}
			result.ExtraClaims[k] = v
		}
	}
	return result
}

// runStep dispatches to the correct step handler.
func (e *Engine) runStep(ctx context.Context, step models.LoginFlowStep, uc UserContext) FlowResult {
	switch step.StepType {
	case "check_attribute":
		return e.stepCheckAttribute(step, uc)
	case "require_mfa":
		return e.stepRequireMFA(ctx, step, uc)
	case "block_if_no_mfa":
		return e.stepBlockIfNoMFA(ctx, step, uc)
	case "enrich_claims":
		return e.stepEnrichClaims(ctx, step, uc)
	case "set_claim":
		return e.stepSetClaim(step, uc)
	case "webhook":
		go e.stepWebhook(context.Background(), step, uc) // non-blocking
		return FlowResult{}
	case "notify":
		return e.stepNotify(ctx, step, uc)
	case "check_ip_risk":
		return e.stepCheckIPRisk(step, uc)
	case "require_email_verified":
		return e.stepRequireEmailVerified(step, uc)
	case "check_breach":
		return e.stepCheckBreach(step, uc)
	case "check_verified":
		return e.stepCheckVerified(step, uc)
	case "check_device":
		return e.stepCheckDevice(ctx, step, uc)
	case "run_action":
		return e.stepRunAction(ctx, step, uc)
	case "ai_decision":
		return e.stepAIDecision(ctx, step, uc)
	case "check_session_age":
		return e.stepCheckSessionAge(step, uc)
	case "oid4vp_challenge":
		return e.stepOID4VPChallenge(step)
	default:
		log.Warn().Str("step_type", step.StepType).Msg("flowengine: unknown step type — skipped")
		return FlowResult{}
	}
}

// ── Step implementations ──────────────────────────────────────────────────────

// check_attribute config:
//   {"field":"department","op":"eq","value":"blocked","action":"deny"}
//   action: "deny" | "allow_only" (deny if value does NOT match)
func (e *Engine) stepCheckAttribute(step models.LoginFlowStep, uc UserContext) FlowResult {
	var cfg struct {
		Field  string `json:"field"`
		Op     string `json:"op"`
		Value  string `json:"value"`
		Action string `json:"action"` // "deny" | "allow_only"
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil || cfg.Field == "" {
		return FlowResult{}
	}

	attrVal := resolveUserField(uc.User, cfg.Field)
	matches := evalOp(attrVal, cfg.Op, cfg.Value)

	switch cfg.Action {
	case "deny":
		if matches {
			return FlowResult{Deny: true, DenyReason: "Access denied by attribute check."}
		}
	case "allow_only":
		if !matches {
			return FlowResult{Deny: true, DenyReason: "Access not permitted for your profile."}
		}
	}
	return FlowResult{}
}

// require_mfa config:
//   {"methods":["totp","webauthn"]}
//   Forces MFA step-up; if the user has no enrolled MFA, denies login.
func (e *Engine) stepRequireMFA(ctx context.Context, step models.LoginFlowStep, uc UserContext) FlowResult {
	count, err := e.mfaRepo.CountConfirmedByUser(ctx, uc.User.ID)
	if err != nil {
		log.Warn().Err(err).Msg("flowengine: require_mfa CountConfirmedByUser failed")
		return FlowResult{}
	}
	if count == 0 {
		return FlowResult{Deny: true, DenyReason: "Multi-factor authentication is required but no MFA method is enrolled. Contact your administrator."}
	}
	return FlowResult{ForceMFA: true}
}

// block_if_no_mfa config: {} or {"message":"..."}
func (e *Engine) stepBlockIfNoMFA(ctx context.Context, step models.LoginFlowStep, uc UserContext) FlowResult {
	count, err := e.mfaRepo.CountConfirmedByUser(ctx, uc.User.ID)
	if err != nil {
		return FlowResult{}
	}
	if count == 0 {
		var cfg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(step.Config, &cfg)
		msg := cfg.Message
		if msg == "" {
			msg = "Login requires multi-factor authentication. Please enrol an MFA method."
		}
		return FlowResult{Deny: true, DenyReason: msg}
	}
	return FlowResult{}
}

// enrich_claims config:
//
//	{
//	  "url": "https://api.example.com/user-attributes",
//	  "method": "POST",
//	  "headers": {"X-API-Key": "secret"},
//	  "body_template": "{\"sub\":\"{{.Sub}}\",\"email\":\"{{.Email}}\"}",
//	  "claim_mappings": [{"source":"$.department","target":"department"}],
//	  "timeout_ms": 3000,
//	  "on_error": "continue"
//	}
func (e *Engine) stepEnrichClaims(ctx context.Context, step models.LoginFlowStep, uc UserContext) FlowResult {
	var cfg struct {
		URL          string            `json:"url"`
		Method       string            `json:"method"`
		Headers      map[string]string `json:"headers"`
		BodyTemplate string            `json:"body_template"`
		ClaimMappings []struct {
			Source string `json:"source"` // JSONPath e.g. "$.role"
			Target string `json:"target"` // claim name e.g. "role"
		} `json:"claim_mappings"`
		TimeoutMs int    `json:"timeout_ms"`
		OnError   string `json:"on_error"` // "continue" | "deny"
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil || cfg.URL == "" {
		return FlowResult{}
	}
	method := strings.ToUpper(cfg.Method)
	if method == "" {
		method = "POST"
	}
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	client := &http.Client{Timeout: timeout}

	// Build request body.
	bodyStr := cfg.BodyTemplate
	if bodyStr == "" {
		// Default: send basic user info as JSON.
		defaultBody, _ := json.Marshal(map[string]any{
			"sub":   uc.User.ID.String(),
			"email": uc.User.Email,
		})
		bodyStr = string(defaultBody)
	} else {
		// Simple placeholder substitution.
		bodyStr = strings.NewReplacer(
			"{{.Sub}}", uc.User.ID.String(),
			"{{.Email}}", uc.User.Email,
			"{{.OrgSlug}}", uc.OrgSlug,
			"{{.ClientID}}", uc.ClientID,
		).Replace(bodyStr)
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, cfg.URL, strings.NewReader(bodyStr))
	if err != nil {
		return e.enrichError(cfg.OnError, "enrich_claims: build request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("url", cfg.URL).Msg("flowengine: enrich_claims request failed")
		return e.enrichError(cfg.OnError, "Claims enrichment service unavailable.")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Warn().Int("status", resp.StatusCode).Str("url", cfg.URL).Msg("flowengine: enrich_claims non-2xx response")
		return e.enrichError(cfg.OnError, fmt.Sprintf("Claims enrichment service returned %d.", resp.StatusCode))
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var responseData map[string]any
	if err := json.Unmarshal(body, &responseData); err != nil {
		return e.enrichError(cfg.OnError, "Claims enrichment response is not valid JSON.")
	}

	extra := map[string]any{}
	for _, m := range cfg.ClaimMappings {
		// Simple key extraction ($.key or just key).
		key := strings.TrimPrefix(m.Source, "$.")
		if val, ok := responseData[key]; ok {
			extra[m.Target] = val
		}
	}
	// If no mappings defined, merge entire response (excluding reserved claims).
	if len(cfg.ClaimMappings) == 0 {
		reserved := map[string]bool{"sub": true, "iss": true, "aud": true, "exp": true, "iat": true, "nbf": true}
		for k, v := range responseData {
			if !reserved[k] {
				extra[k] = v
			}
		}
	}
	return FlowResult{ExtraClaims: extra}
}

func (e *Engine) enrichError(onError, msg string) FlowResult {
	if onError == "deny" {
		return FlowResult{Deny: true, DenyReason: msg}
	}
	return FlowResult{} // continue
}

// set_claim config:
//   {"claim":"tenant_id","value":"acme"}
//   OR: {"claim":"department","source_field":"department"} (from user profile)
func (e *Engine) stepSetClaim(step models.LoginFlowStep, uc UserContext) FlowResult {
	var cfg struct {
		Claim       string `json:"claim"`
		Value       string `json:"value"`
		SourceField string `json:"source_field"`
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil || cfg.Claim == "" {
		return FlowResult{}
	}
	val := cfg.Value
	if cfg.SourceField != "" {
		val = resolveUserField(uc.User, cfg.SourceField)
	}
	return FlowResult{ExtraClaims: map[string]any{cfg.Claim: val}}
}

// webhook config:
//   {"url":"https://...","method":"POST","secret":"signing-secret","on_failure":"continue"}
func (e *Engine) stepWebhook(ctx context.Context, step models.LoginFlowStep, uc UserContext) {
	var cfg struct {
		URL    string `json:"url"`
		Method string `json:"method"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil || cfg.URL == "" {
		return
	}
	method := strings.ToUpper(cfg.Method)
	if method == "" {
		method = "POST"
	}
	payload, _ := json.Marshal(map[string]any{
		"event":     "login",
		"sub":       uc.User.ID.String(),
		"email":     uc.User.Email,
		"client_id": uc.ClientID,
		"org_slug":  uc.OrgSlug,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, method, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Secret != "" {
		req.Header.Set("X-Clavex-Signature", hmacHex(payload, cfg.Secret))
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("url", cfg.URL).Msg("flowengine: webhook delivery failed")
		return
	}
	resp.Body.Close()
}

// check_ip_risk config:
//   {"threshold":70,"action":"deny"} | {"threshold":50,"action":"require_mfa"}
func (e *Engine) stepCheckIPRisk(step models.LoginFlowStep, uc UserContext) FlowResult {
	var cfg struct {
		Threshold int    `json:"threshold"`
		Action    string `json:"action"` // "deny" | "require_mfa"
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil {
		return FlowResult{}
	}
	if uc.RiskScore < cfg.Threshold {
		return FlowResult{}
	}
	if cfg.Action == "require_mfa" {
		return FlowResult{ForceMFA: true}
	}
	return FlowResult{Deny: true, DenyReason: "Access denied due to suspicious IP address."}
}

// require_email_verified config: {}
func (e *Engine) stepRequireEmailVerified(_ models.LoginFlowStep, uc UserContext) FlowResult {
	if !uc.User.IsEmailVerified {
		return FlowResult{Deny: true, DenyReason: "Email verification is required before you can sign in."}
	}
	return FlowResult{}
}

// check_breach config:
//
//	{"action":"deny"|"require_mfa", "message":"..."}
//
// Blocks or forces MFA when the user's account has been flagged as
// having credentials found in a known data breach.  The flag is set
// by the auth handler when the HIBP check detects a compromised
// password (per the org's breached_password_action policy).
func (e *Engine) stepCheckBreach(step models.LoginFlowStep, uc UserContext) FlowResult {
	var cfg struct {
		Action  string `json:"action"`  // "deny" | "require_mfa"
		Message string `json:"message"` // optional custom message
	}
	_ = json.Unmarshal(step.Config, &cfg)

	isBreached := false
	if uc.User.Metadata != nil {
		if v, ok := uc.User.Metadata["is_breached"].(bool); ok {
			isBreached = v
		}
	}
	if !isBreached {
		return FlowResult{}
	}

	msg := cfg.Message
	if msg == "" {
		msg = "Your credentials have been found in a known data breach. Please reset your password before signing in."
	}

	switch cfg.Action {
	case "require_mfa":
		return FlowResult{ForceMFA: true}
	default: // "deny"
		return FlowResult{Deny: true, DenyReason: msg}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// resolveUserField extracts a user attribute value by name.
func resolveUserField(u *models.User, field string) string {
	switch field {
	case "email":
		return u.Email
	case "first_name":
		if u.FirstName != nil {
			return *u.FirstName
		}
	case "last_name":
		if u.LastName != nil {
			return *u.LastName
		}
	case "department":
		if u.Metadata != nil {
			if v, ok := u.Metadata["department"].(string); ok {
				return v
			}
		}
	default:
		// Check metadata for any other field.
		if u.Metadata != nil {
			if v, ok := u.Metadata[field].(string); ok {
				return v
			}
		}
	}
	return ""
}

func evalOp(val, op, expected string) bool {
	switch op {
	case "eq":
		return val == expected
	case "neq":
		return val != expected
	case "contains":
		return strings.Contains(val, expected)
	case "starts_with":
		return strings.HasPrefix(val, expected)
	case "ends_with":
		return strings.HasSuffix(val, expected)
	case "exists":
		return val != ""
	case "not_exists":
		return val == ""
	}
	return false
}

func hmacHex(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// check_verified config:
//
//	{"min_level":"high","step_up_url":"/acme/spid/sso/arubaid-l3","message":"..."}
//
// Denies login when the user's OpenID IDA assurance_level (stored in
// user metadata) is below the configured minimum.
//
// When step_up_url is provided, the result carries StepUpURL so that the
// login handler redirects to a stronger IdP (e.g. SPID L3) instead of
// showing an error page. The IdP callback re-authenticates the user at the
// higher level, updates assurance_level in metadata, and resumes the flow;
// on the next evaluation check_verified will pass.
//
// Level hierarchy (ascending): low(1) < substantial/medium(2) < high(3).
// An unrecognised min_level is treated as misconfiguration and does not block.
func (e *Engine) stepCheckVerified(step models.LoginFlowStep, uc UserContext) FlowResult {
	var cfg struct {
		MinLevel  string `json:"min_level"`
		StepUpURL string `json:"step_up_url"`
		Message   string `json:"message"`
		// Upgrade, when set to "spid", triggers an in-session SPID level elevation
		// instead of a static step_up_url redirect.  The login handler redirects the
		// user to /:org_slug/spid/upgrade which re-initiates SSO at the required level
		// while preserving the original OIDC flow context.
		Upgrade string `json:"upgrade"`
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil || cfg.MinLevel == "" {
		return FlowResult{}
	}

	required := assuranceLevelValue(cfg.MinLevel)
	if required == 0 {
		// Unknown min_level — don't block; log and pass through.
		log.Warn().Str("min_level", cfg.MinLevel).Msg("flowengine: check_verified unknown min_level — skipped")
		return FlowResult{}
	}

	current := 0
	if uc.User.Metadata != nil {
		if v, ok := uc.User.Metadata["assurance_level"].(string); ok {
			current = assuranceLevelValue(v)
		}
	}

	if current < required {
		// In-session SPID level upgrade: redirect to UpgradeSSO instead of denying.
		if cfg.Upgrade == "spid" {
			return FlowResult{UpgradeSPIDLevel: required}
		}
		// In-session CIE upgrade: redirect to CIE UpgradeSSO instead of denying.
		// CIE is always eIDAS High assurance — use when current level < high.
		if cfg.Upgrade == "cie" {
			return FlowResult{UpgradeCIE: true}
		}
		msg := cfg.Message
		if msg == "" {
			msg = "This service requires a higher identity assurance level. Please authenticate with a stronger identity provider."
		}
		result := FlowResult{Deny: true, DenyReason: msg}
		if cfg.StepUpURL != "" {
			result.StepUpURL = cfg.StepUpURL
		}
		return result
	}
	return FlowResult{}
}

// check_session_age config:
//
//	{"max_age_seconds": 3600, "action": "deny" | "require_reauth", "message": "..."}
//
// Enforces a freshness constraint on the authentication time.  If the current
// wall-clock time minus AuthTime (recorded at password/IdP callback) exceeds
// max_age_seconds the step either denies the login (action:"deny") or returns
// ForceReauth=true so the OIDC handler redirects the client with
// error=login_required (action:"require_reauth", default).
//
// Unlike the OIDC max_age parameter (evaluated per-request by the client),
// this step lets the administrator enforce freshness via the server-side flow
// engine — useful for high-assurance OIDC clients that do not send max_age.
func (e *Engine) stepCheckSessionAge(step models.LoginFlowStep, uc UserContext) FlowResult {
	var cfg struct {
		MaxAgeSeconds int    `json:"max_age_seconds"`
		Action        string `json:"action"`  // "deny" | "require_reauth" (default)
		Message       string `json:"message"` // optional custom denial message
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil || cfg.MaxAgeSeconds <= 0 {
		return FlowResult{}
	}

	if uc.AuthTime == 0 {
		// AuthTime not set — cannot evaluate; pass through without blocking.
		return FlowResult{}
	}

	age := time.Now().Unix() - uc.AuthTime
	if age <= int64(cfg.MaxAgeSeconds) {
		return FlowResult{} // session is fresh — pass
	}

	msg := cfg.Message
	if cfg.Action == "deny" {
		if msg == "" {
			msg = "Your session has expired. Please sign in again."
		}
		return FlowResult{Deny: true, DenyReason: msg}
	}
	// Default: require_reauth — signal the OIDC handler to issue login_required.
	return FlowResult{ForceReauth: true}
}

// oid4vp_challenge config:
//
//	{
//	  "dcql_query": {
//	    "credentials": {
//	      "badge": {"format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}
//	    }
//	  },
//	  "message": "Please present your company badge to continue."
//	}
//
// Pauses the login flow and requires the user's IT-Wallet / EUDIW to present a
// verifiable credential matching the configured query.  The login handler creates
// an OID4VP presentation session, shows a QR challenge page, and resumes the
// login once the credential is verified — without re-prompting for the password.
//
// Verified credential claims are merged into the token's extra_claims so the
// resource server can enforce fine-grained access control (e.g. check the mdoc
// expiry or the issuing authority of the presented credential).
//
// This implements in-session step-up per draft-ietf-oauth-step-up-authn-challenge:
// existing SSO context is preserved; only the second factor (the wallet credential)
// is added on top of the initial password / IdP authentication.
func (e *Engine) stepOID4VPChallenge(step models.LoginFlowStep) FlowResult {
	var cfg struct {
		DCQLQuery              map[string]any `json:"dcql_query"`
		PresentationDefinition map[string]any `json:"presentation_definition"`
		Message                string         `json:"message"`
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil {
		log.Warn().Err(err).Msg("flowengine: oid4vp_challenge: invalid config — skipped")
		return FlowResult{}
	}
	if cfg.DCQLQuery == nil && cfg.PresentationDefinition == nil {
		log.Warn().Msg("flowengine: oid4vp_challenge: no dcql_query or presentation_definition — skipped")
		return FlowResult{}
	}
	msg := cfg.Message
	if msg == "" {
		msg = "Please present your verifiable credential to continue."
	}
	return FlowResult{
		OID4VPChallenge: &OID4VPChallengeSpec{
			DCQLQuery:              cfg.DCQLQuery,
			PresentationDefinition: cfg.PresentationDefinition,
			Message:                msg,
		},
	}
}

// assuranceLevelValue maps an IDA assurance level string to a comparable integer.// Supports eIDAS terminology (low/substantial/high) and the alias "medium" for
// substantial.  Returns 0 for unrecognised values.
func assuranceLevelValue(level string) int {
	switch strings.ToLower(level) {
	case "low":
		return 1
	case "medium", "substantial":
		return 2
	case "high":
		return 3
	}
	return 0
}

// ── ai_decision step ──────────────────────────────────────────────────────────
//
// Config: { "prompt": "<additional context/instructions for Claude>", "timeout_action": "allow" | "deny" | "require_mfa" }
//
// Calls Claude Opus 4.7 with contextual information about the login attempt and returns
// allow / deny / require_mfa. Decisions are logged with their reasoning in the audit trail.
// On AI unavailability (no key, timeout, API error) the step falls back to timeout_action
// (default: "allow") so a misconfigured AI key never becomes a full outage.

const aiDecisionSystem = `You are an adaptive authentication policy engine.
Evaluate the provided login context and decide the outcome.

Respond with ONLY valid JSON — no markdown, no explanation:
{
  "action":  "allow" | "deny" | "require_mfa",
  "reason":  "<one-sentence explanation for the audit log>"
}`

func (e *Engine) stepAIDecision(ctx context.Context, step models.LoginFlowStep, uc UserContext) FlowResult {
	if e.orgsRepo == nil {
		log.Warn().Msg("flowengine: ai_decision step skipped — org repository not configured")
		return FlowResult{}
	}

	var cfg struct {
		Prompt        string `json:"prompt"`
		TimeoutAction string `json:"timeout_action"` // "allow" | "deny" | "require_mfa"
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil {
		log.Warn().Err(err).Msg("flowengine: ai_decision: invalid config")
		return FlowResult{}
	}
	if cfg.TimeoutAction == "" {
		cfg.TimeoutAction = "allow"
	}

	// Fail-open: if there's no AI key we skip (don't block production logins).
	key, err := e.orgsRepo.GetAIKey(ctx, uc.User.OrgID)
	if err != nil || key == nil || *key == "" {
		log.Warn().Str("org_id", uc.User.OrgID.String()).Msg("flowengine: ai_decision: no API key — skipping")
		return FlowResult{}
	}

	client := anthropic.NewClient(option.WithAPIKey(*key))

	userMsg := fmt.Sprintf(
		"Login context:\n- User: %s (%s)\n- Client: %s\n- IP: %s\n- Risk score: %d\n- Org: %s",
		uc.User.Email, uc.User.ID.String(),
		uc.ClientID, uc.IPAddress, uc.RiskScore, uc.OrgSlug,
	)
	// Include IDA assurance level if present.
	if idaLevel, ok := uc.User.Metadata["assurance_level"].(string); ok && idaLevel != "" {
		userMsg += "\n- IDA assurance level: " + idaLevel
	}
	if cfg.Prompt != "" {
		userMsg += "\n\nAdditional instructions:\n" + cfg.Prompt
	}

	// Use a tight timeout so a slow API call doesn't stall a login.
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	msg, err := client.Messages.New(callCtx, anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeOpus4_7,
		MaxTokens: 256,
		System: []anthropic.TextBlockParam{
			{Type: "text", Text: aiDecisionSystem},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg)),
		},
	})
	if err != nil {
		log.Warn().Err(err).Str("org_id", uc.User.OrgID.String()).
			Msg("flowengine: ai_decision: API error — applying timeout_action")
		return applyTimeoutAction(cfg.TimeoutAction)
	}

	rawText := ""
	for _, block := range msg.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			rawText = tb.Text
			break
		}
	}

	var decision struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	jsonStr := rawText
	if idx := strings.Index(rawText, "```json"); idx >= 0 {
		jsonStr = rawText[idx+7:]
		if end := strings.Index(jsonStr, "```"); end >= 0 {
			jsonStr = jsonStr[:end]
		}
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonStr)), &decision); err != nil {
		log.Warn().Str("raw", rawText).Msg("flowengine: ai_decision: non-JSON response — applying timeout_action")
		return applyTimeoutAction(cfg.TimeoutAction)
	}

	log.Info().
		Str("user_id", uc.User.ID.String()).
		Str("action", decision.Action).
		Str("reason", decision.Reason).
		Msg("flowengine: ai_decision")

	// Emit a structured audit event for NIS2 Art.21 traceability.
	if e.auditEM != nil {
		email := uc.User.Email
		userIDPtr := uc.User.ID
		resType := "ai_decision"
		e.auditEM.Emit(ctx, audit.EmitParams{
			OrgID:        uc.User.OrgID,
			ActorID:      &userIDPtr,
			ActorEmail:   &email,
			Action:       "flow.ai_decision",
			Status:       decision.Action,
			ResourceType: &resType,
			IPAddress:    &uc.IPAddress,
			Metadata: map[string]interface{}{
				"ai_action": decision.Action,
				"ai_reason": decision.Reason,
				"client_id": uc.ClientID,
				"risk_score": uc.RiskScore,
			},
		})
	}

	switch decision.Action {
	case "deny":
		return FlowResult{Deny: true, DenyReason: decision.Reason}
	case "require_mfa":
		return FlowResult{ForceMFA: true}
	default:
		return FlowResult{}
	}
}

func applyTimeoutAction(action string) FlowResult {
	switch action {
	case "deny":
		return FlowResult{Deny: true, DenyReason: "AI decision engine unavailable."}
	case "require_mfa":
		return FlowResult{ForceMFA: true}
	default:
		return FlowResult{} // allow
	}
}

// ── notify step ──────────────────────────────────────────────────────────────

// notify step config:
//
//	{
//	  "channel": "webhook",
//	  "url": "https://example.com/hook",
//	  "secret": "...",                   // optional HMAC-SHA256 signing key
//	  "template": "{{.UserEmail}} logged in from {{.IPAddress}}"
//	}
//
//	{
//	  "channel": "email",
//	  "to": "security@example.com",      // fixed recipient; omit to use user's email
//	  "subject": "Login alert",
//	  "template": "User {{.UserEmail}} ({{.OrgSlug}}) logged in at risk score {{.RiskScore}}"
//	}
//
//	{
//	  "channel": "sms",
//	  "to": "+39...",                     // fixed number; omit to use user's phone
//	  "template": "Login: {{.UserEmail}} from {{.IPAddress}}"
//	}
//
// Available template variables:
//
//	{{.UserID}}, {{.UserEmail}}, {{.OrgSlug}}, {{.ClientID}}, {{.IPAddress}}, {{.RiskScore}}
//
// Delivery failures are logged but never block the login (fail-open).
func (e *Engine) stepNotify(ctx context.Context, step models.LoginFlowStep, uc UserContext) FlowResult {
	var cfg struct {
		Channel  string `json:"channel"`  // "webhook" | "email" | "sms"
		URL      string `json:"url"`      // webhook
		Secret   string `json:"secret"`   // webhook HMAC key
		To       string `json:"to"`       // email or sms recipient override
		Subject  string `json:"subject"`  // email subject
		Template string `json:"template"` // Go text/template body
	}
	if err := json.Unmarshal(step.Config, &cfg); err != nil || cfg.Channel == "" {
		return FlowResult{}
	}

	// Render the message body from the template.
	body := renderNotifyTemplate(cfg.Template, uc)

	switch strings.ToLower(cfg.Channel) {
	case "webhook":
		e.notifyWebhook(ctx, cfg.URL, cfg.Secret, body, uc)
	case "email":
		e.notifyEmail(ctx, cfg.To, cfg.Subject, body, uc)
	case "sms":
		e.notifySMS(ctx, cfg.To, body, uc)
	default:
		log.Warn().Str("channel", cfg.Channel).Msg("flowengine: notify: unknown channel")
	}
	return FlowResult{} // always allow — notify is a side-effect, not a gate
}

// notifyTemplateVars holds the variables available in the notify step template.
type notifyTemplateVars struct {
	UserID    string
	UserEmail string
	OrgSlug   string
	ClientID  string
	IPAddress string
	RiskScore int
}

func renderNotifyTemplate(tmplSrc string, uc UserContext) string {
	if tmplSrc == "" {
		tmplSrc = "Login event: {{.UserEmail}} org={{.OrgSlug}} client={{.ClientID}} ip={{.IPAddress}} risk={{.RiskScore}}"
	}
	t, err := template.New("notify").Parse(tmplSrc)
	if err != nil {
		return tmplSrc // fall back to raw string on parse error
	}
	vars := notifyTemplateVars{
		UserID:    uc.User.ID.String(),
		UserEmail: uc.User.Email,
		OrgSlug:   uc.OrgSlug,
		ClientID:  uc.ClientID,
		IPAddress: uc.IPAddress,
		RiskScore: uc.RiskScore,
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, vars); err != nil {
		return tmplSrc
	}
	return buf.String()
}

func (e *Engine) notifyWebhook(ctx context.Context, url, secret, body string, uc UserContext) {
	if url == "" {
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"event":     "login.notify",
		"sub":       uc.User.ID.String(),
		"email":     uc.User.Email,
		"org_slug":  uc.OrgSlug,
		"client_id": uc.ClientID,
		"ip":        uc.IPAddress,
		"risk":      uc.RiskScore,
		"message":   body,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		log.Warn().Err(err).Str("url", url).Msg("flowengine: notify webhook: build request failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Clavex-Signature", hmacHex(payload, secret))
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("url", url).Msg("flowengine: notify webhook: delivery failed")
		return
	}
	resp.Body.Close()
}

func (e *Engine) notifyEmail(ctx context.Context, to, subject, body string, uc UserContext) {
	if e.smtpRepo == nil {
		return
	}
	// Derive org UUID from org slug if needed.
	if e.orgsRepo == nil {
		return
	}
	orgID, err := e.orgsRepo.GetIDBySlug(ctx, uc.OrgSlug)
	if err != nil {
		return
	}
	m, err := mailer.ForOrg(ctx, e.smtpRepo, orgID)
	if err != nil {
		log.Warn().Err(err).Str("org", uc.OrgSlug).Msg("flowengine: notify email: mailer unavailable")
		return
	}
	recipient := to
	if recipient == "" {
		recipient = uc.User.Email
	}
	if subject == "" {
		subject = "Login notification"
	}
	// Wrap plain-text body in minimal HTML.
	htmlBody := "<pre>" + body + "</pre>"
	if err := m.Send(recipient, subject, htmlBody); err != nil {
		log.Warn().Err(err).Str("to", recipient).Msg("flowengine: notify email: send failed")
	}
}

func (e *Engine) notifySMS(ctx context.Context, to, body string, uc UserContext) {
	if e.smsRepo == nil {
		return
	}
	if e.orgsRepo == nil {
		return
	}
	orgID, err := e.orgsRepo.GetIDBySlug(ctx, uc.OrgSlug)
	if err != nil {
		return
	}
	provider, err := sms.ForOrg(ctx, e.smsRepo, orgID)
	if err != nil {
		log.Warn().Err(err).Str("org", uc.OrgSlug).Msg("flowengine: notify sms: provider unavailable")
		return
	}
	recipient := to
	// If no explicit recipient, use the user's verified phone number if available.
	// Fall back silently if the user has no phone on record.
	if recipient == "" {
		ph, pErr := e.users.GetPrimaryPhone(ctx, uc.User.ID)
		if pErr != nil || ph == "" {
			log.Debug().Str("user_id", uc.User.ID.String()).Msg("flowengine: notify sms: no phone for user — skipped")
			return
		}
		recipient = ph
	}
	if err := provider.Send(ctx, recipient, body); err != nil {
		log.Warn().Err(err).Str("to", recipient).Msg("flowengine: notify sms: send failed")
	}
}
// ── check_device ─────────────────────────────────────────────────────────────
//
// check_device evaluates fleet-agent posture facts for the authenticating user.
//
// Config fields (all optional):
//
//	"require_device"  bool   — deny login if the user has no registered device
//	"fact"            string — name of a fact key in the device_facts.facts JSONB
//	"fact_value"      string — required string value of that key (exact match)
//	"action"          string — "deny" (default) | "require_mfa"
//	"message"         string — custom denial message
//
// If devicesRepo is nil (not wired), the step is skipped with a warning.
func (e *Engine) stepCheckDevice(ctx context.Context, step models.LoginFlowStep, uc UserContext) FlowResult {
	if e.devicesRepo == nil {
		log.Warn().Msg("flowengine: check_device step skipped — devicesRepo not wired")
		return FlowResult{}
	}

	type cfg struct {
		RequireDevice bool   `json:"require_device"`
		Fact          string `json:"fact"`
		FactValue     string `json:"fact_value"`
		Action        string `json:"action"`
		Message       string `json:"message"`
	}
	var c cfg
	if err := json.Unmarshal(step.Config, &c); err != nil {
		log.Warn().Err(err).Msg("flowengine: check_device: bad config")
		return FlowResult{}
	}

	orgID := uc.User.OrgID
	userID := uc.User.ID

	devices, err := e.devicesRepo.GetByUserID(ctx, orgID, userID)
	if err != nil {
		log.Warn().Err(err).Msg("flowengine: check_device: db error")
		return FlowResult{} // fail-open rather than blocking all logins on transient DB error
	}

	denyMsg := c.Message
	if denyMsg == "" {
		denyMsg = "Access denied: device posture check failed."
	}
	action := c.Action
	if action == "" {
		action = "deny"
	}

	// If no device registered and we require one — apply action immediately.
	if len(devices) == 0 && c.RequireDevice {
		if action == "require_mfa" {
			return FlowResult{ForceMFA: true}
		}
		return FlowResult{Deny: true, DenyReason: denyMsg}
	}

	// If a specific fact key/value is configured, at least one device must satisfy it.
	if c.Fact != "" {
		satisfied := false
		for _, d := range devices {
			if val, ok := d.Facts[c.Fact]; ok {
				if fmt.Sprintf("%v", val) == c.FactValue {
					satisfied = true
					break
				}
			}
		}
		if !satisfied {
			if action == "require_mfa" {
				return FlowResult{ForceMFA: true}
			}
			return FlowResult{Deny: true, DenyReason: denyMsg}
		}
	}

	return FlowResult{}
}

// ── run_action ────────────────────────────────────────────────────────────────
//
// run_action invokes all active Actions V2 executions for the org with event
// type "user.pre_login". The first execution that returns action:"deny" short-
// circuits and the step returns a deny result. Merge claims are applied to the
// user's extra claims if all executions continue.
//
// Config fields (all optional):
//
//	"event_type" string — override event type (default: "user.pre_login")
//
// If actionsRunner is nil (not wired), the step is skipped.
func (e *Engine) stepRunAction(ctx context.Context, step models.LoginFlowStep, uc UserContext) FlowResult {
	if e.actionsRunner == nil {
		log.Warn().Msg("flowengine: run_action step skipped — actionsRunner not wired")
		return FlowResult{}
	}

	var cfg struct {
		EventType string `json:"event_type"`
	}
	_ = json.Unmarshal(step.Config, &cfg)
	eventType := cfg.EventType
	if eventType == "" {
		eventType = "user.pre_login"
	}

	data := map[string]any{
		"user_id":    uc.User.ID.String(),
		"email":      uc.User.Email,
		"org_id":     uc.User.OrgID.String(),
		"client_id":  uc.ClientID,
		"ip_address": uc.IPAddress,
		"risk_score": uc.RiskScore,
	}

	deny, reason, _ := e.actionsRunner.RunSync(ctx, uc.User.OrgID, eventType, data)
	if deny {
		if reason == "" {
			reason = "Access denied by action hook."
		}
		return FlowResult{Deny: true, DenyReason: reason}
	}
	return FlowResult{}
}