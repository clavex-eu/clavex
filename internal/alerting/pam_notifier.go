package alerting

// PAMNotifier sends structured alert messages to Slack (Block Kit) and/or
// Microsoft Teams (Adaptive Card) for the three high-priority PAM events:
//
//   - Break-glass emergency access used (PCI DSS 8.2.6)
//   - Vault credential not rotated within the configured stale threshold
//   - Privileged session running longer than the configured maximum
//
// Both targets are optional and independent: set only SlackWebhookURL,
// only TeamsWebhookURL, or both. When both fields in Config are empty the
// notifier methods are no-ops.
//
// Slack messages use Block Kit with Link-Button actions that open the Clavex
// admin UI directly — no Slack App interactivity endpoint required. Teams
// messages use an Adaptive Card with Action.OpenUrl buttons.
//
// All sends are non-blocking: delivery runs in a detached goroutine so the
// caller (a request handler or background worker) is never delayed. Delivery
// errors are logged at WARN level and do not surface to the caller.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/rs/zerolog/log"
)

// ComplianceDriftChange describes a single security-control change detected by
// the NIS2 compliance drift worker.
type ComplianceDriftChange struct {
	Control  string  // e.g. "mfa_required", "access_ttl"
	Previous *string // nil when the control is newly added
	Current  *string // nil when the control is removed
	Severity string  // "critical" | "high" | "medium" | "low" | "info"
}

// Config holds the server-level PAM alert configuration.
// Embed in config.Config under the "pam_alerts" key.
type PAMAlertConfig struct {
	// SlackWebhookURL is an Incoming Webhook URL obtained from a Slack App
	// (Settings → Incoming Webhooks → Add New Webhook to Workspace).
	// Leave empty to disable Slack delivery.
	SlackWebhookURL string `mapstructure:"slack_webhook_url"`

	// TeamsWebhookURL is an Incoming Webhook URL from Microsoft Teams
	// (channel → Connectors → Incoming Webhook).
	// Leave empty to disable Teams delivery.
	TeamsWebhookURL string `mapstructure:"teams_webhook_url"`

	// StaleCredentialDays is the number of days after which a vault credential
	// that has not been rotated is considered stale and triggers an alert.
	// Only credentials with rotation_interval_days set are checked.
	// Default: 30. Set to 0 to disable stale-credential alerts.
	StaleCredentialDays int `mapstructure:"stale_credential_days"`

	// SessionMaxHours is the maximum duration (in hours) a privileged session
	// may run before triggering a "long session" alert.
	// Default: 8. Set to 0 to disable long-session alerts.
	SessionMaxHours int `mapstructure:"session_max_hours"`

	// AdminBaseURL is the base URL of the Clavex admin console, used to build
	// deep-link buttons in alert messages (e.g. "https://admin.example.com").
	// When empty the buttons are omitted.
	AdminBaseURL string `mapstructure:"admin_base_url"`
}

// PAMNotifier delivers PAM security alerts to Slack and Teams.
// A zero-value PAMNotifier (all-empty Config) is safe to use — all methods
// become no-ops.
type PAMNotifier struct {
	cfg    PAMAlertConfig
	client *http.Client
}
// Returns a no-op notifier (IsEnabled() == false) when both webhook URLs are
// empty — callers can construct it unconditionally.
func NewPAMNotifier(cfg PAMAlertConfig) *PAMNotifier {
	if cfg.StaleCredentialDays == 0 {
		cfg.StaleCredentialDays = 30
	}
	if cfg.SessionMaxHours == 0 {
		cfg.SessionMaxHours = 8
	}
	return &PAMNotifier{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// IsEnabled reports whether at least one delivery target is configured.
func (n *PAMNotifier) IsEnabled() bool {
	return n != nil && (n.cfg.SlackWebhookURL != "" || n.cfg.TeamsWebhookURL != "")
}

// StaleCredentialDays returns the configured threshold (already defaulted to 30).
func (n *PAMNotifier) StaleCredentialDays() int {
	if n == nil {
		return 30
	}
	return n.cfg.StaleCredentialDays
}

// SessionMaxHours returns the configured threshold (already defaulted to 8).
func (n *PAMNotifier) SessionMaxHours() int {
	if n == nil {
		return 8
	}
	return n.cfg.SessionMaxHours
}

// ── Public alert methods ──────────────────────────────────────────────────────

// AlertBreakGlass fires a critical-severity alert when a break-glass emergency
// access request is used. Delivery is asynchronous.
func (n *PAMNotifier) AlertBreakGlass(ar *repository.PAMAccessRequest, requesterEmail string) {
	if !n.IsEnabled() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		approveURL, denyURL := n.pamRequestURLs(ar.OrgID.String(), ar.ID.String())

		slackMsg := slackBreakGlass(ar, requesterEmail, approveURL, denyURL)
		teamsMsg := teamsBreakGlass(ar, requesterEmail, approveURL, denyURL)
		n.deliver(ctx, "break-glass", slackMsg, teamsMsg)
	}()
}

// AlertStaleCredential fires a warning-severity alert when a vault credential
// has not been rotated within StaleCredentialDays. Delivery is asynchronous.
func (n *PAMNotifier) AlertStaleCredential(cred *repository.PAMCredential, staleDays int) {
	if !n.IsEnabled() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		detailURL := n.credentialURL(cred.OrgID.String(), cred.ID.String())
		slackMsg := slackStaleCredential(cred, staleDays, detailURL)
		teamsMsg := teamsStaleCredential(cred, staleDays, detailURL)
		n.deliver(ctx, "stale-credential", slackMsg, teamsMsg)
	}()
}

// AlertLongSession fires a warning-severity alert when a privileged session
// has been running longer than SessionMaxHours. Delivery is asynchronous.
func (n *PAMNotifier) AlertLongSession(s *repository.PAMSession, durationHours float64) {
	if !n.IsEnabled() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		detailURL := n.sessionURL(s.OrgID.String(), s.ID.String())
		slackMsg := slackLongSession(s, durationHours, detailURL)
		teamsMsg := teamsLongSession(s, durationHours, detailURL)
		n.deliver(ctx, "long-session", slackMsg, teamsMsg)
	}()
}

// AlertComplianceDrift notifies Slack/Teams when NIS2/zero-trust security
// controls have changed in an organization.
func (n *PAMNotifier) AlertComplianceDrift(orgName, orgSlug string, changes []ComplianceDriftChange) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	n.deliver(ctx, "compliance_drift",
		slackComplianceDrift(orgName, orgSlug, changes),
		teamsComplianceDrift(orgName, orgSlug, changes),
	)
}

// AlertConformanceScoreDrop fires when an org's continuous assurance score
// drops below its configured threshold. components is the score breakdown.
func (n *PAMNotifier) AlertConformanceScoreDrop(orgName, orgSlug string, score, threshold int, components map[string]any) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	n.deliver(ctx, "conformance_score_drop",
		slackConformanceScoreDrop(orgName, orgSlug, score, threshold, components),
		teamsConformanceScoreDrop(orgName, orgSlug, score, threshold, components),
	)
}

// ── Internal delivery ─────────────────────────────────────────────────────────

func (n *PAMNotifier) deliver(ctx context.Context, kind string, slackPayload, teamsPayload any) {
	if n.cfg.SlackWebhookURL != "" {
		if err := postJSON(ctx, n.client, n.cfg.SlackWebhookURL, slackPayload); err != nil {
			log.Warn().Err(err).Str("kind", kind).Msg("pam-notifier: slack delivery failed")
		}
	}
	if n.cfg.TeamsWebhookURL != "" {
		if err := postJSON(ctx, n.client, n.cfg.TeamsWebhookURL, teamsPayload); err != nil {
			log.Warn().Err(err).Str("kind", kind).Msg("pam-notifier: teams delivery failed")
		}
	}
}

func postJSON(ctx context.Context, client *http.Client, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx status: %d", resp.StatusCode)
	}
	return nil
}

// ── URL builders ──────────────────────────────────────────────────────────────

func (n *PAMNotifier) pamRequestURLs(orgID, reqID string) (approve, deny string) {
	base := strings.TrimRight(n.cfg.AdminBaseURL, "/")
	if base == "" {
		return "", ""
	}
	prefix := fmt.Sprintf("%s/organizations/%s/pam/access-requests/%s", base, orgID, reqID)
	return prefix + "/approve", prefix + "/deny"
}

func (n *PAMNotifier) credentialURL(orgID, credID string) string {
	base := strings.TrimRight(n.cfg.AdminBaseURL, "/")
	if base == "" {
		return ""
	}
	return fmt.Sprintf("%s/organizations/%s/pam/credentials/%s", base, orgID, credID)
}

func (n *PAMNotifier) sessionURL(orgID, sessionID string) string {
	base := strings.TrimRight(n.cfg.AdminBaseURL, "/")
	if base == "" {
		return ""
	}
	return fmt.Sprintf("%s/organizations/%s/pam/sessions/%s", base, orgID, sessionID)
}

// ── Slack Block Kit builders ──────────────────────────────────────────────────

// slackBlock is an untyped map that serialises to any valid Block Kit block.
type slackBlock = map[string]any

func slackBreakGlass(ar *repository.PAMAccessRequest, requesterEmail, approveURL, denyURL string) any {
	target := ar.ResourceName
	if ar.ResourceID != "" {
		target = ar.ResourceID
	}

	fields := []*slackField{
		{Title: "Requester", Value: requesterEmail},
		{Title: "Resource", Value: fmt.Sprintf("%s — %s", ar.ResourceType, target)},
		{Title: "Justification", Value: ar.Justification},
		{Title: "Duration", Value: fmt.Sprintf("%d min", ar.RequestedDuration)},
		{Title: "Request ID", Value: fmt.Sprintf("`%s`", ar.ID)},
		{Title: "Org", Value: ar.OrgID.String()},
	}

	blocks := []slackBlock{
		slackHeaderBlock(":rotating_light:  Break-Glass access used"),
		slackContextBlock("*Severity: CRITICAL* — PCI DSS 8.2.6 requires immediate admin notification"),
		slackDivider(),
		slackSectionFields(fields),
		slackDivider(),
	}

	if approveURL != "" || denyURL != "" {
		blocks = append(blocks, slackActionsBlock([]slackAction{
			{Label: ":white_check_mark:  Approve", URL: approveURL, Style: "primary"},
			{Label: ":x:  Deny", URL: denyURL, Style: "danger"},
			{Label: "View details", URL: approveURL[:strings.LastIndex(approveURL, "/")], Style: ""},
		}))
	}

	return map[string]any{"blocks": blocks}
}

func slackStaleCredential(cred *repository.PAMCredential, staleDays int, detailURL string) any {
	lastRotated := "never"
	if cred.LastRotatedAt != nil {
		lastRotated = cred.LastRotatedAt.Format(time.RFC3339)
	}

	fields := []*slackField{
		{Title: "Credential", Value: cred.Name},
		{Title: "Type", Value: cred.CredentialType},
		{Title: "Last rotated", Value: lastRotated},
		{Title: "Stale since", Value: fmt.Sprintf("%d days", staleDays)},
		{Title: "Credential ID", Value: fmt.Sprintf("`%s`", cred.ID)},
		{Title: "Org", Value: cred.OrgID.String()},
	}

	blocks := []slackBlock{
		slackHeaderBlock(":warning:  Vault credential overdue for rotation"),
		slackContextBlock("*Severity: WARNING* — Credential has not been rotated within the configured interval"),
		slackDivider(),
		slackSectionFields(fields),
		slackDivider(),
	}

	if detailURL != "" {
		blocks = append(blocks, slackActionsBlock([]slackAction{
			{Label: ":arrows_counterclockwise:  Rotate now", URL: detailURL, Style: "primary"},
			{Label: "View credential", URL: detailURL, Style: ""},
		}))
	}

	return map[string]any{"blocks": blocks}
}

func slackLongSession(s *repository.PAMSession, durationHours float64, detailURL string) any {
	target := ""
	if s.TargetHost != nil {
		target = *s.TargetHost
		if s.TargetUser != nil {
			target = *s.TargetUser + "@" + target
		}
	}

	fields := []*slackField{
		{Title: "Session type", Value: s.SessionType},
		{Title: "Target", Value: target},
		{Title: "Started", Value: s.StartedAt.Format(time.RFC3339)},
		{Title: "Duration", Value: fmt.Sprintf("%.1f hours", durationHours)},
		{Title: "Session ID", Value: fmt.Sprintf("`%s`", s.ID)},
		{Title: "Org", Value: s.OrgID.String()},
	}

	blocks := []slackBlock{
		slackHeaderBlock(":clock4:  Privileged session running too long"),
		slackContextBlock(fmt.Sprintf("*Severity: WARNING* — Session has been active for %.1f hours (threshold: configured max)", durationHours)),
		slackDivider(),
		slackSectionFields(fields),
		slackDivider(),
	}

	if detailURL != "" {
		blocks = append(blocks, slackActionsBlock([]slackAction{
			{Label: ":stop_sign:  Terminate session", URL: detailURL, Style: "danger"},
			{Label: "View session", URL: detailURL, Style: ""},
		}))
	}

	return map[string]any{"blocks": blocks}
}

// ── Slack block-kit helpers ───────────────────────────────────────────────────

func slackHeaderBlock(text string) slackBlock {
	return slackBlock{
		"type": "header",
		"text": map[string]any{"type": "plain_text", "text": text, "emoji": true},
	}
}

func slackContextBlock(markdown string) slackBlock {
	return slackBlock{
		"type": "context",
		"elements": []any{
			map[string]any{"type": "mrkdwn", "text": markdown},
		},
	}
}

func slackDivider() slackBlock {
	return slackBlock{"type": "divider"}
}

type slackField struct{ Title, Value string }

func slackSectionFields(fields []*slackField) slackBlock {
	elements := make([]any, 0, len(fields))
	for _, f := range fields {
		if f.Value == "" {
			continue
		}
		elements = append(elements, map[string]any{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*%s*\n%s", f.Title, f.Value),
		})
	}
	return slackBlock{"type": "section", "fields": elements}
}

type slackAction struct {
	Label, URL, Style string
}

func slackActionsBlock(actions []slackAction) slackBlock {
	elements := make([]any, 0, len(actions))
	for _, a := range actions {
		if a.URL == "" {
			continue
		}
		btn := map[string]any{
			"type": "button",
			"text": map[string]any{"type": "plain_text", "text": a.Label, "emoji": true},
			"url":  a.URL,
		}
		if a.Style != "" {
			btn["style"] = a.Style
		}
		elements = append(elements, btn)
	}
	if len(elements) == 0 {
		return slackDivider()
	}
	return slackBlock{"type": "actions", "elements": elements}
}

// ── Microsoft Teams Adaptive Card builders ───────────────────────────────────
//
// Teams incoming webhooks accept application/json in the "message with
// attachments" format (workflow webhooks, 2024+). The payload wraps an
// Adaptive Card v1.4 inside the attachments array.

func teamsBreakGlass(ar *repository.PAMAccessRequest, requesterEmail, approveURL, denyURL string) any {
	target := ar.ResourceName
	facts := []teamsAdaptiveFact{
		{"Requester", requesterEmail},
		{"Resource", fmt.Sprintf("%s — %s", ar.ResourceType, target)},
		{"Justification", ar.Justification},
		{"Duration", fmt.Sprintf("%d min", ar.RequestedDuration)},
		{"Request ID", ar.ID.String()},
		{"Org", ar.OrgID.String()},
	}

	actions := []any{}
	if approveURL != "" {
		actions = append(actions,
			teamsOpenURL("✅  Approve", approveURL),
			teamsOpenURL("❌  Deny", denyURL),
		)
	}

	return teamsCard(
		"🚨  Break-Glass Access Used",
		"**Severity: CRITICAL** — PCI DSS 8.2.6 requires immediate admin notification.",
		"attention",
		facts,
		actions,
	)
}

func teamsStaleCredential(cred *repository.PAMCredential, staleDays int, detailURL string) any {
	lastRotated := "never"
	if cred.LastRotatedAt != nil {
		lastRotated = cred.LastRotatedAt.Format(time.RFC3339)
	}
	facts := []teamsAdaptiveFact{
		{"Credential", cred.Name},
		{"Type", cred.CredentialType},
		{"Last rotated", lastRotated},
		{"Stale since", fmt.Sprintf("%d days", staleDays)},
		{"Credential ID", cred.ID.String()},
		{"Org", cred.OrgID.String()},
	}
	actions := []any{}
	if detailURL != "" {
		actions = append(actions, teamsOpenURL("🔄  Rotate now", detailURL))
	}
	return teamsCard(
		"⚠️  Vault Credential Overdue for Rotation",
		"**Severity: WARNING** — Credential has not been rotated within the configured interval.",
		"warning",
		facts,
		actions,
	)
}

func teamsLongSession(s *repository.PAMSession, durationHours float64, detailURL string) any {
	target := ""
	if s.TargetHost != nil {
		target = *s.TargetHost
		if s.TargetUser != nil {
			target = *s.TargetUser + "@" + target
		}
	}
	facts := []teamsAdaptiveFact{
		{"Session type", s.SessionType},
		{"Target", target},
		{"Started", s.StartedAt.Format(time.RFC3339)},
		{"Duration", fmt.Sprintf("%.1f hours", durationHours)},
		{"Session ID", s.ID.String()},
		{"Org", s.OrgID.String()},
	}
	actions := []any{}
	if detailURL != "" {
		actions = append(actions, teamsOpenURL("🛑  Terminate session", detailURL))
	}
	return teamsCard(
		"🕐  Privileged Session Running Too Long",
		fmt.Sprintf("**Severity: WARNING** — Session has been active for %.1f hours.", durationHours),
		"warning",
		facts,
		actions,
	)
}

type teamsAdaptiveFact struct{ Title, Value string }

func teamsCard(title, description, color string, facts []teamsAdaptiveFact, actions []any) any {
	factItems := make([]any, 0, len(facts))
	for _, f := range facts {
		if f.Value == "" {
			continue
		}
		factItems = append(factItems, map[string]any{"title": f.Title, "value": f.Value})
	}

	body := []any{
		map[string]any{
			"type":   "TextBlock",
			"text":   title,
			"weight": "bolder",
			"size":   "large",
			"color":  color,
			"wrap":   true,
		},
		map[string]any{
			"type": "TextBlock",
			"text": description,
			"wrap": true,
		},
		map[string]any{
			"type":  "FactSet",
			"facts": factItems,
		},
	}

	card := map[string]any{
		"type":    "AdaptiveCard",
		"version": "1.4",
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"body":    body,
	}
	if len(actions) > 0 {
		card["actions"] = actions
	}

	return map[string]any{
		"type": "message",
		"attachments": []any{
			map[string]any{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content":     card,
			},
		},
	}
}

func teamsOpenURL(title, url string) any {
	return map[string]any{
		"type":  "Action.OpenUrl",
		"title": title,
		"url":   url,
	}
}

// ── Compliance drift alert formatters ─────────────────────────────────────────

func slackComplianceDrift(orgName, orgSlug string, changes []ComplianceDriftChange) any {
	severity := "info"
	for _, c := range changes {
		switch {
		case c.Severity == "critical":
			severity = "critical"
		case c.Severity == "high" && severity != "critical":
			severity = "high"
		case c.Severity == "medium" && severity != "critical" && severity != "high":
			severity = "medium"
		}
	}

	emoji := map[string]string{
		"critical": "🚨", "high": "⚠️", "medium": "🔔", "low": "ℹ️", "info": "ℹ️",
	}[severity]
	color := map[string]string{
		"critical": "#DC2626", "high": "#EA580C", "medium": "#D97706", "low": "#6B7280", "info": "#3B82F6",
	}[severity]

	var fields []slackField
	for _, c := range changes {
		prev := "(none)"
		if c.Previous != nil && *c.Previous != "" {
			prev = *c.Previous
		}
		curr := "(removed)"
		if c.Current != nil {
			curr = *c.Current
		}
		fields = append(fields, slackField{
			Title: fmt.Sprintf("[%s] %s", strings.ToUpper(c.Severity), c.Control),
			Value: fmt.Sprintf("%s → %s", prev, curr),
		})
	}

	blocks := []slackBlock{
		slackHeaderBlock(fmt.Sprintf("%s Compliance Drift Detected", emoji)),
		slackContextBlock(fmt.Sprintf("Organisation *%s* (`%s`)", orgName, orgSlug)),
		slackDivider(),
		slackSectionFields(ptrSlackFields(fields)),
		slackContextBlock(fmt.Sprintf("_Detected at %s · NIS2 / Zero-Trust compliance drift_", time.Now().UTC().Format(time.RFC3339))),
	}
	return map[string]any{
		"attachments": []any{
			map[string]any{"color": color, "blocks": blocks},
		},
	}
}

func ptrSlackFields(fields []slackField) []*slackField {
	out := make([]*slackField, len(fields))
	for i := range fields {
		out[i] = &fields[i]
	}
	return out
}

func teamsComplianceDrift(orgName, orgSlug string, changes []ComplianceDriftChange) any {
	var facts []teamsAdaptiveFact
	for _, c := range changes {
		prev := "(none)"
		if c.Previous != nil && *c.Previous != "" {
			prev = *c.Previous
		}
		curr := "(removed)"
		if c.Current != nil {
			curr = *c.Current
		}
		facts = append(facts, teamsAdaptiveFact{
			Title: fmt.Sprintf("[%s] %s", strings.ToUpper(c.Severity), c.Control),
			Value: fmt.Sprintf("%s → %s", prev, curr),
		})
	}
	return teamsCard(
		"⚠️ Compliance Drift Detected",
		fmt.Sprintf("Organisation **%s** (`%s`) has security control changes that may violate NIS2 / zero-trust policy.", orgName, orgSlug),
		"FF8C00",
		facts,
		nil,
	)
}

// ── Conformance score drop ────────────────────────────────────────────────────

func scoreEmoji(score int) string {
	switch {
	case score >= 90:
		return ":white_check_mark:"
	case score >= 70:
		return ":large_yellow_circle:"
	case score >= 50:
		return ":large_orange_circle:"
	default:
		return ":red_circle:"
	}
}

func scoreLevel(score int) string {
	switch {
	case score >= 90:
		return "Excellent"
	case score >= 70:
		return "Good"
	case score >= 50:
		return "Fair"
	case score >= 30:
		return "Poor"
	default:
		return "Critical"
	}
}

func componentLine(components map[string]any, key, label string, max int) string {
	comp, _ := components[key].(map[string]any)
	score := 0
	if comp != nil {
		if s, ok := comp["score"].(int); ok {
			score = s
		} else if sf, ok := comp["score"].(float64); ok {
			score = int(sf)
		}
	}
	return fmt.Sprintf("%s: %d/%d", label, score, max)
}

func slackConformanceScoreDrop(orgName, orgSlug string, score, threshold int, components map[string]any) any {
	emoji := scoreEmoji(score)
	level := scoreLevel(score)
	fields := []*slackField{
		{Title: "Organisation", Value: fmt.Sprintf("%s (`%s`)", orgName, orgSlug)},
		{Title: "Score", Value: fmt.Sprintf("%s *%d/100* — %s", emoji, score, level)},
		{Title: "Threshold", Value: fmt.Sprintf("%d/100", threshold)},
		{Title: "MFA Adoption",   Value: componentLine(components, "mfa_adoption", "MFA", 30)},
		{Title: "PKCE Clients",   Value: componentLine(components, "pkce_clients", "PKCE", 25)},
		{Title: "DPoP Clients",   Value: componentLine(components, "dpop_clients", "DPoP", 25)},
		{Title: "NIS2 Policies",  Value: componentLine(components, "nis2_policies", "NIS2", 20)},
	}
	blocks := []slackBlock{
		slackHeaderBlock(":rotating_light:  Conformance Score Below Threshold"),
		slackContextBlock(fmt.Sprintf("*Severity: HIGH* — continuous assurance score dropped below %d/100", threshold)),
		slackDivider(),
		slackSectionFields(fields),
	}
	return map[string]any{"blocks": blocks}
}

func teamsConformanceScoreDrop(orgName, orgSlug string, score, threshold int, components map[string]any) any {
	facts := []teamsAdaptiveFact{
		{Title: "Organisation", Value: fmt.Sprintf("%s (%s)", orgName, orgSlug)},
		{Title: "Score", Value: fmt.Sprintf("%d/100 — %s", score, scoreLevel(score))},
		{Title: "Threshold", Value: fmt.Sprintf("%d/100", threshold)},
		{Title: "MFA Adoption",  Value: componentLine(components, "mfa_adoption", "MFA", 30)},
		{Title: "PKCE Clients",  Value: componentLine(components, "pkce_clients", "PKCE", 25)},
		{Title: "DPoP Clients",  Value: componentLine(components, "dpop_clients", "DPoP", 25)},
		{Title: "NIS2 Policies", Value: componentLine(components, "nis2_policies", "NIS2", 20)},
	}
	return teamsCard(
		"🔴 Conformance Score Below Threshold",
		fmt.Sprintf("Organisation **%s** (`%s`) continuous assurance score is **%d/100**, below the configured threshold of **%d/100**.", orgName, orgSlug, score, threshold),
		"D92626",
		facts,
		nil,
	)
}


