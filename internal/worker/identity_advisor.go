package worker

// IdentityAdvisorWorker generates a weekly AI-powered identity risk report for
// every active organization that has an Anthropic API key configured.
//
// For each org the worker:
//   1. Gathers security signals from the past 7 days (login anomalies, admin
//      hygiene issues, OAuth2 client risks, conformance score, policy drift).
//   2. Sends the signals to Claude (using the org's own Anthropic key) and asks
//      for a structured CISO-level executive summary with the top-5 prioritised
//      risks and recommended actions.
//   3. Delivers the report by email to all active admin users of the org via
//      the org-configured SMTP server.
//
// Schedule: fires every Monday at 08:00 UTC (checked once per hour).
// If SMTP is not configured, or the org has no Anthropic key, the report is
// silently skipped for that org — no error is propagated.
//
// The report is also available on-demand via the MCP tool `clavex_identity_advisor`.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	advisorCheckInterval = 1 * time.Hour // how often we check whether it's Monday 08:xx UTC
	advisorWindowDays    = 7             // analysis window in days
)

// IdentityAdvisorDeps are optional collaborators for the advisor worker.
type IdentityAdvisorDeps struct {
	// BaseURL is the public root URL used to build deep-link buttons in the report.
	// e.g. "https://admin.example.com"
	BaseURL string
}

// RunIdentityAdvisorWorker starts the weekly AI identity risk report goroutine.
// Call as `go RunIdentityAdvisorWorker(ctx, pool, deps)`.
func RunIdentityAdvisorWorker(ctx context.Context, pool *pgxpool.Pool, deps IdentityAdvisorDeps) {
	ticker := time.NewTicker(advisorCheckInterval)
	defer ticker.Stop()

	log.Info().Str("interval", advisorCheckInterval.String()).
		Msg("identity-advisor-worker: started (fires Mondays ~08:00 UTC)")

	// Do NOT fire immediately on startup to avoid flooding inboxes on every
	// server restart. Wait for the first Monday 08:xx UTC tick.
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("identity-advisor-worker: stopping")
			return
		case t := <-ticker.C:
			utc := t.UTC()
			if utc.Weekday() == time.Monday && utc.Hour() == 8 {
				log.Info().Msg("identity-advisor-worker: running weekly scan")
				runAdvisorForAllOrgs(ctx, pool, deps)
			}
		}
	}
}

// GenerateAdvisorReport generates the AI identity risk report for a single org
// and returns it as a plain-text markdown string. This is the shared function
// used by both the worker (weekly email) and the MCP tool (on-demand).
func GenerateAdvisorReport(
	ctx context.Context,
	pool *pgxpool.Pool,
	orgID uuid.UUID,
	periodDays int,
) (string, *repository.AdvisorSignals, error) {
	if periodDays <= 0 {
		periodDays = advisorWindowDays
	}
	since := time.Now().UTC().Add(-time.Duration(periodDays) * 24 * time.Hour)

	advisorRepo := repository.NewIdentityAdvisorRepository(pool)
	signals, err := advisorRepo.GatherSignals(ctx, orgID, since)
	if err != nil {
		return "", nil, fmt.Errorf("gather signals: %w", err)
	}

	// Fetch the org's Anthropic key.
	orgsRepo := repository.NewOrgRepository(pool)
	apiKey, err := orgsRepo.GetAIKey(ctx, orgID)
	if err != nil || apiKey == nil || *apiKey == "" {
		return "", signals, fmt.Errorf("no Anthropic API key configured for org %s", orgID)
	}

	report, err := callAdvisorClaude(ctx, *apiKey, signals, periodDays)
	if err != nil {
		return "", signals, fmt.Errorf("claude: %w", err)
	}
	return report, signals, nil
}

// runAdvisorForAllOrgs iterates every active org, generates the report, and
// delivers it by email to admin users.
func runAdvisorForAllOrgs(ctx context.Context, pool *pgxpool.Pool, deps IdentityAdvisorDeps) {
	driftRepo := repository.NewComplianceDriftRepository(pool)
	orgIDs, err := driftRepo.AllActiveOrgIDs(ctx)
	if err != nil {
		log.Error().Err(err).Msg("identity-advisor-worker: list orgs failed")
		return
	}
	smtpRepo := repository.NewSMTPRepository(pool)

	for _, orgID := range orgIDs {
		reportText, signals, err := GenerateAdvisorReport(ctx, pool, orgID, advisorWindowDays)
		if err != nil {
			// Log at debug level — missing key / SMTP are expected in dev.
			log.Debug().Err(err).Str("org_id", orgID.String()).
				Msg("identity-advisor-worker: skipped org")
			continue
		}
		if err := deliverAdvisorEmail(ctx, smtpRepo, orgID, signals, reportText, deps.BaseURL); err != nil {
			log.Warn().Err(err).Str("org_id", orgID.String()).
				Msg("identity-advisor-worker: email delivery failed")
		}
	}
}

// callAdvisorClaude sends the gathered signals to Claude and returns the
// formatted risk report as a markdown string.
func callAdvisorClaude(
	ctx context.Context,
	apiKey string,
	signals *repository.AdvisorSignals,
	periodDays int,
) (string, error) {
	// Serialise signals to JSON for the prompt — compact but human-readable.
	signalsJSON, err := json.MarshalIndent(signals, "", "  ")
	if err != nil {
		return "", err
	}

	systemPrompt := `You are a senior CISO-level security advisor specialising in identity and access management (IAM), zero-trust architecture, and NIS2 / eIDAS 2 compliance.

You receive structured weekly security telemetry from an identity platform (Clavex) and produce a concise, actionable executive risk report addressed to the organisation's CISO or IT security lead.

Your reports must be:
- Factual: base every claim on the signals provided, cite exact numbers
- Prioritised: rank risks by actual exploitability and business impact, not theoretical severity
- Actionable: each risk must include a concrete remediation step (< 3 sentences)
- Executive: no jargon without explanation; a CISO with 10 minutes should be able to act on it

Output format (Markdown):

## Weekly Identity Risk Report — {org_name}
**Period:** {date_range}  
**Overall Risk Level:** CRITICAL | HIGH | MEDIUM | LOW

### Executive Summary
(2–4 sentences: what changed, what's the top concern, overall posture direction)

### Top Risks
(up to 5, numbered, ordered by priority)

**1. {Risk Title}** — Severity: {CRITICAL|HIGH|MEDIUM|LOW}
*What it means:* ...
*Recommended action:* ...

### Quick Wins (< 1 hour each)
(bullet list of 3 immediate actions)

### Trend Note
(1 sentence: is posture improving, degrading, or stable compared to what the data suggests)`

	userMsg := fmt.Sprintf(
		"Analyse the following security signals and generate the weekly identity risk report.\n\n"+
			"Analysis period: past %d days\n\n"+
			"```json\n%s\n```",
		periodDays, string(signalsJSON),
	)

	client := anthropic.NewClient(option.WithAPIKey(apiKey))
	msg, err := client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeOpus4_7,
		MaxTokens: 2048,
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
		return "", fmt.Errorf("anthropic messages.new: %w", err)
	}
	for _, block := range msg.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			return tb.Text, nil
		}
	}
	return "", fmt.Errorf("anthropic: no text content in response")
}

// deliverAdvisorEmail sends the AI report to all admin users of the org.
func deliverAdvisorEmail(
	ctx context.Context,
	smtpRepo *repository.SMTPRepository,
	orgID uuid.UUID,
	signals *repository.AdvisorSignals,
	reportText string,
	baseURL string,
) error {
	m, err := mailer.ForOrg(ctx, smtpRepo, orgID)
	if err != nil {
		return fmt.Errorf("smtp not configured: %w", err)
	}
	if len(signals.AdminEmails) == 0 {
		return fmt.Errorf("no admin recipients for org %s", orgID)
	}

	subject := fmt.Sprintf(
		"[Clavex] Weekly Identity Risk Report — %s (%s)",
		signals.OrgName,
		signals.Until.Format("2 Jan 2006"),
	)

	riskLevel := extractRiskLevel(reportText)
	htmlBody := buildAdvisorEmailHTML(signals, reportText, riskLevel, baseURL)

	var sendErr error
	for _, email := range signals.AdminEmails {
		if err := m.Send(email, subject, htmlBody); err != nil {
			log.Warn().Err(err).Str("to", email).Msg("identity-advisor: email send failed")
			sendErr = err
		}
	}
	return sendErr
}

// extractRiskLevel scans the report for the "Overall Risk Level:" marker and
// returns the level string (CRITICAL, HIGH, MEDIUM, LOW). Falls back to "MEDIUM".
func extractRiskLevel(report string) string {
	for _, line := range strings.Split(report, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Overall Risk Level:") || strings.Contains(line, "**Overall Risk Level:**") {
			for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
				if strings.Contains(strings.ToUpper(line), level) {
					return level
				}
			}
		}
	}
	return "MEDIUM"
}

// buildAdvisorEmailHTML wraps the markdown report in a clean responsive HTML email.
// The markdown is rendered as preformatted text (no external library required).
func buildAdvisorEmailHTML(
	signals *repository.AdvisorSignals,
	reportMarkdown string,
	riskLevel string,
	baseURL string,
) string {
	riskColor := map[string]string{
		"CRITICAL": "#dc2626",
		"HIGH":     "#ea580c",
		"MEDIUM":   "#d97706",
		"LOW":      "#16a34a",
	}
	color := riskColor[riskLevel]
	if color == "" {
		color = "#d97706"
	}

	// Simple markdown → HTML conversion for the subset we produce:
	// ##/###, **bold**, *italic*, - bullets, blank lines → <p>
	html := markdownToHTML(reportMarkdown)

	var dashboardLink string
	if baseURL != "" {
		dashboardLink = fmt.Sprintf(
			`<p style="text-align:center;margin-top:24px;">
			  <a href="%s/organizations/%s/security" style="background:#1e40af;color:#fff;padding:10px 22px;border-radius:6px;text-decoration:none;font-weight:600;">
			    View Security Dashboard →
			  </a>
			</p>`, baseURL, signals.OrgID,
		)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Weekly Identity Risk Report</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111827;">
<table width="100%%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:32px 0;">
<tr><td align="center">
<table width="620" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">
  <!-- Header -->
  <tr><td style="background:#1e40af;padding:28px 36px;">
    <p style="margin:0;font-size:13px;color:#bfdbfe;letter-spacing:.08em;text-transform:uppercase;">Powered by Clavex</p>
    <h1 style="margin:6px 0 0;font-size:22px;color:#fff;font-weight:700;">Weekly Identity Risk Report</h1>
    <p style="margin:4px 0 0;font-size:14px;color:#93c5fd;">%s &nbsp;·&nbsp; %s – %s</p>
  </td></tr>
  <!-- Risk badge -->
  <tr><td style="padding:20px 36px 0;">
    <span style="display:inline-block;background:%s;color:#fff;font-size:13px;font-weight:700;padding:4px 14px;border-radius:20px;letter-spacing:.05em;">
      RISK LEVEL: %s
    </span>
  </td></tr>
  <!-- Key stats -->
  <tr><td style="padding:20px 36px;">
    <table width="100%%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center" style="background:#f9fafb;border-radius:8px;padding:16px;width:25%%;">
          <p style="margin:0;font-size:28px;font-weight:700;color:#1e40af;">%d</p>
          <p style="margin:4px 0 0;font-size:12px;color:#6b7280;">Total Logins</p>
        </td>
        <td width="12"></td>
        <td align="center" style="background:#fef2f2;border-radius:8px;padding:16px;width:25%%;">
          <p style="margin:0;font-size:28px;font-weight:700;color:#dc2626;">%d</p>
          <p style="margin:4px 0 0;font-size:12px;color:#6b7280;">Failed Logins</p>
        </td>
        <td width="12"></td>
        <td align="center" style="background:#fff7ed;border-radius:8px;padding:16px;width:25%%;">
          <p style="margin:0;font-size:28px;font-weight:700;color:#ea580c;">%d</p>
          <p style="margin:4px 0 0;font-size:12px;color:#6b7280;">Admins w/o MFA</p>
        </td>
        <td width="12"></td>
        <td align="center" style="background:#f0fdf4;border-radius:8px;padding:16px;width:25%%;">
          <p style="margin:0;font-size:28px;font-weight:700;color:#16a34a;">%d</p>
          <p style="margin:4px 0 0;font-size:12px;color:#6b7280;">Conformance Score</p>
        </td>
      </tr>
    </table>
  </td></tr>
  <!-- AI Report body -->
  <tr><td style="padding:0 36px 28px;">
    <div style="font-size:15px;line-height:1.7;color:#1f2937;">
      %s
    </div>
    %s
  </td></tr>
  <!-- Footer -->
  <tr><td style="background:#f9fafb;padding:16px 36px;border-top:1px solid #e5e7eb;">
    <p style="margin:0;font-size:12px;color:#9ca3af;">
      This report was generated by Clavex AI Identity Advisor using your Anthropic API key.
      The analysis covers the period %s – %s.
      To unsubscribe, remove admin role assignments or disable SMTP in the Clavex console.
    </p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`,
		signals.OrgName,
		signals.Since.Format("2 Jan"),
		signals.Until.Format("2 Jan 2006"),
		color, riskLevel,
		signals.TotalLogins,
		signals.FailedLogins,
		len(signals.AdminsWithoutMFA),
		conformanceScoreInt(signals),
		html,
		dashboardLink,
		signals.Since.Format("2 Jan 2006"),
		signals.Until.Format("2 Jan 2006"),
	)
}

func conformanceScoreInt(s *repository.AdvisorSignals) int {
	if s.ConformanceScore == nil {
		return 0
	}
	return s.ConformanceScore.Score
}

// markdownToHTML converts the subset of markdown produced by Claude into HTML.
// This handles: ## headings, **bold**, *italic*, - bullet lists, blank lines.
// No external library needed.
func markdownToHTML(md string) string {
	var sb strings.Builder
	lines := strings.Split(md, "\n")
	inList := false

	for _, raw := range lines {
		line := raw

		// Headings
		if strings.HasPrefix(line, "### ") {
			if inList {
				sb.WriteString("</ul>\n")
				inList = false
			}
			sb.WriteString("<h3 style=\"margin:20px 0 6px;font-size:16px;color:#1e40af;\">")
			sb.WriteString(inlineFormat(line[4:]))
			sb.WriteString("</h3>\n")
			continue
		}
		if strings.HasPrefix(line, "## ") {
			if inList {
				sb.WriteString("</ul>\n")
				inList = false
			}
			sb.WriteString("<h2 style=\"margin:24px 0 8px;font-size:18px;color:#111827;border-bottom:2px solid #e5e7eb;padding-bottom:6px;\">")
			sb.WriteString(inlineFormat(line[3:]))
			sb.WriteString("</h2>\n")
			continue
		}
		// Bullet list items
		if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
			if !inList {
				sb.WriteString("<ul style=\"margin:8px 0;padding-left:20px;\">\n")
				inList = true
			}
			sb.WriteString("<li style=\"margin:4px 0;\">")
			sb.WriteString(inlineFormat(line[2:]))
			sb.WriteString("</li>\n")
			continue
		}
		// Numbered list items
		if len(line) > 3 && line[1] == '.' && line[0] >= '1' && line[0] <= '9' {
			if !inList {
				sb.WriteString("<ol style=\"margin:8px 0;padding-left:20px;\">\n")
				inList = true
			}
			sb.WriteString("<li style=\"margin:6px 0;\">")
			sb.WriteString(inlineFormat(strings.TrimSpace(line[2:])))
			sb.WriteString("</li>\n")
			continue
		}
		// Blank line: close any open list, paragraph break
		if strings.TrimSpace(line) == "" {
			if inList {
				sb.WriteString("</ul>\n")
				inList = false
			}
			sb.WriteString("<br>\n")
			continue
		}
		// Horizontal rule
		if line == "---" || line == "***" {
			if inList {
				sb.WriteString("</ul>\n")
				inList = false
			}
			sb.WriteString("<hr style=\"border:none;border-top:1px solid #e5e7eb;margin:16px 0;\">\n")
			continue
		}
		// Normal paragraph line
		if inList {
			sb.WriteString("</ul>\n")
			inList = false
		}
		sb.WriteString("<p style=\"margin:6px 0;\">")
		sb.WriteString(inlineFormat(line))
		sb.WriteString("</p>\n")
	}

	if inList {
		sb.WriteString("</ul>\n")
	}
	return sb.String()
}

// inlineFormat applies **bold**, *italic*, and `code` inline formatting.
func inlineFormat(s string) string {
	// Escape HTML special chars first.
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")

	// **bold**
	for strings.Contains(s, "**") {
		i := strings.Index(s, "**")
		j := strings.Index(s[i+2:], "**")
		if j < 0 {
			break
		}
		inner := s[i+2 : i+2+j]
		s = s[:i] + "<strong>" + inner + "</strong>" + s[i+2+j+2:]
	}
	// *italic* (single star, not already bold)
	for strings.Contains(s, "*") {
		i := strings.Index(s, "*")
		j := strings.Index(s[i+1:], "*")
		if j < 0 {
			break
		}
		inner := s[i+1 : i+1+j]
		s = s[:i] + "<em>" + inner + "</em>" + s[i+1+j+1:]
	}
	// `code`
	for strings.Contains(s, "`") {
		i := strings.Index(s, "`")
		j := strings.Index(s[i+1:], "`")
		if j < 0 {
			break
		}
		inner := s[i+1 : i+1+j]
		s = s[:i] + `<code style="background:#f3f4f6;padding:1px 5px;border-radius:3px;font-size:13px;">` + inner + "</code>" + s[i+1+j+1:]
	}
	return s
}
