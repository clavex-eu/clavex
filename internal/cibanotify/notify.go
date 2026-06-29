// Package cibanotify delivers end-user notifications for CIBA authentication
// requests via three channels: HTTP webhook, email (SMTP), and SMS.
//
// When a backchannel authentication request is created, the caller fires
// Notifier.Notify() with the request details. Notifier dispatches to all
// configured channels for the organisation concurrently and returns the first
// non-nil error (other errors are logged but do not block the CIBA flow).
//
// # Notification payload
//
// Every notification contains:
//   - AppName      — the OIDC client's display name
//   - BindingMessage — short text provided by the client (e.g. "Transfer €500")
//   - ApproveURL   — deep link to POST /ciba/:id/approve (via admin console or
//                    a dedicated mobile endpoint)
//   - DenyURL      — deep link to POST /ciba/:id/deny
//   - ExpiresIn    — seconds before the request expires
//
// # Security
//
// Approve/deny URLs embed the auth_req_id (a 32-byte random opaque token).
// They are sent over a pre-configured channel (HTTPS webhook, SMTP, or verified
// phone number) and are single-use — the CIBA approve handler calls Delete()
// after issuing tokens.
//
// Webhook requests are signed with HMAC-SHA256 using a per-org secret
// (X-Clavex-Signature: sha256=<hex>) so the receiver can verify authenticity.
package cibanotify

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
	"time"

	"github.com/rs/zerolog/log"
)

// ── Notification payload ──────────────────────────────────────────────────────

// Params contains all data needed to compose a CIBA notification.
type Params struct {
	// AuthReqID is the auth_req_id (opaque, used in approve/deny URLs).
	AuthReqID string
	// AppName is the OIDC client's display name shown to the user.
	AppName string
	// UserEmail is the resolved end-user email address (for email channel).
	UserEmail string
	// UserPhone is the resolved end-user phone number (E.164, for SMS channel).
	UserPhone string
	// BindingMessage is the short contextual text provided by the client.
	// Example: "Transfer €500 to Alice"
	BindingMessage string
	// ApproveURL is the URL the user clicks/taps to approve the request.
	// For SCA flows using VP-based authentication, VPRequestURI is preferred
	// over ApproveURL — the wallet presents a credential instead of a tap.
	ApproveURL string
	// DenyURL is the URL the user clicks/taps to deny the request.
	DenyURL string
	// ExpiresIn is how many seconds until the auth_req expires.
	ExpiresIn int
	// DeviceTokens is the list of mobile push tokens registered for the
	// target user (populated by the handler from ciba_device_tokens).
	// Used by the PushSender channel; ignored by other channels.
	DeviceTokens []DeviceToken
	// VPRequestURI is the OID4VP authorization request URI used for
	// CIBA+OID4VP SCA flows.  When non-empty the wallet app opens this URI
	// instead of showing a simple approve/deny prompt.
	// Format: openid4vp://?request_uri=<request_uri>
	// The wallet presents the required credential (e.g. CIE mdoc), Clavex
	// verifies the presentation and auto-approves the CIBA request.
	// Empty for classic CIBA flows.
	VPRequestURI string
}

// ── Channel interfaces ────────────────────────────────────────────────────────

// WebhookSender delivers the notification as an HMAC-signed HTTP POST.
type WebhookSender interface {
	SendWebhook(ctx context.Context, p Params) error
}

// EmailSender delivers the notification via transactional email.
type EmailSender interface {
	SendEmail(ctx context.Context, p Params) error
}

// SMSSender delivers the notification via SMS.
type SMSSender interface {
	SendSMS(ctx context.Context, p Params) error
}

// ── Multi-channel notifier ────────────────────────────────────────────────────

// Notifier dispatches CIBA approval notifications over one or more channels.
// All nil channels are silently skipped.
type Notifier struct {
	webhook WebhookSender
	email   EmailSender
	sms     SMSSender
	push    PushSender
}

// New creates a Notifier with the provided channel implementations.
// Pass nil for any channel that is not configured.
func New(webhook WebhookSender, email EmailSender, sms SMSSender) *Notifier {
	return &Notifier{webhook: webhook, email: email, sms: sms}
}

// WithPush attaches a push notification channel (APNs / FCM).
func (n *Notifier) WithPush(p PushSender) *Notifier {
	n.push = p
	return n
}

// Notify dispatches the notification to all configured channels.
// It runs webhook, email, and SMS concurrently and waits for all to finish.
// Returns the first non-nil error; other errors are logged.
func (n *Notifier) Notify(ctx context.Context, p Params) error {
	type result struct{ err error }
	ch := make(chan result, 3)
	sent := 0

	if n.webhook != nil {
		sent++
		go func() {
			err := n.webhook.SendWebhook(ctx, p)
			if err != nil {
				log.Warn().Err(err).Str("auth_req_id", p.AuthReqID).Msg("ciba-notify: webhook failed")
			}
			ch <- result{err}
		}()
	}
	if n.email != nil && p.UserEmail != "" {
		sent++
		go func() {
			err := n.email.SendEmail(ctx, p)
			if err != nil {
				log.Warn().Err(err).Str("auth_req_id", p.AuthReqID).Msg("ciba-notify: email failed")
			}
			ch <- result{err}
		}()
	}
	if n.sms != nil && p.UserPhone != "" {
		sent++
		go func() {
			err := n.sms.SendSMS(ctx, p)
			if err != nil {
				log.Warn().Err(err).Str("auth_req_id", p.AuthReqID).Msg("ciba-notify: sms failed")
			}
			ch <- result{err}
		}()
	}
	if n.push != nil && len(p.DeviceTokens) > 0 {
		sent++
		go func() {
			err := n.push.SendPush(ctx, p)
			if err != nil {
				log.Warn().Err(err).Str("auth_req_id", p.AuthReqID).Msg("ciba-notify: push failed")
			}
			ch <- result{err}
		}()
	}

	if sent == 0 {
		log.Debug().Str("auth_req_id", p.AuthReqID).Msg("ciba-notify: no channel configured — skipping notification")
		return nil
	}

	var firstErr error
	for i := 0; i < sent; i++ {
		r := <-ch
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
	}
	return firstErr
}

// ── Webhook implementation ────────────────────────────────────────────────────

const (
	webhookTimeout   = 10 * time.Second
	webhookUserAgent = "Clavex-CIBA-Notify/1.0"
)

// WebhookConfig holds the per-org webhook notification configuration.
type WebhookConfig struct {
	// URL is the HTTPS endpoint that will receive the POST.
	URL string
	// Secret is the HMAC-SHA256 signing secret (at least 32 bytes recommended).
	// Used to set the X-Clavex-Signature header.
	// Optional — if empty, the header is omitted.
	Secret string
	// Headers are extra HTTP headers forwarded with every request
	// (e.g. "Authorization": "Bearer <token>").
	Headers map[string]string
}

// WebhookPayload is the JSON body POSTed to the org's notification webhook.
type WebhookPayload struct {
	Event          string `json:"event"`           // always "ciba.authentication_request"
	AuthReqID      string `json:"auth_req_id"`
	AppName        string `json:"app_name"`
	UserEmail      string `json:"user_email,omitempty"`
	BindingMessage string `json:"binding_message,omitempty"`
	ApproveURL     string `json:"approve_url"`
	DenyURL        string `json:"deny_url"`
	ExpiresIn      int    `json:"expires_in"`
	IssuedAt       int64  `json:"issued_at"` // Unix timestamp
}

// WebhookChannel implements WebhookSender.
type WebhookChannel struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewWebhookChannel creates a WebhookChannel.
func NewWebhookChannel(cfg WebhookConfig) *WebhookChannel {
	return &WebhookChannel{
		cfg:    cfg,
		client: &http.Client{Timeout: webhookTimeout},
	}
}

// SendWebhook signs and delivers the CIBA notification to the configured URL.
func (w *WebhookChannel) SendWebhook(ctx context.Context, p Params) error {
	payload := WebhookPayload{
		Event:          "ciba.authentication_request",
		AuthReqID:      p.AuthReqID,
		AppName:        p.AppName,
		UserEmail:      p.UserEmail,
		BindingMessage: p.BindingMessage,
		ApproveURL:     p.ApproveURL,
		DenyURL:        p.DenyURL,
		ExpiresIn:      p.ExpiresIn,
		IssuedAt:       time.Now().Unix(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("ciba webhook: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ciba webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", webhookUserAgent)

	// HMAC-SHA256 signature (same scheme as Stripe / GitHub webhooks).
	if w.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.cfg.Secret))
		mac.Write(body)
		req.Header.Set("X-Clavex-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	for k, v := range w.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("ciba webhook: send: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		log.Debug().Err(err).Msg("ciba webhook: discard body")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ciba webhook: server returned %d", resp.StatusCode)
	}
	return nil
}

// ── Email implementation ──────────────────────────────────────────────────────

// RawMailSender is the subset of mailer.Mailer that the email channel needs.
// Decouples this package from the mailer package (avoids import cycle).
type RawMailSender interface {
	Send(to, subject, htmlBody string) error
}

// EmailChannel implements EmailSender using an org SMTP mailer.
type EmailChannel struct {
	mailer  RawMailSender
	fromApp string // used in the email subject
}

// NewEmailChannel creates an EmailChannel.
// fromApp is the display name embedded in the subject line.
func NewEmailChannel(mailer RawMailSender, fromApp string) *EmailChannel {
	return &EmailChannel{mailer: mailer, fromApp: fromApp}
}

// SendEmail delivers an HTML approval email to the user.
func (e *EmailChannel) SendEmail(_ context.Context, p Params) error {
	subject := fmt.Sprintf("Richiesta di accesso da %s", p.AppName)
	html := cibaEmailHTML(p)
	if err := e.mailer.Send(p.UserEmail, subject, html); err != nil {
		return fmt.Errorf("ciba email: %w", err)
	}
	return nil
}

func cibaEmailHTML(p Params) string {
	binding := ""
	if p.BindingMessage != "" {
		binding = fmt.Sprintf(`<p style="font-size:16px;color:#374151;background:#f3f4f6;border-radius:6px;padding:12px 16px;font-style:italic;">&#8220;%s&#8221;</p>`, p.BindingMessage)
	}
	return strings.Join([]string{
		`<!DOCTYPE html><html lang="it"><head><meta charset="UTF-8"/>`,
		`<meta name="viewport" content="width=device-width,initial-scale=1.0"/>`,
		`<title>Richiesta di accesso</title></head>`,
		`<body style="margin:0;padding:0;background:#f9fafb;font-family:system-ui,-apple-system,sans-serif;">`,
		`<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 16px;">`,
		`<table width="100%" style="max-width:480px;background:#ffffff;border-radius:12px;`,
		`box-shadow:0 1px 3px rgba(0,0,0,.1);overflow:hidden;">`,
		// Header
		`<tr><td style="background:#5DCAA5;padding:24px 32px;">`,
		`<p style="margin:0;font-size:13px;color:rgba(255,255,255,.85);letter-spacing:.08em;text-transform:uppercase;">Clavex Identity</p>`,
		`<h1 style="margin:8px 0 0;font-size:22px;font-weight:700;color:#ffffff;">Richiesta di accesso</h1>`,
		`</td></tr>`,
		// Body
		`<tr><td style="padding:32px;">`,
		fmt.Sprintf(`<p style="margin:0 0 12px;font-size:15px;color:#374151;"><strong>%s</strong> richiede di autenticarti.</p>`, p.AppName),
		binding,
		`<p style="margin:16px 0 4px;font-size:13px;color:#6b7280;">Questa richiesta scade tra `,
		fmt.Sprintf(`<strong>%d secondi</strong>.</p>`, p.ExpiresIn),
		// Buttons
		`<table style="margin:24px 0 0;width:100%"><tr>`,
		fmt.Sprintf(`<td style="padding-right:8px;"><a href="%s" style="display:block;text-align:center;background:#5DCAA5;color:#ffffff;`, p.ApproveURL),
		`text-decoration:none;font-weight:600;font-size:15px;padding:12px;border-radius:8px;">`,
		`&#10003; Approva</a></td>`,
		fmt.Sprintf(`<td style="padding-left:8px;"><a href="%s" style="display:block;text-align:center;background:#f3f4f6;color:#374151;`, p.DenyURL),
		`text-decoration:none;font-weight:600;font-size:15px;padding:12px;border-radius:8px;">`,
		`&#10007; Nega</a></td>`,
		`</tr></table>`,
		`<p style="margin:24px 0 0;font-size:12px;color:#9ca3af;">Se non riconosci questa richiesta, ignora questa email o clicca <a href="`,
		fmt.Sprintf(`%s" style="color:#6b7280;">Nega</a>.</p>`, p.DenyURL),
		`</td></tr>`,
		// Footer
		`<tr><td style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb;">`,
		`<p style="margin:0;font-size:11px;color:#9ca3af;">Clavex Identity Platform &mdash; non rispondere a questa email.</p>`,
		`</td></tr></table></td></tr></table></body></html>`,
	}, "")
}

// ── SMS implementation ────────────────────────────────────────────────────────

// RawSMSSender is the subset of sms.Provider needed by the SMS channel.
type RawSMSSender interface {
	Send(ctx context.Context, to, body string) error
}

// SMSChannel implements SMSSender using an org SMS provider.
type SMSChannel struct {
	provider RawSMSSender
}

// NewSMSChannel creates an SMSChannel.
func NewSMSChannel(provider RawSMSSender) *SMSChannel {
	return &SMSChannel{provider: provider}
}

// SendSMS delivers a short approval SMS to the user's phone number.
// The message contains a plain-text binding_message and the approve URL only
// (deny = ignore). The approve URL should be a short URL or deep link.
func (s *SMSChannel) SendSMS(ctx context.Context, p Params) error {
	body := fmt.Sprintf("Clavex: %s richiede il tuo accesso", p.AppName)
	if p.BindingMessage != "" {
		body = fmt.Sprintf("Clavex: %s — %s", p.AppName, p.BindingMessage)
	}
	body += fmt.Sprintf("\nApprova: %s\nNega: %s", p.ApproveURL, p.DenyURL)

	// Truncate to 160 chars (single SMS segment) — prefer the approve link.
	if len(body) > 160 {
		body = body[:157] + "..."
	}

	if err := s.provider.Send(ctx, p.UserPhone, body); err != nil {
		return fmt.Errorf("ciba sms: %w", err)
	}
	return nil
}
