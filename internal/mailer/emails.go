package mailer

import (
	"bytes"
	"fmt"
	"html/template"
)

// Transactional email bodies are rendered with html/template so the org name and
// links (which originate from tenant config / request data) are context-escaped.
// This closes the email content-injection vector (CWE-79/CWE-93) that raw
// fmt.Sprintf interpolation into HTML would otherwise open.

type emailData struct {
	OrgName   string
	URL       string
	CancelURL string
}

var (
	tmplPasswordReset = template.Must(template.New("password-reset").Parse(`
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#1a2230">
  <h2 style="color:#1D9E75">Password Reset Request</h2>
  <p>We received a request to reset the password for your <strong>{{.OrgName}}</strong> account.</p>
  <p style="margin:32px 0">
    <a href="{{.URL}}" style="background:#1D9E75;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Reset my password
    </a>
  </p>
  <p style="color:#6b7280;font-size:13px">
    This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email.
  </p>
  <p style="color:#6b7280;font-size:12px">If the button above does not work, copy this URL into your browser:<br>{{.URL}}</p>
</body></html>`))

	tmplEmailVerification = template.Must(template.New("email-verification").Parse(`
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#1a2230">
  <h2 style="color:#1D9E75">Verify your email</h2>
  <p>Welcome to <strong>{{.OrgName}}</strong>! Please verify your email address to continue.</p>
  <p style="margin:32px 0">
    <a href="{{.URL}}" style="background:#1D9E75;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Verify my email
    </a>
  </p>
  <p style="color:#6b7280;font-size:13px">This link expires in 30 minutes.</p>
  <p style="color:#6b7280;font-size:12px">If the button above does not work, copy this URL into your browser:<br>{{.URL}}</p>
</body></html>`))

	tmplErasureConfirmation = template.Must(template.New("erasure-confirmation").Parse(`
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#1a2230">
  <h2 style="color:#dc2626">Account deletion request</h2>
  <p>We received a request to permanently delete your <strong>{{.OrgName}}</strong> account and all associated personal data (GDPR Article 17).</p>
  <p style="margin:32px 0">
    <a href="{{.URL}}" style="background:#dc2626;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Confirm account deletion
    </a>
  </p>
  <p style="color:#6b7280;font-size:13px">
    This confirmation link expires in <strong>24 hours</strong>. If you do not click it, no action will be taken.
  </p>
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0"/>
  <p style="color:#6b7280;font-size:13px">
    <strong>What happens after confirmation?</strong><br>
    Your account will be scheduled for deletion in <strong>30 days</strong>. During this grace period you may cancel the request at any time using the link below.
    After 30 days your personal data will be permanently erased and cannot be recovered.
  </p>
  <p style="margin:16px 0">
    <a href="{{.CancelURL}}" style="color:#6b7280;font-size:13px;text-decoration:underline">
      Cancel deletion request
    </a>
  </p>
  <p style="color:#9ca3af;font-size:12px">If you did not request account deletion, you can safely ignore this email. Your account remains active.</p>
  <p style="color:#9ca3af;font-size:12px">If the button above does not work, copy this URL into your browser:<br>{{.URL}}</p>
</body></html>`))

	tmplUnlockMagicLink = template.Must(template.New("unlock-magic-link").Parse(`
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#1a2230">
  <h2 style="color:#f59e0b">Account Unlock Request</h2>
  <p>An administrator of <strong>{{.OrgName}}</strong> has sent you this link to unlock your account.</p>
  <p>Your account was temporarily locked due to too many failed login attempts or a high-risk login signal.</p>
  <p style="margin:32px 0">
    <a href="{{.URL}}" style="background:#f59e0b;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Unlock my account
    </a>
  </p>
  <p style="color:#6b7280;font-size:13px">
    This link expires in <strong>15 minutes</strong> and can only be used once.
    If your account is already unlocked, clicking the link is harmless.
  </p>
  <p style="color:#6b7280;font-size:13px">
    If you did not expect this email, contact your administrator — do <strong>not</strong> click the link.
  </p>
  <p style="color:#9ca3af;font-size:12px">If the button above does not work, copy this URL into your browser:<br>{{.URL}}</p>
</body></html>`))
)

// renderAndSend executes an email template and delivers the result.
func (m *Mailer) renderAndSend(to, subject string, t *template.Template, data emailData) error {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return fmt.Errorf("mailer: render email: %w", err)
	}
	return m.Send(to, subject, buf.String())
}
