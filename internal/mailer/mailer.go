// Package mailer delivers transactional emails via an org-configured SMTP server.
package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
)

// Mailer sends transactional emails using an org's SMTP configuration.
type Mailer struct {
	settings *models.SMTPSettings
}

// ForOrg creates a Mailer loaded with the org's SMTP settings (including password).
// Returns an error if SMTP is not configured or not active for the org.
func ForOrg(ctx context.Context, smtpRepo *repository.SMTPRepository, orgID uuid.UUID) (*Mailer, error) {
	s, err := smtpRepo.GetWithPassword(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("smtp not configured for org %s: %w", orgID, err)
	}
	if !s.IsActive {
		return nil, fmt.Errorf("smtp is disabled for org %s", orgID)
	}
	if s.Host == "" {
		return nil, fmt.Errorf("smtp host not set for org %s", orgID)
	}
	return &Mailer{settings: s}, nil
}

// Send delivers a single email.
func (m *Mailer) Send(to, subject, htmlBody string) error {
	s := m.settings
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)

	fromDisplay := s.FromName + " <" + s.FromAddress + ">"
	msg := strings.Join([]string{
		"From: " + fromDisplay,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"",
		htmlBody,
	}, "\r\n")

	var auth smtp.Auth
	if s.Username != nil && s.Password != nil && *s.Username != "" {
		auth = smtp.PlainAuth("", *s.Username, *s.Password, s.Host)
	}

	if s.UseTLS {
		return m.sendTLS(addr, auth, s.FromAddress, to, []byte(msg))
	}
	return smtp.SendMail(addr, auth, s.FromAddress, []string{to}, []byte(msg))
}

func (m *Mailer) sendTLS(addr string, auth smtp.Auth, from, to string, msg []byte) error {
	s := m.settings
	host, _, _ := net.SplitHostPort(addr)
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}

	conn, err := tls.Dial("tcp", addr, tlsCfg) //nolint:noctx
	if err != nil {
		return fmt.Errorf("TLS dial: %w", err)
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP client: %w", err)
	}
	defer client.Quit() //nolint:errcheck

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}
	_ = s // used above
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}

// SendPasswordReset delivers a password-reset email.
func (m *Mailer) SendPasswordReset(to, orgName, resetURL string) error {
	subject := "Reset your " + orgName + " password"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#1a2230">
  <h2 style="color:#1D9E75">Password Reset Request</h2>
  <p>We received a request to reset the password for your <strong>%s</strong> account.</p>
  <p style="margin:32px 0">
    <a href="%s" style="background:#1D9E75;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Reset my password
    </a>
  </p>
  <p style="color:#6b7280;font-size:13px">
    This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email.
  </p>
  <p style="color:#6b7280;font-size:12px">If the button above does not work, copy this URL into your browser:<br>%s</p>
</body></html>`, orgName, resetURL, resetURL)
	return m.Send(to, subject, body)
}

// SendEmailVerification delivers an email verification link.
func (m *Mailer) SendEmailVerification(to, orgName, verifyURL string) error {
	subject := "Verify your " + orgName + " email address"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#1a2230">
  <h2 style="color:#1D9E75">Verify your email</h2>
  <p>Welcome to <strong>%s</strong>! Please verify your email address to continue.</p>
  <p style="margin:32px 0">
    <a href="%s" style="background:#1D9E75;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Verify my email
    </a>
  </p>
  <p style="color:#6b7280;font-size:13px">This link expires in 30 minutes.</p>
  <p style="color:#6b7280;font-size:12px">If the button above does not work, copy this URL into your browser:<br>%s</p>
</body></html>`, orgName, verifyURL, verifyURL)
	return m.Send(to, subject, body)
}

// SendErasureConfirmation delivers the GDPR Art.17 erasure confirmation email.
// confirmURL is the one-time link the user must click to schedule erasure.
// cancelURL is a link the user can click during the 30-day grace period to cancel.
func (m *Mailer) SendErasureConfirmation(to, orgName, confirmURL, cancelURL string) error {
	subject := "Confirm account deletion — " + orgName
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#1a2230">
  <h2 style="color:#dc2626">Account deletion request</h2>
  <p>We received a request to permanently delete your <strong>%s</strong> account and all associated personal data (GDPR Article 17).</p>
  <p style="margin:32px 0">
    <a href="%s" style="background:#dc2626;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
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
    <a href="%s" style="color:#6b7280;font-size:13px;text-decoration:underline">
      Cancel deletion request
    </a>
  </p>
  <p style="color:#9ca3af;font-size:12px">If you did not request account deletion, you can safely ignore this email. Your account remains active.</p>
  <p style="color:#9ca3af;font-size:12px">If the button above does not work, copy this URL into your browser:<br>%s</p>
</body></html>`, orgName, confirmURL, cancelURL, confirmURL)
	return m.Send(to, subject, body)
}

// SendUnlockMagicLink delivers a one-time account-unlock link to a locked user.
// The link is valid for 15 minutes and clears the adaptive lockout on click.
func (m *Mailer) SendUnlockMagicLink(to, orgName, unlockURL string) error {
	subject := "Unlock your " + orgName + " account"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;color:#1a2230">
  <h2 style="color:#f59e0b">Account Unlock Request</h2>
  <p>An administrator of <strong>%s</strong> has sent you this link to unlock your account.</p>
  <p>Your account was temporarily locked due to too many failed login attempts or a high-risk login signal.</p>
  <p style="margin:32px 0">
    <a href="%s" style="background:#f59e0b;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
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
  <p style="color:#9ca3af;font-size:12px">If the button above does not work, copy this URL into your browser:<br>%s</p>
</body></html>`, orgName, unlockURL, unlockURL)
	return m.Send(to, subject, body)
}
