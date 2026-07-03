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

	// Sanitize all header values to prevent SMTP header / email injection.
	toAddr, err := SanitizeAddress(to)
	if err != nil {
		return err
	}
	fromAddr, err := SanitizeAddress(s.FromAddress)
	if err != nil {
		return err
	}
	to = toAddr

	fromDisplay := SanitizeHeader(s.FromName) + " <" + fromAddr + ">"
	msg := strings.Join([]string{
		"From: " + fromDisplay,
		"To: " + toAddr,
		"Subject: " + SanitizeHeader(subject),
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
		return m.sendTLS(addr, auth, fromAddr, to, []byte(msg))
	}
	return smtp.SendMail(addr, auth, fromAddr, []string{to}, []byte(msg))
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
	return m.renderAndSend(to, "Reset your "+orgName+" password",
		tmplPasswordReset, emailData{OrgName: orgName, URL: resetURL})
}

// SendEmailVerification delivers an email verification link.
func (m *Mailer) SendEmailVerification(to, orgName, verifyURL string) error {
	return m.renderAndSend(to, "Verify your "+orgName+" email address",
		tmplEmailVerification, emailData{OrgName: orgName, URL: verifyURL})
}

// SendErasureConfirmation delivers the GDPR Art.17 erasure confirmation email.
// confirmURL is the one-time link the user must click to schedule erasure.
// cancelURL is a link the user can click during the 30-day grace period to cancel.
func (m *Mailer) SendErasureConfirmation(to, orgName, confirmURL, cancelURL string) error {
	return m.renderAndSend(to, "Confirm account deletion — "+orgName,
		tmplErasureConfirmation, emailData{OrgName: orgName, URL: confirmURL, CancelURL: cancelURL})
}

// SendUnlockMagicLink delivers a one-time account-unlock link to a locked user.
// The link is valid for 15 minutes and clears the adaptive lockout on click.
func (m *Mailer) SendUnlockMagicLink(to, orgName, unlockURL string) error {
	return m.renderAndSend(to, "Unlock your "+orgName+" account",
		tmplUnlockMagicLink, emailData{OrgName: orgName, URL: unlockURL})
}
