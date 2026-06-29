package handler

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/smtp"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// SMTPHandler manages per-org SMTP configuration.
type SMTPHandler struct {
	repo *repository.SMTPRepository
}

func NewSMTPHandler(pool *pgxpool.Pool) *SMTPHandler {
	return &SMTPHandler{repo: repository.NewSMTPRepository(pool)}
}

// Get returns the current SMTP settings for an org (password is never returned).
// GET /api/v1/organizations/:org_id/smtp
func (h *SMTPHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	settings, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil {
		// Return empty object if not configured yet
		return c.JSON(http.StatusOK, map[string]interface{}{})
	}
	return c.JSON(http.StatusOK, settings)
}

type updateSMTPRequest struct {
	Host        string  `json:"host"         validate:"required,hostname"`
	Port        int     `json:"port"         validate:"required,min=1,max=65535"`
	Username    *string `json:"username"`
	Password    string  `json:"password"` // empty = keep existing
	FromAddress string  `json:"from_address" validate:"required,email"`
	FromName    string  `json:"from_name"    validate:"required,min=1,max=128"`
	UseTLS      bool    `json:"use_tls"`
	IsActive    bool    `json:"is_active"`
}

// Put replaces the SMTP settings for an org.
// PUT /api/v1/organizations/:org_id/smtp
func (h *SMTPHandler) Put(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req updateSMTPRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	s := &models.SMTPSettings{
		OrgID:       orgID,
		Host:        req.Host,
		Port:        req.Port,
		Username:    req.Username,
		FromAddress: req.FromAddress,
		FromName:    req.FromName,
		UseTLS:      req.UseTLS,
		IsActive:    req.IsActive,
	}
	out, err := h.repo.Upsert(c.Request().Context(), s, req.Password)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, out)
}

// Test sends a test email to verify the SMTP configuration.
// POST /api/v1/organizations/:org_id/smtp/test
type testSMTPRequest struct {
	To string `json:"to" validate:"required,email"`
}

func (h *SMTPHandler) Test(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req testSMTPRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	settings, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "SMTP not configured for this organization")
	}
	if err := sendTestEmail(settings, req.To); err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "SMTP test failed: "+err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "Test email sent successfully"})
}

// sendTestEmail delivers a test message using the stored SMTP settings.
// Password is re-fetched from DB (the model's Password field is set by the upsert).
func sendTestEmail(s *models.SMTPSettings, to string) error {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)

	body := fmt.Sprintf("From: %s <%s>\r\nTo: %s\r\nSubject: Clavex SMTP test\r\n\r\nThis is a test email from Clavex IAM. If you received this, SMTP is configured correctly.",
		s.FromName, s.FromAddress, to)

	var auth smtp.Auth
	if s.Username != nil && s.Password != nil {
		auth = smtp.PlainAuth("", *s.Username, *s.Password, s.Host)
	}

	if s.UseTLS {
		tlsCfg := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
		host, _, _ := net.SplitHostPort(addr)
		tlsCfg.ServerName = host
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
				return fmt.Errorf("auth: %w", err)
			}
		}
		if err := client.Mail(s.FromAddress); err != nil {
			return err
		}
		if err := client.Rcpt(to); err != nil {
			return err
		}
		w, err := client.Data()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprint(w, body)
		return w.Close()
	}
	return smtp.SendMail(addr, auth, s.FromAddress, []string{to}, []byte(body))
}
