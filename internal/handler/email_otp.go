package handler

import (
	"html"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/lockout"
	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

const emailOTPTTL = 10 * time.Minute

var emailOTPRequestTmpl = template.Must(
	template.ParseFS(templateFS, "templates/email_otp_request.html"),
)

var emailOTPVerifyTmpl = template.Must(
	template.ParseFS(templateFS, "templates/email_otp_verify.html"),
)

// EmailOTPHandler handles passwordless login via a 6-digit code sent by email.
type EmailOTPHandler struct {
	store    *session.Store
	orgs     *repository.OrgRepository
	users    *repository.UserRepository
	emailOTP *repository.EmailOTPRepository
	smtp     *repository.SMTPRepository
	guard    *lockout.Guard // nil = no brute-force throttling
}

// NewEmailOTPHandler creates a new EmailOTPHandler.
func NewEmailOTPHandler(pool *pgxpool.Pool, store *session.Store) *EmailOTPHandler {
	return &EmailOTPHandler{
		store:    store,
		orgs:     repository.NewOrgRepository(pool),
		users:    repository.NewUserRepository(pool),
		emailOTP: repository.NewEmailOTPRepository(pool),
		smtp:     repository.NewSMTPRepository(pool),
	}
}

// WithGuard attaches the adaptive lockout guard used to throttle OTP
// verification (brute-force protection). Returns the handler for chaining.
func (h *EmailOTPHandler) WithGuard(g *lockout.Guard) *EmailOTPHandler {
	h.guard = g
	return h
}

type otpRequestData struct {
	OrgName        string
	OrgSlug        string
	LogoURL        string
	LoginSessionID string
	Error          string
	Nonce          string
}

type otpVerifyData struct {
	OrgName        string
	OrgSlug        string
	LogoURL        string
	LoginSessionID string
	Email          string
	Error          string
	Nonce          string
}

// RequestPage shows the email entry form.
// GET /:org_slug/otp
func (h *EmailOTPHandler) RequestPage(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	loginSessionID := c.QueryParam("login_session_id")

	ctx := c.Request().Context()
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	var logoURL string
	if org.LogoURL != nil {
		logoURL = *org.LogoURL
	}

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return emailOTPRequestTmpl.Execute(c.Response().Writer, otpRequestData{
		OrgName:        org.Name,
		OrgSlug:        orgSlug,
		LogoURL:        logoURL,
		LoginSessionID: loginSessionID,
		Nonce:          middleware.GetCSPNonce(c),
	})
}

// Send generates a 6-digit OTP, persists a hash, and emails the code.
// POST /:org_slug/otp/send
func (h *EmailOTPHandler) Send(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	loginSessionID := c.FormValue("login_session_id")
	email := strings.ToLower(strings.TrimSpace(c.FormValue("email")))

	ctx := c.Request().Context()
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	// Validate login session exists.
	loginSess, err := h.store.GetLoginSession(ctx, loginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please start over")
	}

	var logoURL string
	if org.LogoURL != nil {
		logoURL = *org.LogoURL
	}

	renderErr := func(errMsg string) error {
		c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
		c.Response().WriteHeader(http.StatusUnprocessableEntity)
		return emailOTPRequestTmpl.Execute(c.Response().Writer, otpRequestData{
			OrgName:        org.Name,
			OrgSlug:        orgSlug,
			LogoURL:        logoURL,
			LoginSessionID: loginSessionID,
			Error:          errMsg,
			Nonce:          middleware.GetCSPNonce(c),
		})
	}

	if email == "" {
		return renderErr("Please enter your email address.")
	}

	// Resend throttle: min interval + hourly cap per address (anti email-bombing).
	if allowed, retry := h.store.OTPSendAllowed(ctx, "email", org.ID.String(), email); !allowed {
		return renderErr("Please wait " + lockout.FormatDuration(retry) + " before requesting another code.")
	}

	// Generate and store OTP. We intentionally do not look up the user here
	// to prevent email enumeration — the error is surfaced at verify time.
	code, err := h.emailOTP.Create(ctx, org.ID, email, loginSessionID, nil, emailOTPTTL)
	if err != nil {
		c.Logger().Errorf("email otp create org=%s: %v", orgSlug, err)
		return renderErr("An error occurred. Please try again.")
	}

	// Send the code via SMTP.  Failures are logged but do not block the redirect
	// so that timing differences cannot reveal whether an address is registered.
	m, mailerErr := mailer.ForOrg(ctx, h.smtp, org.ID)
	if mailerErr == nil {
		subject := "Your sign-in code for " + org.Name
		body := buildEmailOTPBody(org.Name, code)
		if sendErr := m.Send(email, subject, body); sendErr != nil {
			c.Logger().Warnf("email otp send org=%s: %v", orgSlug, sendErr)
		}
	} else {
		c.Logger().Warnf("email otp: smtp not configured for org=%s: %v", orgSlug, mailerErr)
	}

	// Update session state.
	loginSess.EmailOTPPending = true
	loginSess.EmailOTPAddress = email
	_ = h.store.SaveLoginSession(ctx, loginSess, 15*time.Minute)

	return c.Redirect(http.StatusSeeOther, "/"+orgSlug+"/otp/verify?login_session_id="+loginSessionID)
}

// VerifyPage shows the code entry form.
// GET /:org_slug/otp/verify
func (h *EmailOTPHandler) VerifyPage(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	loginSessionID := c.QueryParam("login_session_id")

	ctx := c.Request().Context()
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	loginSess, err := h.store.GetLoginSession(ctx, loginSessionID)
	if err != nil || loginSess == nil || !loginSess.EmailOTPPending {
		// Session missing or OTP not pending — send back to email entry.
		return c.Redirect(http.StatusFound, "/"+orgSlug+"/otp?login_session_id="+loginSessionID)
	}

	var logoURL string
	if org.LogoURL != nil {
		logoURL = *org.LogoURL
	}

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return emailOTPVerifyTmpl.Execute(c.Response().Writer, otpVerifyData{
		OrgName:        org.Name,
		OrgSlug:        orgSlug,
		LogoURL:        logoURL,
		LoginSessionID: loginSessionID,
		Email:          loginSess.EmailOTPAddress,
		Nonce:          middleware.GetCSPNonce(c),
	})
}

// VerifySubmit validates the submitted OTP code and completes the login.
// POST /:org_slug/otp/verify
func (h *EmailOTPHandler) VerifySubmit(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	loginSessionID := c.FormValue("login_session_id")
	email := strings.ToLower(strings.TrimSpace(c.FormValue("email")))
	code := strings.TrimSpace(c.FormValue("code"))

	ctx := c.Request().Context()
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	loginSess, err := h.store.GetLoginSession(ctx, loginSessionID)
	if err != nil || loginSess == nil || !loginSess.EmailOTPPending {
		return echo.NewHTTPError(http.StatusBadRequest, "session expired — please start over")
	}

	var logoURL string
	if org.LogoURL != nil {
		logoURL = *org.LogoURL
	}

	renderErr := func(errMsg string) error {
		c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
		c.Response().WriteHeader(http.StatusUnprocessableEntity)
		return emailOTPVerifyTmpl.Execute(c.Response().Writer, otpVerifyData{
			OrgName:        org.Name,
			OrgSlug:        orgSlug,
			LogoURL:        logoURL,
			LoginSessionID: loginSessionID,
			Email:          email,
			Error:          errMsg,
			Nonce:          middleware.GetCSPNonce(c),
		})
	}

	if code == "" {
		return renderErr("Please enter the 6-digit code from your email.")
	}

	// Brute-force throttle: a 6-digit code is guessable, so cap attempts with the
	// adaptive lockout guard (keyed on org+email), same mechanism as password login.
	if h.guard != nil {
		if d, locked := h.guard.IsLocked(ctx, org.ID.String(), email); locked {
			return renderErr("Too many incorrect codes. Try again in " + lockout.FormatDuration(d) + ".")
		}
	}

	// Consume OTP — returns empty string on invalid/expired code.
	sessionID, err := h.emailOTP.Consume(ctx, org.ID, email, code, loginSessionID)
	if err != nil || sessionID == "" {
		if h.guard != nil {
			h.guard.RecordFailure(ctx, org.ID.String(), email, 0)
		}
		return renderErr("Incorrect or expired code. Please check your email and try again.")
	}
	if h.guard != nil {
		h.guard.ClearFailures(ctx, org.ID.String(), email)
	}

	// Look up the user.
	user, err := h.users.GetByEmail(ctx, org.ID, email)
	if err != nil || !user.IsActive {
		return renderErr("No active account found for this email address.")
	}

	// Mark the login session as authenticated and let the resume flow continue.
	loginSess.UserID = user.ID.String()
	loginSess.EmailOTPPending = false
	loginSess.EmailOTPAddress = ""
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	return c.Redirect(http.StatusSeeOther, "/"+orgSlug+"/authorize/resume?login_session_id="+loginSessionID)
}

// buildEmailOTPBody returns a minimal but well-formatted HTML email body.
func buildEmailOTPBody(orgName, code string) string {
	// html.EscapeString prevents XSS if orgName contains HTML special chars.
	safeOrg := html.EscapeString(orgName)
	return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:40px 20px;background:#f9fafb;font-family:ui-sans-serif,system-ui,sans-serif">
  <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:12px;border:1px solid #e5e7eb;padding:40px">
    <h2 style="margin:0 0 8px;font-size:20px;color:#111827">Your sign-in code</h2>
    <p style="margin:0 0 24px;color:#6b7280;font-size:14px">Use this code to sign in to <strong>` + safeOrg + `</strong>. It expires in 10&nbsp;minutes.</p>
    <div style="background:#f3f4f6;border-radius:8px;padding:20px;text-align:center">
      <span style="font-size:40px;font-weight:700;letter-spacing:0.2em;color:#1f2937;font-family:monospace">` + code + `</span>
    </div>
    <p style="margin:24px 0 0;color:#9ca3af;font-size:12px">If you didn&rsquo;t request this code, you can safely ignore this email.</p>
  </div>
</body>
</html>`
}
