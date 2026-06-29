package handler

import (
	"html"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/lockout"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/sms"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

const phoneOTPTTL = 10 * time.Minute

var phoneOTPRequestTmpl = template.Must(
	template.ParseFS(templateFS, "templates/phone_otp_request.html"),
)

var phoneOTPVerifyTmpl = template.Must(
	template.ParseFS(templateFS, "templates/phone_otp_verify.html"),
)

// PhoneOTPHandler handles passwordless first-factor login via a 6-digit
// code sent by SMS to the user's registered phone number.
type PhoneOTPHandler struct {
	store    *session.Store
	orgs     *repository.OrgRepository
	users    *repository.UserRepository
	phoneOTP *repository.PhoneLoginOTPRepository
	smsRepo  *repository.SMSSettingsRepository
	guard    *lockout.Guard // nil = no brute-force throttling
}

// NewPhoneOTPHandler creates a new PhoneOTPHandler.
func NewPhoneOTPHandler(pool *pgxpool.Pool, store *session.Store) *PhoneOTPHandler {
	return &PhoneOTPHandler{
		store:    store,
		orgs:     repository.NewOrgRepository(pool),
		users:    repository.NewUserRepository(pool),
		phoneOTP: repository.NewPhoneLoginOTPRepository(pool),
		smsRepo:  repository.NewSMSSettingsRepository(pool),
	}
}

// WithGuard attaches the adaptive lockout guard used to throttle OTP
// verification (brute-force protection). Returns the handler for chaining.
func (h *PhoneOTPHandler) WithGuard(g *lockout.Guard) *PhoneOTPHandler {
	h.guard = g
	return h
}

type phoneOTPRequestData struct {
	OrgName        string
	OrgSlug        string
	LogoURL        string
	LoginSessionID string
	Error          string
	Nonce          string
}

type phoneOTPVerifyData struct {
	OrgName        string
	OrgSlug        string
	LogoURL        string
	LoginSessionID string
	Phone          string // masked for display
	Error          string
	Nonce          string
}

// RequestPage shows the phone number entry form.
// GET /:org_slug/phone-otp
func (h *PhoneOTPHandler) RequestPage(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	loginSessionID := c.QueryParam("login_session_id")

	ctx := c.Request().Context()
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return phoneOTPRequestTmpl.Execute(c.Response().Writer, phoneOTPRequestData{
		OrgName:        org.Name,
		OrgSlug:        orgSlug,
		LogoURL:        orgLogoURL(org.LogoURL),
		LoginSessionID: loginSessionID,
		Nonce:          middleware.GetCSPNonce(c),
	})
}

// Send generates a 6-digit OTP and sends it via SMS.
// POST /:org_slug/phone-otp/send
func (h *PhoneOTPHandler) Send(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	loginSessionID := c.FormValue("login_session_id")
	phone := strings.TrimSpace(c.FormValue("phone"))

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

	renderErr := func(errMsg string) error {
		c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
		c.Response().WriteHeader(http.StatusUnprocessableEntity)
		return phoneOTPRequestTmpl.Execute(c.Response().Writer, phoneOTPRequestData{
			OrgName:        org.Name,
			OrgSlug:        orgSlug,
			LogoURL:        orgLogoURL(org.LogoURL),
			LoginSessionID: loginSessionID,
			Error:          errMsg,
			Nonce:          middleware.GetCSPNonce(c),
		})
	}

	if phone == "" {
		return renderErr("Please enter your phone number.")
	}

	// Resend throttle: min interval + hourly cap per number (anti SMS toll-fraud).
	if allowed, retry := h.store.OTPSendAllowed(ctx, "phone", org.ID.String(), phone); !allowed {
		return renderErr("Please wait " + lockout.FormatDuration(retry) + " before requesting another code.")
	}

	// Generate and store OTP.  We intentionally do NOT look up the user here
	// to prevent phone number enumeration — any error is surfaced at verify time.
	code, err := h.phoneOTP.Create(ctx, org.ID, phone, loginSessionID, phoneOTPTTL)
	if err != nil {
		c.Logger().Errorf("phone otp create org=%s: %v", orgSlug, err)
		return renderErr("An error occurred. Please try again.")
	}

	// Send via SMS.  Failures are logged but do not block the redirect so that
	// timing differences cannot reveal whether a phone number is registered.
	provider, smsErr := sms.ForOrg(ctx, h.smsRepo, org.ID)
	if smsErr == nil {
		body := "Your sign-in code for " + html.EscapeString(org.Name) + ": " + code + ". Valid for 10 minutes."
		if sendErr := provider.Send(ctx, phone, body); sendErr != nil {
			c.Logger().Warnf("phone otp send org=%s: %v", orgSlug, sendErr)
		}
	} else {
		c.Logger().Warnf("phone otp: sms not configured for org=%s: %v", orgSlug, smsErr)
	}

	// Update session state.
	loginSess.PhoneOTPPending = true
	loginSess.PhoneOTPPhone = phone
	_ = h.store.SaveLoginSession(ctx, loginSess, 15*time.Minute)

	return c.Redirect(http.StatusSeeOther, "/"+orgSlug+"/phone-otp/verify?login_session_id="+loginSessionID)
}

// VerifyPage shows the code entry form.
// GET /:org_slug/phone-otp/verify
func (h *PhoneOTPHandler) VerifyPage(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	loginSessionID := c.QueryParam("login_session_id")

	ctx := c.Request().Context()
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	loginSess, err := h.store.GetLoginSession(ctx, loginSessionID)
	if err != nil || loginSess == nil || !loginSess.PhoneOTPPending {
		// Session missing or OTP not initiated — send back to phone entry.
		return c.Redirect(http.StatusFound, "/"+orgSlug+"/phone-otp?login_session_id="+loginSessionID)
	}

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return phoneOTPVerifyTmpl.Execute(c.Response().Writer, phoneOTPVerifyData{
		OrgName:        org.Name,
		OrgSlug:        orgSlug,
		LogoURL:        orgLogoURL(org.LogoURL),
		LoginSessionID: loginSessionID,
		Phone:          maskPhone(loginSess.PhoneOTPPhone),
		Nonce:          middleware.GetCSPNonce(c),
	})
}

// VerifySubmit validates the submitted OTP code and completes the login.
// POST /:org_slug/phone-otp/verify
func (h *PhoneOTPHandler) VerifySubmit(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	loginSessionID := c.FormValue("login_session_id")
	phone := strings.TrimSpace(c.FormValue("phone"))
	code := strings.TrimSpace(c.FormValue("code"))

	ctx := c.Request().Context()
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	loginSess, err := h.store.GetLoginSession(ctx, loginSessionID)
	if err != nil || loginSess == nil || !loginSess.PhoneOTPPending {
		return echo.NewHTTPError(http.StatusBadRequest, "session expired — please start over")
	}

	// Use the phone stored in the session, not the submitted form value,
	// to prevent parameter tampering.
	sessionPhone := loginSess.PhoneOTPPhone

	renderErr := func(errMsg string) error {
		c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
		c.Response().WriteHeader(http.StatusUnprocessableEntity)
		return phoneOTPVerifyTmpl.Execute(c.Response().Writer, phoneOTPVerifyData{
			OrgName:        org.Name,
			OrgSlug:        orgSlug,
			LogoURL:        orgLogoURL(org.LogoURL),
			LoginSessionID: loginSessionID,
			Phone:          maskPhone(sessionPhone),
			Error:          errMsg,
			Nonce:          middleware.GetCSPNonce(c),
		})
	}

	_ = phone // submitted phone is intentionally unused — always use session value

	if code == "" {
		return renderErr("Please enter the 6-digit code from your SMS.")
	}

	// Brute-force throttle: cap SMS OTP guesses with the adaptive lockout guard
	// (keyed on org+phone), same mechanism as password login.
	if h.guard != nil {
		if d, locked := h.guard.IsLocked(ctx, org.ID.String(), sessionPhone); locked {
			return renderErr("Too many incorrect codes. Try again in " + lockout.FormatDuration(d) + ".")
		}
	}

	// Consume the OTP — returns empty string on invalid/expired code.
	consumedSessionID, err := h.phoneOTP.Consume(ctx, org.ID, sessionPhone, code, loginSessionID)
	if err != nil || consumedSessionID == "" {
		if h.guard != nil {
			h.guard.RecordFailure(ctx, org.ID.String(), sessionPhone, 0)
		}
		return renderErr("Incorrect or expired code. Please check your SMS and try again.")
	}
	if h.guard != nil {
		h.guard.ClearFailures(ctx, org.ID.String(), sessionPhone)
	}

	// Look up the user by phone number.
	user, err := h.users.GetByPhone(ctx, org.ID, sessionPhone)
	if err != nil || !user.IsActive {
		return renderErr("No active account found for this phone number.")
	}

	// Mark the login session as authenticated and let the resume flow continue.
	loginSess.UserID = user.ID.String()
	loginSess.PhoneOTPPending = false
	loginSess.PhoneOTPPhone = ""
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	return c.Redirect(http.StatusSeeOther, "/"+orgSlug+"/authorize/resume?login_session_id="+loginSessionID)
}

// maskPhone returns a privacy-preserving display version of the phone number,
// e.g. "+39 *** *** 4321".  Keeps the country code and last 4 digits visible.
func maskPhone(phone string) string {
	if len(phone) < 5 {
		return phone
	}
	// Keep first 3 chars (country code) and last 4 digits.
	if len(phone) > 7 {
		return phone[:3] + " *** " + phone[len(phone)-4:]
	}
	return phone[:1] + strings.Repeat("*", len(phone)-3) + phone[len(phone)-2:]
}

// orgLogoURL returns the org's logo URL string or empty string if unset.
func orgLogoURL(logoURL *string) string {
	if logoURL != nil {
		return *logoURL
	}
	return ""
}
