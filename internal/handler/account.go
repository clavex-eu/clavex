package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/go-webauthn/webauthn/protocol"
	walib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"github.com/clavex-eu/clavex/internal/ssf"
)

const accountCookie = "clavex_act"

// AccountHandler serves the user self-service portal.
// Routes live at /:org_slug/account/... and use their own cookie auth,
// completely separate from the admin JWT system.
type AccountHandler struct {
	orgs         *repository.OrgRepository
	users        *repository.UserRepository
	mfa          *repository.MFARepository
	mdsRepo      *repository.MDSRepository
	tokens       *repository.RefreshTokenRepository
	store        *session.Store
	pwPolicy     *repository.PasswordPolicyRepository
	loginHistory *repository.LoginHistoryRepository
	smtp         *repository.SMTPRepository
	erasure      *repository.ErasureRequestRepository
	devices      *repository.TrustedDeviceRepository
	pool         *pgxpool.Pool
	webAuthn     *walib.WebAuthn        // nil when not configured
	rdb          redis.UniversalClient
	ssfDisp      *ssf.Dispatcher        // nil when not configured
}

func NewAccountHandler(cfg *config.Config, pool *pgxpool.Pool, rdb redis.UniversalClient, store *session.Store) *AccountHandler {
	h := &AccountHandler{
		orgs:         repository.NewOrgRepository(pool),
		users:        repository.NewUserRepository(pool),
		mfa:          repository.NewMFARepository(pool),
		mdsRepo:      repository.NewMDSRepository(pool),
		tokens:       repository.NewRefreshTokenRepository(pool),
		store:        store,
		pwPolicy:     repository.NewPasswordPolicyRepository(pool),
		loginHistory: repository.NewLoginHistoryRepository(pool),
		smtp:         repository.NewSMTPRepository(pool),
		erasure:      repository.NewErasureRequestRepository(pool),
		devices:      repository.NewTrustedDeviceRepository(pool),
		pool:         pool,
		rdb:          rdb,
	}
	if cfg.Auth.WebAuthnRPID != "" {
		wa, err := walib.New(&walib.Config{
			RPDisplayName: cfg.Auth.WebAuthnRPName,
			RPID:          cfg.Auth.WebAuthnRPID,
			RPOrigins:     cfg.Auth.WebAuthnRPOrigins,
		})
		if err == nil {
			h.webAuthn = wa
		}
	}
	return h
}

// WithSSFDispatcher attaches an SSF dispatcher so the handler can fire
// CAEP credential-change events after a self-service password update.
func (h *AccountHandler) WithSSFDispatcher(d *ssf.Dispatcher) *AccountHandler {
	h.ssfDisp = d
	return h
}

// ── Templates ─────────────────────────────────────────────────────────────────

// countryFlag converts an ISO-3166-1 alpha-2 code to a flag emoji.
// Each letter maps to a Regional Indicator Symbol (U+1F1E6..U+1F1FF).
func countryFlag(code string) string {
	if len(code) != 2 {
		return "🌐"
	}
	r1 := rune(code[0]-'A') + 0x1F1E6
	r2 := rune(code[1]-'A') + 0x1F1E6
	return string([]rune{r1, r2})
}

var accountTmplFuncs = template.FuncMap{
	"countryFlag": countryFlag,
}

var (
	// Each page set parses the shared base layout + its own content block.
	accountProfileTmpl        = template.Must(template.New("base").Funcs(accountTmplFuncs).ParseFS(templateFS, "templates/account_base.html", "templates/account_profile.html"))
	accountSessionsTmpl       = template.Must(template.New("base").Funcs(accountTmplFuncs).ParseFS(templateFS, "templates/account_base.html", "templates/account_sessions.html"))
	accountSecurityTmpl       = template.Must(template.New("base").Funcs(accountTmplFuncs).ParseFS(templateFS, "templates/account_base.html", "templates/account_security.html"))
	accountActivityTmpl       = template.Must(template.New("base").Funcs(accountTmplFuncs).ParseFS(templateFS, "templates/account_base.html", "templates/account_activity.html"))
	accountLoginTmpl          = template.Must(template.New("account_login").ParseFS(templateFS, "templates/account_login.html"))
	accountErasureConfirmTmpl = template.Must(template.New("account_erasure_confirm").ParseFS(templateFS, "templates/account_erasure_confirm.html"))
)

// accountData is the view model passed to every account portal template.
// PasskeyDevice is the view-model for a single WebAuthn passkey shown on the
// account security page. It enriches the raw MFA credential with MDS3 metadata.
type PasskeyDevice struct {
	ID          uuid.UUID  // mfa_credentials.id — used in the remove form action
	Name        string     // user-given name (e.g. "iPhone 15 Pro")
	AAGUID      string     // extracted from data JSONB (may be empty for U2F keys)
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	IsPrimary   bool
	// MDS3-enriched fields (empty when AAGUID not in catalog)
	MDSLabel    string // e.g. "YubiKey 5 NFC" (falls back to Name)
	CertLevel   string // e.g. "L2", "L3+"
	DeviceType  string // "platform" | "cross-platform" | "unknown"
}

type accountData struct {
	OrgName        string
	LogoURL        *string
	OrgSlug        string
	User           *models.User
	Sessions       []*repository.ActiveSession
	MFAs           []*models.MFACredential
	Passkeys       []PasskeyDevice // WebAuthn credentials enriched with MDS3 labels
	TrustedDevices []*models.TrustedDevice
	LoginEvents    []*models.LoginEvent
	ActiveTab      string // "profile" | "sessions" | "security" | "activity"
	Flash          string
	Error          string
	Nonce          string // CSP nonce for inline/external scripts
	// ErasurePending is non-nil when the user has a pending/scheduled erasure request.
	ErasurePending *repository.ErasureRequest
	// WebAuthnEnabled is true when the server is configured with a WebAuthn RP ID.
	// Used to conditionally render passkey enrollment buttons.
	WebAuthnEnabled bool
}

func renderAccount(c echo.Context, tmpl *template.Template, data accountData) error {
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().Header().Set("Cache-Control", "no-store")
	data.Nonce = middleware.GetCSPNonce(c)
	return tmpl.ExecuteTemplate(c.Response().Writer, "base", data)
}

// ── Session cookie helpers ─────────────────────────────────────────────────────

func clearAccountCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     accountCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func setAccountCookie(c echo.Context, sessID string) {
	c.SetCookie(&http.Cookie{
		Name:     accountCookie,
		Value:    sessID,
		Path:     "/",
		MaxAge:   int(session.AccountSessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func getAccountSession(c echo.Context) *session.AccountSession {
	if v := c.Get("account_session"); v != nil {
		if s, ok := v.(*session.AccountSession); ok {
			return s
		}
	}
	return nil
}

// ── Middleware ─────────────────────────────────────────────────────────────────

// RequireAccountSession validates the account portal cookie.
// On failure it redirects to the portal login page for the org.
func (h *AccountHandler) RequireAccountSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		orgSlug := c.Param("org_slug")
		loginURL := "/" + orgSlug + "/account/login"

		cookie, err := c.Cookie(accountCookie)
		if err != nil || cookie.Value == "" {
			return c.Redirect(http.StatusFound, loginURL)
		}
		sess, err := h.store.GetAccountSession(c.Request().Context(), cookie.Value)
		if err != nil || sess == nil || sess.OrgSlug != orgSlug {
			clearAccountCookie(c)
			return c.Redirect(http.StatusFound, loginURL)
		}
		c.Set("account_session", sess)
		return next(c)
	}
}

// ── Login / Logout ─────────────────────────────────────────────────────────────

// LoginPage renders the account portal login form.
// GET /:org_slug/account/login
func (h *AccountHandler) LoginPage(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}
	return h.renderLoginPage(c, org, "")
}

// LoginSubmit handles credential submission for the portal.
// POST /:org_slug/account/login
func (h *AccountHandler) LoginSubmit(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	email := strings.TrimSpace(c.FormValue("email"))
	password := c.FormValue("password")

	user, err := h.users.GetByEmail(ctx, org.ID, email)
	if err != nil || !user.IsActive {
		return h.renderLoginPage(c, org, "Invalid email or password.")
	}
	if user.PasswordHash == nil || !h.users.CheckPassword(*user.PasswordHash, password) {
		return h.renderLoginPage(c, org, "Invalid email or password.")
	}

	sess := &session.AccountSession{
		ID:        uuid.NewString(),
		UserID:    user.ID.String(),
		OrgID:     org.ID.String(),
		OrgSlug:   orgSlug,
		CreatedAt: time.Now(),
	}
	if err := h.store.SaveAccountSession(ctx, sess); err != nil {
		log.Error().Err(err).Msg("account: failed to save session")
		return echo.ErrInternalServerError
	}
	setAccountCookie(c, sess.ID)
	return c.Redirect(http.StatusFound, "/"+orgSlug+"/account")
}

// Logout clears the account portal session.
// POST /:org_slug/account/logout
func (h *AccountHandler) Logout(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	ctx := c.Request().Context()
	if cookie, err := c.Cookie(accountCookie); err == nil && cookie.Value != "" {
		_ = h.store.DeleteAccountSession(ctx, cookie.Value)
	}
	clearAccountCookie(c)
	// Also clear the OIDC SSO session so that the OP no longer considers the
	// user authenticated (prevents prompt=none from succeeding after logout).
	if cookie, err := c.Cookie(ssoCookie); err == nil && cookie.Value != "" {
		_ = h.store.DeleteSSOSession(ctx, cookie.Value)
		c.SetCookie(&http.Cookie{
			Name: ssoCookie, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	return c.Redirect(http.StatusFound, "/"+orgSlug+"/account/login")
}

func (h *AccountHandler) renderLoginPage(c echo.Context, org *models.Organization, errMsg string) error {
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().Header().Set("Cache-Control", "no-store")
	return accountLoginTmpl.ExecuteTemplate(c.Response().Writer, "account_login", map[string]interface{}{
		"OrgName": org.Name,
		"LogoURL": org.LogoURL,
		"Error":   errMsg,
		"Nonce":   middleware.GetCSPNonce(c),
	})
}

// ── Profile ───────────────────────────────────────────────────────────────────

// Profile renders the account profile page.
// GET /:org_slug/account
func (h *AccountHandler) Profile(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}
	// Load any active erasure request to show status banners.
	erasurePending, _ := h.erasure.GetActiveByUser(ctx, org.ID, user.ID)
	return renderAccount(c, accountProfileTmpl, accountData{
		OrgName: org.Name, LogoURL: org.LogoURL, OrgSlug: sess.OrgSlug,
		User: user, ActiveTab: "profile", Flash: c.QueryParam("flash"),
		ErasurePending: erasurePending,
	})
}

// UpdateProfile handles first/last name updates.
// POST /:org_slug/account/profile
func (h *AccountHandler) UpdateProfile(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	fn := nullableStr(strings.TrimSpace(c.FormValue("first_name")))
	ln := nullableStr(strings.TrimSpace(c.FormValue("last_name")))

	if _, err := h.users.Update(ctx, user.ID, fn, ln, nil, nil); err != nil {
		log.Error().Err(err).Msg("account: profile update failed")
		return renderAccount(c, accountProfileTmpl, accountData{
			OrgName: org.Name, LogoURL: org.LogoURL, OrgSlug: sess.OrgSlug,
			User: user, ActiveTab: "profile",
			Error: "Failed to update profile. Please try again.",
		})
	}
	return c.Redirect(http.StatusFound, "/"+sess.OrgSlug+"/account?flash=Profile+updated")
}

// ChangePassword handles the password change form.
// POST /:org_slug/account/password
func (h *AccountHandler) ChangePassword(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	renderErr := func(msg string) error {
		return renderAccount(c, accountProfileTmpl, accountData{
			OrgName: org.Name, LogoURL: org.LogoURL, OrgSlug: sess.OrgSlug,
			User: user, ActiveTab: "profile", Error: msg,
		})
	}

	// Re-fetch with hash so we can verify the current password.
	userWithHash, err := h.users.GetByIDWithHash(ctx, user.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	currentPW := c.FormValue("current_password")
	newPW := c.FormValue("new_password")
	confirmPW := c.FormValue("confirm_password")

	if userWithHash.PasswordHash == nil || !h.users.CheckPassword(*userWithHash.PasswordHash, currentPW) {
		return renderErr("Current password is incorrect.")
	}
	if len(newPW) < 8 {
		return renderErr("New password must be at least 8 characters.")
	}
	if newPW != confirmPW {
		return renderErr("New passwords do not match.")
	}
	if newPW == currentPW {
		return renderErr("New password must differ from the current one.")
	}

	if err := h.users.SetPassword(ctx, user.ID, newPW); err != nil {
		return renderErr("Failed to update password. Please try again.")
	}
	// CAEP: credential-change — notify receivers so they can revoke tokens immediately.
	if h.ssfDisp != nil {
		orgID, _ := uuid.Parse(sess.OrgID)
		h.ssfDisp.Dispatch(orgID, sess.OrgSlug, user.ID.String(),
			ssf.EventCredentialChange,
			ssf.CredentialChangeBody("password", "update"))
	}
	return c.Redirect(http.StatusFound, "/"+sess.OrgSlug+"/account?flash=Password+changed+successfully")
}

// ── Sessions ──────────────────────────────────────────────────────────────────

// Sessions renders the active sessions page.
// GET /:org_slug/account/sessions
func (h *AccountHandler) Sessions(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	orgID, _ := uuid.Parse(sess.OrgID)
	activeSessions, listErr := h.tokens.ListActiveByUser(ctx, orgID, user.ID)
	if listErr != nil {
		activeSessions = nil
	}
	return renderAccount(c, accountSessionsTmpl, accountData{
		OrgName: org.Name, LogoURL: org.LogoURL, OrgSlug: sess.OrgSlug,
		User: user, Sessions: activeSessions, ActiveTab: "sessions",
		Flash: c.QueryParam("flash"),
	})
}

// RevokeSession revokes a single refresh token by ID.
// POST /:org_slug/account/sessions/:id/revoke
func (h *AccountHandler) RevokeSession(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, _, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	tokenID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid session id")
	}

	// Ownership check — prevent IDOR.
	orgID, _ := uuid.Parse(sess.OrgID)
	activeSessions, err := h.tokens.ListActiveByUser(ctx, orgID, user.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	owned := false
	for _, s := range activeSessions {
		if s.ID == tokenID {
			owned = true
			break
		}
	}
	if !owned {
		return echo.ErrForbidden
	}

	if err := h.tokens.RevokeByID(ctx, tokenID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.Redirect(http.StatusFound, "/"+sess.OrgSlug+"/account/sessions?flash=Session+revoked")
}

// RevokeAllSessions revokes every active session for the authenticated user.
// POST /:org_slug/account/sessions/revoke-all
func (h *AccountHandler) RevokeAllSessions(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, _, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}
	orgID, _ := uuid.Parse(sess.OrgID)
	_ = h.tokens.RevokeAllByUser(ctx, orgID, user.ID)
	return c.Redirect(http.StatusFound, "/"+sess.OrgSlug+"/account/sessions?flash=All+sessions+revoked")
}

// ── Security / MFA ─────────────────────────────────────────────────────────────

// Security renders the MFA devices page.
// GET /:org_slug/account/security
func (h *AccountHandler) Security(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	mfas, listErr := h.mfa.ListByUser(ctx, user.ID)
	if listErr != nil {
		mfas = nil
	}

	// Build enriched passkey device list (WebAuthn credentials + MDS3 labels).
	passkeys := h.buildPasskeyDevices(ctx, mfas)

	trustedDevs, _ := h.devices.ListByUser(ctx, org.ID, user.ID)

	return renderAccount(c, accountSecurityTmpl, accountData{
		OrgName: org.Name, LogoURL: org.LogoURL, OrgSlug: sess.OrgSlug,
		User: user, MFAs: mfas, Passkeys: passkeys, TrustedDevices: trustedDevs, ActiveTab: "security",
		Flash:           c.QueryParam("flash"),
		WebAuthnEnabled: h.webAuthn != nil,
	})
}

// RevokeDevice removes a single trusted device owned by the authenticated user.
// POST /:org_slug/account/security/devices/:id/revoke
func (h *AccountHandler) RevokeDevice(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}
	deviceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid device id")
	}
	if err := h.devices.Revoke(ctx, org.ID, user.ID, deviceID); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "device not found")
	}
	return c.Redirect(http.StatusFound, "/"+sess.OrgSlug+"/account/security?flash=Device+removed")
}

// RevokeAllDevices removes all trusted devices for the authenticated user.
// POST /:org_slug/account/security/devices/revoke-all
func (h *AccountHandler) RevokeAllDevices(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}
	if err := h.devices.RevokeAllForUser(ctx, org.ID, user.ID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.Redirect(http.StatusFound, "/"+sess.OrgSlug+"/account/security?flash=All+devices+removed")
}

// buildPasskeyDevices extracts WebAuthn credentials from the full MFA list,
// pulls the AAGUID from the credential JSONB data, and enriches each entry
// with the MDS3 description and certification level.
func (h *AccountHandler) buildPasskeyDevices(ctx context.Context, mfas []*models.MFACredential) []PasskeyDevice {
	// Collect AAGUIDs to batch-look up in MDS3.
	var devices []PasskeyDevice
	var aaguids []string
	aaguidIdx := map[string]int{} // aaguid → index in devices slice

	for _, m := range mfas {
		if m.Type != "webauthn" {
			continue
		}
		// AAGUID is stored inside the JSONB data blob by the go-webauthn library
		// as data["aaguid"] (string, lower-cased UUID format).
		aaguid := ""
		if m.Data != nil {
			if v, ok := m.Data["aaguid"]; ok {
				if s, ok := v.(string); ok {
					aaguid = strings.ToLower(s)
				}
			}
		}

		dev := PasskeyDevice{
			ID:         m.ID,
			Name:       m.Name,
			AAGUID:     aaguid,
			CreatedAt:  m.CreatedAt,
			LastUsedAt: m.LastUsedAt,
			IsPrimary:  m.IsPrimary,
			MDSLabel:   m.Name, // fallback if no MDS3 entry
		}
		if aaguid != "" && aaguid != "00000000-0000-0000-0000-000000000000" {
			if _, dup := aaguidIdx[aaguid]; !dup {
				aaguids = append(aaguids, aaguid)
			}
			aaguidIdx[aaguid] = len(devices)
		}
		devices = append(devices, dev)
	}

	if len(aaguids) == 0 || h.mdsRepo == nil {
		return devices
	}

	mdsMap, err := h.mdsRepo.GetByAAGUIDs(ctx, aaguids)
	if err != nil {
		log.Warn().Err(err).Msg("account security: MDS3 lookup failed")
		return devices
	}

	// Enrich each device with MDS3 data.
	for i := range devices {
		if devices[i].AAGUID == "" {
			continue
		}
		entry, ok := mdsMap[devices[i].AAGUID]
		if !ok || entry == nil {
			continue
		}
		if entry.Description != "" {
			devices[i].MDSLabel = entry.Description
		}
		if entry.CertificationLevel != nil {
			devices[i].CertLevel = *entry.CertificationLevel
		}
		devices[i].DeviceType = entry.AuthenticatorType
	}
	return devices
}

// DeleteMFA removes an MFA credential owned by the authenticated user.
// POST /:org_slug/account/security/mfa/:id/delete
func (h *AccountHandler) DeleteMFA(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, _, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	credID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid credential id")
	}

	// Ownership check.
	mfas, err := h.mfa.ListByUser(ctx, user.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	owned := false
	for _, m := range mfas {
		if m.ID == credID {
			owned = true
			break
		}
	}
	if !owned {
		return echo.ErrForbidden
	}

	if err := h.mfa.Delete(ctx, credID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.Redirect(http.StatusFound, "/"+sess.OrgSlug+"/account/security?flash=Device+removed")
}

// ── TOTP self-enrollment (account portal) ─────────────────────────────────────

// BeginTOTPEnrollment starts TOTP enrollment from the account portal.
// Returns JSON with { credential_id, otpauth_uri, qr_url }.
// POST /:org_slug/account/security/totp/enroll
func (h *AccountHandler) BeginTOTPEnrollment(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	// Clean up any leftover pending TOTP before issuing a fresh one.
	_ = h.mfa.DeletePendingTOTP(ctx, user.ID)

	issuer := org.Name
	if issuer == "" {
		issuer = sess.OrgSlug
	}
	key, err := totpGenerate(totpGenerateOpts{Issuer: issuer, AccountName: user.Email})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "enrollment failed"})
	}

	cred, err := h.mfa.CreateTOTP(ctx, user.ID, "Authenticator App", map[string]interface{}{
		"secret":      key.secret,
		"otpauth_uri": key.url,
		"confirmed":   false,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "enrollment failed"})
	}

	qrURL := "/" + sess.OrgSlug + "/account/security/totp/" + cred.ID.String() + "/qr"
	return c.JSON(http.StatusCreated, map[string]string{
		"credential_id": cred.ID.String(),
		"otpauth_uri":   key.url,
		"qr_url":        qrURL,
	})
}

// TOTPQRImage serves the QR PNG for a pending TOTP credential (session-cookie auth).
// GET /:org_slug/account/security/totp/:cred_id/qr
func (h *AccountHandler) TOTPQRImage(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, _, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}
	credID, err := uuid.Parse(c.Param("cred_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid credential id")
	}

	full, err := h.mfa.GetWithData(ctx, credID)
	if err != nil || full.UserID != user.ID || full.Type != "totp" {
		return echo.ErrNotFound
	}
	if confirmed, _ := full.Data["confirmed"].(bool); confirmed {
		return echo.NewHTTPError(http.StatusGone, "QR no longer available after confirmation")
	}
	otpauthURI, _ := full.Data["otpauth_uri"].(string)
	if otpauthURI == "" {
		secret, _ := full.Data["secret"].(string)
		if secret == "" {
			return echo.ErrInternalServerError
		}
		otpauthURI = "otpauth://totp/" + sess.OrgSlug + "?secret=" + secret + "&issuer=" + sess.OrgSlug
	}
	return serveTOTPQRPNG(c, otpauthURI)
}

// ConfirmTOTPEnrollment confirms TOTP and returns one-time backup codes as JSON.
// POST /:org_slug/account/security/totp/confirm
func (h *AccountHandler) ConfirmTOTPEnrollment(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, _, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	type req struct {
		CredentialID string `json:"credential_id"`
		Code         string `json:"code"`
	}
	var body req
	if err := c.Bind(&body); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}
	credID, err := uuid.Parse(body.CredentialID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid credential id"})
	}

	cred, err := h.mfa.GetWithData(ctx, credID)
	if err != nil || cred.UserID != user.ID || cred.Type != "totp" {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "credential not found"})
	}
	if confirmed, _ := cred.Data["confirmed"].(bool); confirmed {
		return c.JSON(http.StatusConflict, map[string]string{"error": "already confirmed"})
	}

	secret, _ := cred.Data["secret"].(string)
	if !totpValidate(body.Code, secret) {
		return c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "invalid TOTP code"})
	}

	if err := h.mfa.SetTOTPConfirmed(ctx, credID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "confirmation failed"})
	}

	plainCodes, err := h.mfa.GenerateBackupCodes(ctx, cred.UserID)
	if err != nil {
		return c.JSON(http.StatusOK, map[string]interface{}{"backup_codes": nil})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"backup_codes": plainCodes})
}

// ── Hybrid passkey enrollment (cross-device via QR) ───────────────────────────

// BeginHybridPasskeyRegistration starts a cross-device passkey registration
// using FIDO2 Hybrid Transport (CTAP 2.2). Authentication is via account session
// cookie, making this callable directly from the self-service account portal.
//
// POST /:org_slug/account/security/passkey/hybrid/begin
func (h *AccountHandler) BeginHybridPasskeyRegistration(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, map[string]string{"error": "webauthn_not_configured"})
	}
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, _, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	existing, err := h.mfa.ListWebAuthnByUser(ctx, user.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	waUser := &webAuthnUser{
		id:          user.ID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}
	options, session, err := h.webAuthn.BeginRegistration(waUser,
		walib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		walib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			// CrossPlatform forces the browser's native hybrid QR dialog so the
			// user can scan with their phone and create a passkey on that device.
			AuthenticatorAttachment: protocol.CrossPlatform,
			UserVerification:        protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "begin hybrid passkey registration failed")
	}
	sessionBytes, _ := json.Marshal(session)
	redisKey := "acct:pk:hybrid:" + user.ID.String()
	if err := h.rdb.Set(ctx, redisKey, sessionBytes, webAuthnChallengeTTL).Err(); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, options)
}

// FinishHybridPasskeyRegistration completes the cross-device passkey ceremony
// and persists the credential tagged with source_transport=hybrid.
//
// POST /:org_slug/account/security/passkey/hybrid/finish
func (h *AccountHandler) FinishHybridPasskeyRegistration(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, map[string]string{"error": "webauthn_not_configured"})
	}
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, _, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	redisKey := "acct:pk:hybrid:" + user.ID.String()
	sessionBytes, err := h.rdb.GetDel(ctx, redisKey).Bytes()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "hybrid registration session expired; call begin first")
	}
	var session walib.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return echo.ErrInternalServerError
	}

	existing, err := h.mfa.ListWebAuthnByUser(ctx, user.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	waUser := &webAuthnUser{
		id:          user.ID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}
	credential, err := h.webAuthn.FinishRegistration(waUser, session, c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "hybrid passkey verification failed")
	}
	credBytes, _ := json.Marshal(credential)
	var credData map[string]interface{}
	_ = json.Unmarshal(credBytes, &credData)
	credData["is_passkey"] = true
	credData["source_transport"] = "hybrid"

	name := c.QueryParam("name")
	if name == "" {
		name = "Phone Passkey"
	}
	if _, err := h.mfa.CreateWebAuthn(ctx, user.ID, name, credData); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, map[string]string{"status": "enrolled"})
}

// Activity renders the last 30 login events for the authenticated user.
// GET /:org_slug/account/activity
func (h *AccountHandler) Activity(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}
	orgID, _ := uuid.Parse(sess.OrgID)
	userID := user.ID

	page, _ := h.loginHistory.ListLoginHistory(ctx, repository.ListLoginHistoryParams{
		OrgID:  &orgID,
		UserID: &userID,
		Limit:  30,
	})
	var events []*models.LoginEvent
	if page != nil {
		events = page.Items
	}
	return renderAccount(c, accountActivityTmpl, accountData{
		OrgName:     org.Name,
		LogoURL:     org.LogoURL,
		OrgSlug:     sess.OrgSlug,
		User:        user,
		LoginEvents: events,
		ActiveTab:   "activity",
		Flash:       c.QueryParam("flash"),
	})
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func (h *AccountHandler) loadAccountUser(ctx context.Context, sess *session.AccountSession) (*models.User, *models.Organization, error) {
	userID, err := uuid.Parse(sess.UserID)
	if err != nil {
		return nil, nil, echo.ErrInternalServerError
	}
	user, err := h.users.GetByID(ctx, userID)
	if err != nil || !user.IsActive {
		return nil, nil, echo.ErrUnauthorized
	}
	org, err := h.orgs.GetBySlug(ctx, sess.OrgSlug)
	if err != nil || !org.IsActive {
		return nil, nil, echo.ErrInternalServerError
	}
	return user, org, nil
}

// nullableStr returns nil if s is empty, otherwise &s.
// This allows COALESCE in SQL to skip updates for blank fields.
func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ── GDPR self-service erasure ──────────────────────────────────────────────────

// RequestErasure handles POST /:org_slug/account/erasure/request
//
// Creates the erasure request record and sends the confirmation email.
// If an active request already exists, re-sends the confirmation email
// (idempotent — prevents duplicate spamming by checking the existing token).
func (h *AccountHandler) RequestErasure(c echo.Context) error {
	ctx := c.Request().Context()
	sess := getAccountSession(c)
	user, org, err := h.loadAccountUser(ctx, sess)
	if err != nil {
		return err
	}

	orgSlug := sess.OrgSlug
	baseURL := fmt.Sprintf("%s://%s", c.Scheme(), c.Request().Host)

	// Check for an existing active request.
	existing, _ := h.erasure.GetActiveByUser(ctx, org.ID, user.ID)
	if existing != nil && existing.Status == repository.ErasureStatusScheduled {
		// Already scheduled — nothing to do, show status.
		return c.Redirect(http.StatusFound, "/"+orgSlug+"/account?flash=erasure_already_scheduled")
	}

	// Create a new request (or the user has a stale pending_confirmation — handled by
	// UNIQUE constraint; let this fail and redirect gracefully).
	req, confirmToken, cancelToken, err := h.erasure.Create(ctx, org.ID, user.ID)
	if err != nil {
		// Unique conflict: a pending_confirmation exists; just redirect back.
		log.Warn().Err(err).Str("user_id", user.ID.String()).Msg("gdpr-erasure: create failed (probably duplicate)")
		return c.Redirect(http.StatusFound, "/"+orgSlug+"/account?flash=erasure_email_sent")
	}

	confirmURL := fmt.Sprintf("%s/%s/account/erasure/confirm?token=%s", baseURL, orgSlug, confirmToken)
	cancelURL := fmt.Sprintf("%s/%s/account/erasure/cancel?token=%s", baseURL, orgSlug, cancelToken)

	// Send confirmation email (best-effort; log on failure but don't block).
	m, mailErr := mailer.ForOrg(ctx, h.smtp, org.ID)
	if mailErr == nil {
		if sendErr := m.SendErasureConfirmation(user.Email, org.Name, confirmURL, cancelURL); sendErr != nil {
			log.Warn().Err(sendErr).Str("user_id", user.ID.String()).Msg("gdpr-erasure: failed to send confirmation email")
		}
	} else {
		log.Warn().Err(mailErr).Str("org_id", org.ID.String()).Msg("gdpr-erasure: SMTP not configured; skipping email")
	}

	_ = req // record stored; tokens sent
	return c.Redirect(http.StatusFound, "/"+orgSlug+"/account?flash=erasure_email_sent")
}

// ConfirmErasure handles GET /:org_slug/account/erasure/confirm?token=…
//
// Validates the one-time confirmation token, schedules the erasure (grace period
// starts now), and renders a confirmation page.
func (h *AccountHandler) ConfirmErasure(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	token := c.QueryParam("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing token")
	}

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	req, err := h.erasure.Confirm(ctx, token)
	if err != nil {
		// Token invalid, expired, or already used.
		return h.renderErasureConfirmPage(c, org.Name, org.LogoURL, orgSlug, "invalid_token", nil)
	}

	log.Info().
		Str("user_id", req.UserID.String()).
		Str("org_id", req.OrgID.String()).
		Time("scheduled_for", func() time.Time {
			if req.ScheduledFor != nil {
				return *req.ScheduledFor
			}
			return time.Time{}
		}()).
		Msg("gdpr-erasure: scheduled")

	return h.renderErasureConfirmPage(c, org.Name, org.LogoURL, orgSlug, "", req)
}

// CancelErasure handles GET /:org_slug/account/erasure/cancel?token=…
//
// Validates the cancel token and cancels a scheduled erasure request.
func (h *AccountHandler) CancelErasure(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	token := c.QueryParam("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing token")
	}

	req, err := h.erasure.Cancel(ctx, token)
	if err != nil {
		return c.Redirect(http.StatusFound, "/"+orgSlug+"/account?flash=erasure_cancel_failed")
	}

	log.Info().
		Str("user_id", req.UserID.String()).
		Str("org_id", req.OrgID.String()).
		Msg("gdpr-erasure: cancelled by user")

	return c.Redirect(http.StatusFound, "/"+orgSlug+"/account?flash=erasure_cancelled")
}

// renderErasureConfirmPage renders the standalone erasure confirmation/error page.
// It does not use the account_base layout (no session required — user may be logged out).
func (h *AccountHandler) renderErasureConfirmPage(
	c echo.Context,
	orgName string, logoURL *string, orgSlug, errKind string,
	req *repository.ErasureRequest,
) error {
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().Header().Set("Cache-Control", "no-store")
	return accountErasureConfirmTmpl.ExecuteTemplate(c.Response().Writer, "account_erasure_confirm", map[string]interface{}{
		"OrgName": orgName,
		"LogoURL": logoURL,
		"OrgSlug": orgSlug,
		"ErrKind": errKind,
		"Request": req,
		"Nonce":   middleware.GetCSPNonce(c),
	})
}
