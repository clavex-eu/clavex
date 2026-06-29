package handler

import (
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/go-webauthn/webauthn/protocol"
	walib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var passkeyEnrollLoginTmpl = template.Must(
	template.ParseFS(templateFS, "templates/passkey_enroll_login.html"),
)

// PasskeyEnrollLoginHandler handles the "enroll-on-next-login" passkey flow.
//
// Administrators mark a user with required_action=ENROLL_PASSKEY (via
// PUT /api/v1/organizations/:org_id/users/:id/required-actions). On the next
// login, after password / MFA is verified, the user is redirected here to
// complete a WebAuthn registration before receiving the auth code.
//
// Endpoints (tenant-scoped, no JWT — auth is via the login session):
//
//	GET  /:org_slug/enroll-passkey            — HTML enrollment page
//	POST /:org_slug/enroll-passkey/begin      — begin WebAuthn ceremony (JSON)
//	POST /:org_slug/enroll-passkey/finish     — finish ceremony, clear action
type PasskeyEnrollLoginHandler struct {
	store    *session.Store
	orgs     *repository.OrgRepository
	users    *repository.UserRepository
	mfaRepo  *repository.MFARepository
	webAuthn *walib.WebAuthn // nil when WebAuthn is not configured
	rdb      redis.UniversalClient
}

type passkeyEnrollLoginData struct {
	OrgName        string
	OrgSlug        string
	LogoURL        string
	LoginSessionID string
	Error          string
	Nonce          string
}

// NewPasskeyEnrollLoginHandler constructs the handler from the same dependencies
// as MFAHandler so server.go can share the already-constructed values.
func NewPasskeyEnrollLoginHandler(
	store *session.Store,
	orgs *repository.OrgRepository,
	users *repository.UserRepository,
	mfaRepo *repository.MFARepository,
	webAuthn *walib.WebAuthn, // may be nil
	rdb redis.UniversalClient,
) *PasskeyEnrollLoginHandler {
	return &PasskeyEnrollLoginHandler{
		store:    store,
		orgs:     orgs,
		users:    users,
		mfaRepo:  mfaRepo,
		webAuthn: webAuthn,
		rdb:      rdb,
	}
}

// EnrollPage renders the enrollment landing page.
// GET /:org_slug/enroll-passkey?login_session_id=...
func (h *PasskeyEnrollLoginHandler) EnrollPage(c echo.Context) error {
	orgSlug := c.Param("org_slug")
	sessID := c.QueryParam("login_session_id")

	ctx := c.Request().Context()
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please start over")
	}

	errMsg := ""
	if h.webAuthn == nil {
		errMsg = "Passkey enrollment is not configured for this server."
	}

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return passkeyEnrollLoginTmpl.Execute(c.Response().Writer, passkeyEnrollLoginData{
		OrgName:        org.Name,
		OrgSlug:        orgSlug,
		LogoURL:        orgLogoURL(org.LogoURL),
		LoginSessionID: sessID,
		Error:          errMsg,
		Nonce:          middleware.GetCSPNonce(c),
	})
}

// EnrollBegin starts the WebAuthn registration ceremony.
// POST /:org_slug/enroll-passkey/begin?login_session_id=...
func (h *PasskeyEnrollLoginHandler) EnrollBegin(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}

	orgSlug := c.Param("org_slug")
	sessID := c.FormValue("login_session_id")
	if sessID == "" {
		sessID = c.QueryParam("login_session_id")
	}

	ctx := c.Request().Context()

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}
	_ = org

	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess == nil || loginSess.UserID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired")
	}

	userID, err := uuid.Parse(loginSess.UserID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrNotFound
	}

	existing, err := h.mfaRepo.ListWebAuthnByUser(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	waUser := &webAuthnUser{
		id:          userID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}

	options, waSession, err := h.webAuthn.BeginRegistration(waUser,
		walib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		walib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "begin passkey registration failed")
	}

	sessionBytes, _ := json.Marshal(waSession)
	redisKey := "pk:enroll-login:" + userID.String()
	if err := h.rdb.Set(ctx, redisKey, sessionBytes, webAuthnChallengeTTL).Err(); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusOK, options)
}

// EnrollFinish completes the WebAuthn registration, clears the required action,
// and redirects to /authorize/resume so the OIDC flow can complete.
// POST /:org_slug/enroll-passkey/finish?login_session_id=...
func (h *PasskeyEnrollLoginHandler) EnrollFinish(c echo.Context) error {
	if h.webAuthn == nil {
		return echo.NewHTTPError(http.StatusBadRequest, map[string]string{"error": "webauthn_not_configured"})
	}

	orgSlug := c.Param("org_slug")
	sessID := c.QueryParam("login_session_id")
	if sessID == "" {
		sessID = c.FormValue("login_session_id")
	}

	ctx := c.Request().Context()

	loginSess, err := h.store.GetLoginSession(ctx, sessID)
	if err != nil || loginSess == nil || loginSess.UserID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired")
	}

	userID, err := uuid.Parse(loginSess.UserID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Retrieve the WebAuthn challenge stored by EnrollBegin.
	redisKey := "pk:enroll-login:" + userID.String()
	sessionBytes, err := h.rdb.GetDel(ctx, redisKey).Bytes()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "passkey registration session expired; call begin first")
	}
	var waSession walib.SessionData
	if err := json.Unmarshal(sessionBytes, &waSession); err != nil {
		return echo.ErrInternalServerError
	}

	user, err := h.users.GetByID(ctx, userID)
	if err != nil {
		return echo.ErrNotFound
	}

	existing, err := h.mfaRepo.ListWebAuthnByUser(ctx, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	waUser := &webAuthnUser{
		id:          userID[:],
		name:        user.Email,
		displayName: user.GetFirstName() + " " + user.GetLastName(),
		credentials: credentialsFromModels(existing),
	}

	credential, err := h.webAuthn.FinishRegistration(waUser, waSession, c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, "passkey verification failed: "+err.Error())
	}

	// Store the credential.
	credBytes, _ := json.Marshal(credential)
	var credData map[string]interface{}
	_ = json.Unmarshal(credBytes, &credData)
	credData["is_passkey"] = true
	credData["enrolled_via"] = "login_required_action"

	if _, err := h.mfaRepo.CreateWebAuthn(ctx, userID, "Passkey", credData); err != nil {
		return echo.ErrInternalServerError
	}

	// Remove ENROLL_PASSKEY from the user's required_actions.
	newActions := make([]string, 0, len(user.RequiredActions))
	for _, a := range user.RequiredActions {
		if a != "ENROLL_PASSKEY" {
			newActions = append(newActions, a)
		}
	}
	_ = h.users.SetRequiredActions(ctx, userID, newActions)

	// Refresh the session TTL and redirect to the OIDC resume endpoint.
	_ = h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute)

	return c.Redirect(http.StatusSeeOther, "/"+orgSlug+"/authorize/resume?login_session_id="+sessID)
}
