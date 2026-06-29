package handler

// RFC 8628 – OAuth 2.0 Device Authorization Grant

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/lockout"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/tracing"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
)

// ── Compiled templates ────────────────────────────────────────────────────────

var deviceCodeEntryTmpl = template.Must(
	template.ParseFS(templateFS, "templates/device_code.html"),
)

var deviceLoginPageTmpl = template.Must(
	template.ParseFS(templateFS, "templates/device_login.html"),
)

var deviceConsentPageTmpl = template.Must(
	template.ParseFS(templateFS, "templates/device_consent.html"),
)

var deviceDonePageTmpl = template.Must(
	template.ParseFS(templateFS, "templates/device_done.html"),
)

// ── §3.1 POST /:org_slug/device_authorization ─────────────────────────────────

// DeviceAuthorization implements RFC 8628 §3.1.
func (h *OIDCHandler) DeviceAuthorization(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.oidc.device_authorization")
	defer span.End()
	span.SetAttributes(attribute.String("org_slug", orgSlug))

	clientID, _, _, err := h.authenticateClient(c)
	if err != nil {
		span.SetStatus(otelcodes.Error, "invalid_client")
		return tokenError(c, "invalid_client", err.Error())
	}

	client, err := h.clients.GetByClientID(ctx, clientID)
	if err != nil {
		return tokenError(c, "invalid_client", "client not found")
	}
	hasGrant := false
	for _, g := range client.GrantTypes {
		if g == "urn:ietf:params:oauth:grant-type:device_code" {
			hasGrant = true
			break
		}
	}
	if !hasGrant {
		return tokenError(c, "unauthorized_client", "client not authorised for device_code grant")
	}

	scope := strings.TrimSpace(c.FormValue("scope"))
	if scope == "" {
		scope = "openid"
	}

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return tokenError(c, "invalid_request", "org not found")
	}

	dc, rawDevice, err := h.deviceCodes.Create(ctx, org.ID, clientID, scope, 10*time.Minute)
	if err != nil {
		span.RecordError(err)
		return echo.ErrInternalServerError
	}

	issuer := h.issuerFromRequest(c, orgSlug)
	verificationURI := issuer + "/device"
	span.SetAttributes(
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.device_code.user_code", dc.UserCode),
	)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"device_code":               rawDevice,
		"user_code":                 dc.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + dc.UserCode,
		"expires_in":                int(time.Until(dc.ExpiresAt).Seconds()),
		"interval":                  dc.PollInterval,
	})
}

// ── §3.3 User interaction: GET/POST /:org_slug/device ─────────────────────────

// DeviceUserPage renders the user-code entry form.
func (h *OIDCHandler) DeviceUserPage(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	data := map[string]interface{}{
		"Error":         "",
		"PrefilledCode": c.QueryParam("user_code"),
		"OrgName":       "",
		"LogoURL":       "",
	}
	if org, err := h.orgs.GetBySlug(ctx, orgSlug); err == nil {
		data["OrgName"] = org.Name
		if org.LogoURL != nil {
			data["LogoURL"] = *org.LogoURL
		}
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return deviceCodeEntryTmpl.Execute(c.Response(), data)
}

// DeviceUserSubmit validates the user code and routes to login or consent.
func (h *OIDCHandler) DeviceUserSubmit(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	userCode := strings.ToUpper(strings.TrimSpace(c.FormValue("user_code")))

	renderErr := func(msg string) error {
		data := map[string]interface{}{
			"Error":         msg,
			"PrefilledCode": userCode,
			"OrgName":       "",
			"LogoURL":       "",
		}
		if org, err := h.orgs.GetBySlug(ctx, orgSlug); err == nil {
			data["OrgName"] = org.Name
			if org.LogoURL != nil {
				data["LogoURL"] = *org.LogoURL
			}
		}
		c.Response().WriteHeader(http.StatusUnprocessableEntity)
		c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
		return deviceCodeEntryTmpl.Execute(c.Response(), data)
	}

	if userCode == "" {
		return renderErr("Please enter the code displayed on your device.")
	}
	dc, err := h.deviceCodes.GetByUserCode(ctx, userCode)
	if err != nil {
		return renderErr("Code not found. Please check the code and try again.")
	}
	if time.Now().After(dc.ExpiresAt) {
		return renderErr("Code has expired. Please restart the activation on your device.")
	}
	if dc.IsAuthorized != nil {
		return renderErr("This code has already been used.")
	}

	issuer := h.issuerFromRequest(c, orgSlug)

	// If the user already has an active SSO session, skip straight to consent.
	if cookie, cookieErr := c.Cookie(ssoCookie); cookieErr == nil {
		if ssoSess, sessErr := h.store.GetSSOSession(ctx, cookie.Value); sessErr == nil &&
			ssoSess != nil && ssoSess.OrgSlug == orgSlug {
			return c.Redirect(http.StatusFound,
				fmt.Sprintf("%s/device/consent?dc_id=%s", issuer, dc.ID.String()))
		}
	}
	return c.Redirect(http.StatusFound,
		fmt.Sprintf("%s/device/login?dc_id=%s", issuer, dc.ID.String()))
}

// ── Device login ──────────────────────────────────────────────────────────────

// DeviceLoginPage renders the email+password form for device activation.
func (h *OIDCHandler) DeviceLoginPage(c echo.Context) error {
	return h.renderDeviceLoginPage(c, c.Param("org_slug"), c.QueryParam("dc_id"), "", "", "")
}

func (h *OIDCHandler) renderDeviceLoginPage(c echo.Context, orgSlug, dcID, email, errMsg, lockedUntil string) error {
	ctx := c.Request().Context()
	data := map[string]interface{}{
		"OrgName":     "",
		"LogoURL":     "",
		"DCID":        dcID,
		"Email":       email,
		"Error":       errMsg,
		"LockedUntil": lockedUntil,
		"ClientName":  "",
		"Scope":       "",
	}
	if org, err := h.orgs.GetBySlug(ctx, orgSlug); err == nil {
		data["OrgName"] = org.Name
		if org.LogoURL != nil {
			data["LogoURL"] = *org.LogoURL
		}
	}
	if id, err := uuid.Parse(dcID); err == nil {
		if dc, err := h.deviceCodes.GetByID(ctx, id); err == nil {
			if cl, err := h.clients.GetByClientID(ctx, dc.ClientID); err == nil {
				data["ClientName"] = cl.Name
				data["Scope"] = dc.Scope
			}
		}
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return deviceLoginPageTmpl.Execute(c.Response(), data)
}

// DeviceLoginSubmit handles email+password login for device activation.
func (h *OIDCHandler) DeviceLoginSubmit(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	dcIDStr := c.FormValue("dc_id")
	email := strings.ToLower(strings.TrimSpace(c.FormValue("email")))
	password := c.FormValue("password")

	renderErr := func(msg string) error {
		return h.renderDeviceLoginPage(c, orgSlug, dcIDStr, email, msg, "")
	}

	dcID, err := uuid.Parse(dcIDStr)
	if err != nil {
		return renderErr("Invalid activation session. Please start over on your device.")
	}
	dc, err := h.deviceCodes.GetByID(ctx, dcID)
	if err != nil || time.Now().After(dc.ExpiresAt) {
		return renderErr("Activation code expired. Please restart the process on your device.")
	}
	if dc.IsAuthorized != nil {
		return renderErr("This code has already been used.")
	}

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return renderErr("Organization not found.")
	}

	if h.guard != nil {
		if remaining, locked := h.guard.IsLocked(ctx, org.ID.String(), email); locked {
			return h.renderDeviceLoginPage(c, orgSlug, dcIDStr, email, "",
				lockout.FormatDuration(remaining))
		}
	}

	user, err := h.users.GetByEmail(ctx, org.ID, email)
	if err != nil || !user.IsActive {
		if h.guard != nil {
			h.guard.RecordFailure(ctx, org.ID.String(), email, 0)
		}
		return renderErr("Invalid email or password.")
	}
	if user.PasswordHash == nil || !h.users.CheckPassword(*user.PasswordHash, password) {
		if h.guard != nil {
			h.guard.RecordFailure(ctx, org.ID.String(), email, 0)
		}
		return renderErr("Invalid email or password.")
	}

	if h.guard != nil {
		h.guard.ClearFailures(ctx, org.ID.String(), email)
	}

	ssoID := uuid.NewString()
	ssoSess := &session.SSOSession{
		ID:        ssoID,
		UserID:    user.ID.String(),
		OrgID:     org.ID.String(),
		OrgSlug:   orgSlug,
		AuthTime:  time.Now().Unix(),
		CreatedAt: time.Now(),
	}
	if err := h.store.SaveSSOSession(ctx, ssoSess); err != nil {
		return renderErr("An error occurred. Please try again.")
	}
	setSSOCookie(c, ssoID)

	issuer := h.issuerFromRequest(c, orgSlug)
	return c.Redirect(http.StatusFound,
		fmt.Sprintf("%s/device/consent?dc_id=%s", issuer, dc.ID.String()))
}

// ── Device consent ────────────────────────────────────────────────────────────

// DeviceConsentPage renders the approve/deny page.
func (h *OIDCHandler) DeviceConsentPage(c echo.Context) error {
	return h.renderDeviceConsentPage(c, c.Param("org_slug"), c.QueryParam("dc_id"), "")
}

func (h *OIDCHandler) renderDeviceConsentPage(c echo.Context, orgSlug, dcIDStr, errMsg string) error {
	ctx := c.Request().Context()
	data := map[string]interface{}{
		"OrgName":     "",
		"LogoURL":     "",
		"DCID":        dcIDStr,
		"ClientName":  "",
		"Scope":       "",
		"ScopeItems":  []string{},
		"UserEmail":   "",
		"UserInitial": "?",
		"Error":       errMsg,
	}
	if org, err := h.orgs.GetBySlug(ctx, orgSlug); err == nil {
		data["OrgName"] = org.Name
		if org.LogoURL != nil {
			data["LogoURL"] = *org.LogoURL
		}
	}

	dcID, err := uuid.Parse(dcIDStr)
	if err != nil {
		c.Response().WriteHeader(http.StatusBadRequest)
		c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
		return deviceConsentPageTmpl.Execute(c.Response(), data)
	}
	dc, err := h.deviceCodes.GetByID(ctx, dcID)
	if err != nil || time.Now().After(dc.ExpiresAt) {
		data["Error"] = "Activation code expired. Please restart the process on your device."
		c.Response().WriteHeader(http.StatusGone)
		c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
		return deviceConsentPageTmpl.Execute(c.Response(), data)
	}

	if cl, clErr := h.clients.GetByClientID(ctx, dc.ClientID); clErr == nil {
		data["ClientName"] = cl.Name
	}
	data["Scope"] = dc.Scope
	data["ScopeItems"] = deviceScopeDescriptions(dc.Scope)

	if cookie, cookieErr := c.Cookie(ssoCookie); cookieErr == nil {
		if ssoSess, sessErr := h.store.GetSSOSession(ctx, cookie.Value); sessErr == nil &&
			ssoSess != nil && ssoSess.OrgSlug == orgSlug {
			if userID, pErr := uuid.Parse(ssoSess.UserID); pErr == nil {
				if u, uErr := h.users.GetByID(ctx, userID); uErr == nil {
					data["UserEmail"] = u.Email
					if len(u.Email) > 0 {
						data["UserInitial"] = strings.ToUpper(string(u.Email[0]))
					}
				}
			}
		}
	}

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return deviceConsentPageTmpl.Execute(c.Response(), data)
}

// DeviceConsentSubmit handles approve/deny.
func (h *OIDCHandler) DeviceConsentSubmit(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	dcIDStr := c.FormValue("dc_id")
	action := c.FormValue("action")

	renderErr := func(msg string) error {
		return h.renderDeviceConsentPage(c, orgSlug, dcIDStr, msg)
	}

	dcID, err := uuid.Parse(dcIDStr)
	if err != nil {
		return renderErr("Invalid session. Please start over on your device.")
	}
	dc, err := h.deviceCodes.GetByID(ctx, dcID)
	if err != nil || time.Now().After(dc.ExpiresAt) {
		return renderErr("Activation code expired. Please restart the process on your device.")
	}
	if dc.IsAuthorized != nil {
		return renderErr("This code has already been used.")
	}

	cookie, cookieErr := c.Cookie(ssoCookie)
	if cookieErr != nil {
		issuer := h.issuerFromRequest(c, orgSlug)
		return c.Redirect(http.StatusFound,
			fmt.Sprintf("%s/device/login?dc_id=%s", issuer, dcIDStr))
	}
	ssoSess, sessErr := h.store.GetSSOSession(ctx, cookie.Value)
	if sessErr != nil || ssoSess == nil || ssoSess.OrgSlug != orgSlug {
		issuer := h.issuerFromRequest(c, orgSlug)
		return c.Redirect(http.StatusFound,
			fmt.Sprintf("%s/device/login?dc_id=%s", issuer, dcIDStr))
	}
	userID, pErr := uuid.Parse(ssoSess.UserID)
	if pErr != nil {
		return renderErr("An error occurred. Please sign in again.")
	}

	clientName := ""
	if cl, clErr := h.clients.GetByClientID(ctx, dc.ClientID); clErr == nil {
		clientName = cl.Name
	}

	doneData := map[string]interface{}{
		"OrgName":    "",
		"LogoURL":    "",
		"ClientName": clientName,
		"Allowed":    false,
	}
	if org, err := h.orgs.GetBySlug(ctx, orgSlug); err == nil {
		doneData["OrgName"] = org.Name
		if org.LogoURL != nil {
			doneData["LogoURL"] = *org.LogoURL
		}
	}

	if action == "allow" {
		if err := h.deviceCodes.Authorize(ctx, dcID, userID); err != nil {
			return renderErr("An error occurred. Please try again.")
		}
		doneData["Allowed"] = true
	} else {
		_ = h.deviceCodes.Deny(ctx, dcID)
	}

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return deviceDonePageTmpl.Execute(c.Response(), doneData)
}

// ── §3.5 Token polling: grant_type=urn:ietf:params:oauth:grant-type:device_code

// deviceCodeGrant handles the device polling leg of RFC 8628.
func (h *OIDCHandler) deviceCodeGrant(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	clientID, _, _, err := h.authenticateClient(c)
	if err != nil {
		return tokenError(c, "invalid_client", err.Error())
	}

	rawDevice := c.FormValue("device_code")
	if rawDevice == "" {
		return tokenError(c, "invalid_request", "missing device_code")
	}

	dc, err := h.deviceCodes.GetByDeviceCode(ctx, rawDevice)
	if err != nil {
		return tokenError(c, "invalid_grant", "device code not found")
	}
	if dc.ClientID != clientID {
		return tokenError(c, "invalid_grant", "device code was not issued to this client")
	}
	if time.Now().After(dc.ExpiresAt) {
		return tokenError(c, "expired_token", "device code expired")
	}

	if tooFast, pollErr := h.deviceCodes.TouchPoll(ctx, dc.ID, dc.PollInterval); pollErr == nil && tooFast {
		_ = h.deviceCodes.SlowDown(ctx, dc.ID)
		return tokenError(c, "slow_down",
			fmt.Sprintf("polling too fast; wait at least %d seconds", dc.PollInterval+5))
	}

	if dc.IsAuthorized == nil {
		return tokenError(c, "authorization_pending", "user has not yet approved the request")
	}
	if !*dc.IsAuthorized {
		return tokenError(c, "access_denied", "user denied the request")
	}

	user, err := h.users.GetByID(ctx, *dc.UserID)
	if err != nil || !user.IsActive {
		return tokenError(c, "invalid_grant", "user not found or inactive")
	}

	tc := h.newTC(h.issuerFromRequest(c, orgSlug))
	// Resolve per-client id_token alg and apply TTL overrides.
	idTokenAlg := ""
	var dcCl *models.OIDCClient
	if fetched, clErr := h.clients.GetByClientID(ctx, clientID); clErr == nil {
		dcCl = fetched
		idTokenAlg = dcCl.IDTokenSignedResponseAlg
	}
	var dcOrg *models.Organization
	if o, oErr := h.orgs.GetBySlug(ctx, orgSlug); oErr == nil {
		dcOrg = o
	}
	h.applyOrgOverrides(ctx, tc, dcOrg, dcCl)
	uc := oidc.UserClaimsFromModel(user)
	if roleNames, err := h.users.FlattenRoleNames(ctx, user.ID); err == nil {
		uc.Roles = roleNames
	}
	if gnames, err := h.groups.GroupsForUser(ctx, user.ID); err == nil {
		uc.Groups = gnames
	}
	if h.mappers != nil {
		uc.ExtraClaims = oidc.ResolveMapperExtraClaims(ctx, h.mappers, clientID, uc, user.Metadata)
	}
	if h.flags != nil {
		var roleIDs []uuid.UUID
		if rms, rErr := h.users.ListRolesByUser(ctx, user.ID); rErr == nil {
			roleIDs = make([]uuid.UUID, len(rms))
			for i, r := range rms {
				roleIDs[i] = r.ID
			}
		}
		if flags, fErr := h.flags.ResolveForUser(ctx, dc.OrgID, user.ID, roleIDs); fErr == nil && flags != nil {
			if uc.ExtraClaims == nil {
				uc.ExtraClaims = map[string]any{}
			}
			uc.ExtraClaims["flags"] = flags
		}
	}

	accessToken, _, err := tc.IssueAccessToken(clientID, dc.Scope, &uc, nil, nil)
	if err != nil {
		return echo.ErrInternalServerError
	}
	uc.AtHash = oidc.ComputeAtHash(accessToken)

	idToken, err := tc.IssueIDToken(clientID, "", uc, oidc.ResolveIDTokenAlg(idTokenAlg))
	if err != nil {
		return echo.ErrInternalServerError
	}

	familyID := uuid.New()
	refreshToken, err := oidc.IssueRefreshToken(ctx, h.tokens, repository.CreateRefreshTokenParams{
		OrgID:     dc.OrgID,
		ClientID:  clientID,
		UserID:    dc.UserID,
		FamilyID:  familyID,
		Scope:     dc.Scope,
		ExpiresAt: time.Now().Add(tc.RefreshTokenTTL),
	})
	if err != nil {
		return echo.ErrInternalServerError
	}

	_ = h.deviceCodes.Delete(ctx, dc.ID)

	return c.JSON(http.StatusOK, &oidc.TokenSet{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(tc.AccessTokenTTL.Seconds()),
		Scope:        dc.Scope,
	})
}

// deviceScopeDescriptions returns human-readable descriptions for scope values.
func deviceScopeDescriptions(scope string) []string {
	known := map[string]string{
		"openid":         "Verify your identity",
		"profile":        "Read your name and profile picture",
		"email":          "Read your email address",
		"offline_access": "Stay connected (use refresh tokens)",
		"address":        "Read your address",
		"phone":          "Read your phone number",
	}
	var out []string
	for _, s := range strings.Fields(scope) {
		if desc, ok := known[s]; ok {
			out = append(out, desc)
		} else {
			out = append(out, s)
		}
	}
	return out
}
