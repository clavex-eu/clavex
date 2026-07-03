// Package forwardauth implements a Forward Auth proxy endpoint.
package forwardauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

const (
	cookieName      = "_clavex_session"
	redirectCookie  = "_clavex_rd"
	stateCookieName = "_clavex_state"
	sessionTTL      = 8 * time.Hour
)

// Handler handles Forward Auth endpoints.
type Handler struct {
	sessions *BrowserSessionRepository
	orgs     *repository.OrgRepository
	users    *repository.UserRepository
	cfg      *config.Config
}

// New creates a Forward Auth handler.
func New(cfg *config.Config, pool *pgxpool.Pool) *Handler {
	return &Handler{
		sessions: NewBrowserSessionRepository(pool),
		orgs:     repository.NewOrgRepository(pool),
		users:    repository.NewUserRepository(pool),
		cfg:      cfg,
	}
}

// Verify checks for a valid browser session cookie.
// Returns 200 + X-Auth-* headers on success, 401 on failure.
// GET /:org_slug/auth/verify
func (h *Handler) Verify(c echo.Context) error {
	cookie, err := c.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return c.NoContent(http.StatusUnauthorized)
	}
	hash := hashSession(cookie.Value)
	sess, err := h.sessions.GetByHash(c.Request().Context(), hash)
	if err != nil || sess == nil || sess.ExpiresAt.Before(time.Now()) {
		clearCookie(c)
		return c.NoContent(http.StatusUnauthorized)
	}
	go h.sessions.Touch(context.Background(), sess.ID) //nolint:errcheck
	user, err := h.users.GetByID(c.Request().Context(), sess.UserID)
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}
	c.Response().Header().Set("X-Auth-User-Id", user.ID.String())
	c.Response().Header().Set("X-Auth-User-Email", user.Email)
	c.Response().Header().Set("X-Auth-Org-Id", sess.OrgID.String())
	if user.FirstName != nil {
		c.Response().Header().Set("X-Auth-User-Name", *user.FirstName)
	}
	return c.NoContent(http.StatusOK)
}

// SignIn saves the original URL and redirects to OIDC authorize.
// GET /:org_slug/auth/sign-in?rd=<original_url>
func (h *Handler) SignIn(c echo.Context) error {
	slug := c.Param("org_slug")
	org, err := h.orgs.GetBySlug(c.Request().Context(), slug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}
	rd := c.QueryParam("rd")
	if rd == "" {
		rd = "/"
	}
	c.SetCookie(&http.Cookie{Name: redirectCookie, Value: rd, Path: "/", MaxAge: 300, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	state, err := generateToken()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate state")
	}
	c.SetCookie(&http.Cookie{Name: stateCookieName, Value: state, Path: "/", MaxAge: 300, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, org.Slug)
	callbackURL := issuer + "/auth/callback"
	authURL := issuer + "/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"forward_auth"},
		"redirect_uri":  {callbackURL},
		"scope":         {"openid profile email"},
		"state":         {state},
	}.Encode()
	return c.Redirect(http.StatusFound, authURL)
}

// Callback handles the OIDC authorization code return.
// GET /:org_slug/auth/callback?code=...&state=...
func (h *Handler) Callback(c echo.Context) error {
	slug := c.Param("org_slug")
	org, err := h.orgs.GetBySlug(c.Request().Context(), slug)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}
	state := c.QueryParam("state")
	stateCookie, err := c.Cookie(stateCookieName)
	if err != nil || stateCookie.Value != state || state == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid state")
	}
	c.SetCookie(&http.Cookie{Name: stateCookieName, Value: "", MaxAge: -1, Path: "/"})
	code := c.QueryParam("code")
	if code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing code")
	}
	user, err := h.callbackImpl(c, org, code)
	if err != nil {
		return err
	}
	raw, err := generateToken()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create session")
	}
	hash := hashSession(raw)
	if err := h.sessions.Create(c.Request().Context(), org.ID, user.ID, hash, c.Request().UserAgent(), c.RealIP(), sessionTTL); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to persist session")
	}
	secure := c.Request().TLS != nil
	c.SetCookie(&http.Cookie{Name: cookieName, Value: raw, Path: "/", MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	rd := "/"
	if rdCookie, err := c.Cookie(redirectCookie); err == nil && rdCookie.Value != "" {
		rd = safeRedirect(rdCookie.Value, h.cfg.Auth.IssuerBase, "/")
		c.SetCookie(&http.Cookie{Name: redirectCookie, Value: "", MaxAge: -1, Path: "/"})
	}
	return c.Redirect(http.StatusFound, rd)
}

// safeRedirect returns target only if it is a safe post-auth destination — a
// site-relative path, or an absolute URL on the same origin as issuerBase —
// otherwise it returns fallback. This prevents open redirects (CWE-601) via a
// caller-supplied `rd` value.
func safeRedirect(target, issuerBase, fallback string) string {
	if target == "" {
		return fallback
	}
	u, err := url.Parse(target)
	if err != nil {
		return fallback
	}
	if u.Scheme == "" && u.Host == "" {
		// Site-relative path. Reject "//host" and "/\host", which browsers treat
		// as scheme-relative absolute URLs.
		if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") && !strings.HasPrefix(target, "/\\") {
			return target
		}
		return fallback
	}
	// Absolute URL: only allow the same origin as the configured issuer base.
	if base, berr := url.Parse(issuerBase); berr == nil && u.Scheme == base.Scheme && u.Host == base.Host {
		return target
	}
	return fallback
}

// SignOut clears the session cookie and deletes the session record.
// GET /:org_slug/auth/sign-out
func (h *Handler) SignOut(c echo.Context) error {
	if cookie, err := c.Cookie(cookieName); err == nil && cookie.Value != "" {
		hash := hashSession(cookie.Value)
		_ = h.sessions.DeleteByHash(c.Request().Context(), hash)
	}
	clearCookie(c)
	slug := c.Param("org_slug")
	fallback := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, slug) + "/auth/sign-in"
	rd := safeRedirect(c.QueryParam("rd"), h.cfg.Auth.IssuerBase, fallback)
	return c.Redirect(http.StatusFound, rd)
}

// callbackImpl exchanges the authorization code via the local token endpoint.
func (h *Handler) callbackImpl(c echo.Context, org *models.Organization, code string) (*models.User, error) {
	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, org.Slug)
	callbackURL := issuer + "/auth/callback"
	tokenURL := issuer + "/token"
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callbackURL}, "client_id": {"forward_auth"}}
	tokenReq, err := http.NewRequestWithContext(c.Request().Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "token request failed")
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "token exchange failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "token exchange rejected")
	}
	var tokenBody struct {
		AccessToken string `json:"access_token"`
	}
	if err := decodeJSON(resp.Body, &tokenBody); err != nil || tokenBody.AccessToken == "" {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid token response")
	}
	req, _ := http.NewRequestWithContext(c.Request().Context(), http.MethodGet, issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenBody.AccessToken)
	uiResp, err := http.DefaultClient.Do(req)
	if err != nil || uiResp.StatusCode != http.StatusOK {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "userinfo failed")
	}
	defer uiResp.Body.Close()
	var ui struct {
		Sub string `json:"sub"`
	}
	if err := decodeJSON(uiResp.Body, &ui); err != nil || ui.Sub == "" {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid userinfo")
	}
	userID, err := uuid.Parse(ui.Sub)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid sub")
	}
	return h.users.GetByID(c.Request().Context(), userID)
}

func clearCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}
