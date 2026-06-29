package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/labstack/echo/v4"
)

const (
	// CSRFCookieName is the JS-readable double-submit token cookie. The SPA reads
	// it and echoes the value in CSRFHeaderName on every state-changing request.
	CSRFCookieName = "clavex_csrf"
	// CSRFHeaderName is the request header carrying the double-submit token.
	CSRFHeaderName = "X-CSRF-Token"
)

// CSRFProtect guards cookie-authenticated state-changing requests with the
// double-submit-cookie pattern. It is intentionally narrow:
//
//   - Safe methods (GET/HEAD/OPTIONS/TRACE) are never blocked; they (re)issue
//     the token cookie so the SPA always has a fresh value to echo.
//   - Requests authenticated by a header credential (Authorization: Bearer or
//     X-API-Key) are exempt: those credentials are not ambient, so they cannot
//     be driven by a cross-site forgery. This keeps programmatic/SDK clients
//     working without a CSRF token.
//   - Cookie-authenticated mutations must present CSRFHeaderName equal to the
//     CSRFCookieName value, compared in constant time. A cross-site attacker can
//     send the session cookie but can neither read the token cookie nor set a
//     custom header, so the match fails.
//
// This layers on top of the session cookie's SameSite=Lax attribute, which
// already blocks the classic cross-site POST.
func CSRFProtect(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()

			// Ensure a token cookie exists so the SPA can read and echo it.
			token := ""
			if ck, err := c.Cookie(CSRFCookieName); err == nil && ck.Value != "" {
				token = ck.Value
			} else {
				token = newCSRFToken()
				c.SetCookie(&http.Cookie{
					Name:     CSRFCookieName,
					Value:    token,
					Path:     "/",
					Domain:   cfg.Auth.AdminCookieDomain,
					HttpOnly: false, // must be readable by the SPA
					Secure:   cfg.Auth.AdminCookieSecure,
					SameSite: http.SameSiteLaxMode,
				})
			}

			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
				return next(c)
			}

			// Header-credentialed (non-ambient) callers are not CSRF-able.
			if r.Header.Get(echo.HeaderAuthorization) != "" || r.Header.Get("X-API-Key") != "" {
				return next(c)
			}

			sent := r.Header.Get(CSRFHeaderName)
			if sent == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(token)) != 1 {
				return echo.NewHTTPError(http.StatusForbidden, "invalid CSRF token")
			}
			return next(c)
		}
	}
}

func newCSRFToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
