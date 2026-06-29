package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/labstack/echo/v4"
)

// NonceKey is the context.Context key used to propagate the CSP nonce to
// non-Echo code (e.g. saml/session.go) that only has an *http.Request.
type NonceKey struct{}

const cspNonceEchoKey = "csp_nonce"

// ExtraSecurityHeaders adds the three security headers that are not covered by
// Echo's built-in Secure middleware:
//
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Permissions-Policy: geolocation=(), microphone=(), camera=()
//   - Cross-Origin-Opener-Policy: same-origin
//
// Apply globally: e.Use(middleware.ExtraSecurityHeaders())
func ExtraSecurityHeaders() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			h := c.Response().Header()
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			return next(c)
		}
	}
}

// HTMLPageCSP generates a fresh random nonce per request and applies a
// nonce-based Content-Security-Policy suitable for server-rendered HTML login
// pages, including support for Tailwind CDN, hCaptcha, and Cloudflare Turnstile.
//
// The nonce is stored in both the Echo context (key "csp_nonce") and the
// standard request context (key NonceKey{}) so it is accessible from non-Echo
// helpers such as saml/session.go.
//
// Apply on the tenant route group so it overrides the strict global CSP only
// for HTML-serving routes.
func HTMLPageCSP() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			nonce, err := generateCSPNonce()
			if err != nil {
				return echo.ErrInternalServerError
			}

			// Store nonce for template access.
			c.Set(cspNonceEchoKey, nonce)
			// Also inject into the standard context so non-Echo code can read it.
			ctx := context.WithValue(c.Request().Context(), NonceKey{}, nonce)
			c.SetRequest(c.Request().WithContext(ctx))

			// Build the CSP header.
			// script-src:  only nonce-tagged scripts + scripts they load (strict-dynamic).
			// style-src:   self + unsafe-inline (Tailwind's inline styles from CDN require it).
			// connect-src: captcha providers that make XHR/fetch calls.
			// frame-src:   captcha iframe widgets.
			// form-action: restrict form posts to same origin.
			// frame-ancestors: clickjacking protection (belt-and-suspenders with X-Frame-Options).
			csp := fmt.Sprintf(
				"default-src 'self'; "+
					"script-src 'nonce-%s' 'strict-dynamic'; "+
					"style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data: https:; "+
					"font-src 'self' https:; "+
					"connect-src 'self' https://hcaptcha.com https://newassets.hcaptcha.com https://challenges.cloudflare.com; "+
					"frame-src https://hcaptcha.com https://newassets.hcaptcha.com https://challenges.cloudflare.com; "+
					"frame-ancestors 'none'; "+
					"base-uri 'self'; "+
					"form-action 'self' https:",
				nonce,
			)
			c.Response().Header().Set("Content-Security-Policy", csp)

			return next(c)
		}
	}
}

// GetCSPNonce retrieves the per-request CSP nonce set by HTMLPageCSP.
// Returns an empty string if the middleware was not applied on this route.
func GetCSPNonce(c echo.Context) string {
	v, _ := c.Get(cspNonceEchoKey).(string)
	return v
}

func generateCSPNonce() (string, error) {
	b := make([]byte, 18) // 18 bytes → 24-char base64, well above the 128-bit minimum.
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
