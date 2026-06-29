package middleware

import (
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/license"
	"github.com/labstack/echo/v4"
)

// LicenseWarning adds an X-Clavex-License-Warning response header when the
// installation is over the org limit (grace period active or expired).
// This middleware is cheap — it reads from a cached in-memory state.
func LicenseWarning(checker *license.Checker) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			s := checker.State()
			if s.ExceedsLimit {
				c.Response().Header().Set("X-Clavex-License-Warning", s.WarningMessage)
			}
			return next(c)
		}
	}
}

// oidcAuthPaths are the path suffixes that initiate new OIDC sessions.
// Only these are blocked when the license grace period expires.
var oidcAuthPaths = []string{
	"/authorize",
	"/token",
	"/device_authorization",
	"/par",
}

// RequireLicenseNotBlocked rejects OIDC authorize / token endpoints with 503
// when the installation's 30-day grace period has expired and the org count
// still exceeds the license limit. Admin API and health endpoints are unaffected.
func RequireLicenseNotBlocked(checker *license.Checker) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !checker.State().AuthBlocked {
				return next(c)
			}
			// Only block OIDC auth paths that create new sessions.
			path := c.Path()
			for _, suffix := range oidcAuthPaths {
				if strings.HasSuffix(path, suffix) {
					return echo.NewHTTPError(
						http.StatusServiceUnavailable,
						"Authentication is temporarily blocked: the license org limit has been "+
							"exceeded for more than 30 days. Contact support@clavex.eu to obtain a license.",
					)
				}
			}
			return next(c)
		}
	}
}
