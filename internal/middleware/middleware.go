package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// APIKeyVerifyFunc validates an X-API-Key header value and returns synthesized
// Claims on success, (nil, nil) if the key format is not ours, or an error if
// the key is present but invalid/revoked.
type APIKeyVerifyFunc func(ctx context.Context, rawKey string) (*Claims, error)

// RequestLogger returns an Echo middleware that logs every request via zerolog.
func RequestLogger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)
			req := c.Request()
			res := c.Response()

			status := res.Status
			if err != nil {
				if he, ok := err.(*echo.HTTPError); ok {
					status = he.Code
				} else {
					status = http.StatusInternalServerError
				}
			}

			log.Info().
				Str("method", req.Method).
				Str("path", req.URL.Path).
				Int("status", status).
				Dur("latency", time.Since(start)).
				Str("request_id", res.Header().Get(echo.HeaderXRequestID)).
				Str("ip", c.RealIP()).
				Msg("request")

			return err
		}
	}
}

// EurekaContextKey is the key used to store parsed claims in echo.Context.
type contextKey string

const (
	claimsKey  contextKey = "claims"
	orgSlugKey contextKey = "org_slug"
)

// AdminCookieName is the HttpOnly cookie carrying the admin-console JWT.
// The login handler sets it; requireJWT reads it as a fallback after the
// Authorization header (which programmatic/SDK clients keep using).
const AdminCookieName = "clavex_admin"

// Claims holds the JWT payload for authenticated requests.
type Claims struct {
	jwt.RegisteredClaims
	OrgID        string   `json:"org_id"`
	Email        string   `json:"email"`
	Roles        []string `json:"roles"`
	IsAdmin      bool     `json:"is_admin"`
	IsSuperAdmin bool     `json:"is_super_admin"`
	// Permissions holds the union of all delegated admin role permissions.
	// nil = legacy org admin (full access); []string = delegated admin (restricted).
	Permissions []string `json:"permissions,omitempty"`
}

// RequireAdminJWT validates the Bearer token and requires is_admin == true.
// If verifyAPIKey is non-nil, X-API-Key headers are also accepted.
func RequireAdminJWT(cfg *config.Config, verifyAPIKey ...APIKeyVerifyFunc) echo.MiddlewareFunc {
	var verifier APIKeyVerifyFunc
	if len(verifyAPIKey) > 0 {
		verifier = verifyAPIKey[0]
	}
	return requireJWT(cfg, true, verifier)
}

// RequireUserJWT validates the Bearer token (any authenticated user).
func RequireUserJWT(cfg *config.Config) echo.MiddlewareFunc {
	return requireJWT(cfg, false, nil)
}

func requireJWT(cfg *config.Config, adminOnly bool, verifier APIKeyVerifyFunc) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Try X-API-Key first (only when a verifier is wired in).
			if verifier != nil {
				apiKey := c.Request().Header.Get("X-API-Key")
				if apiKey != "" {
					claims, err := verifier(c.Request().Context(), apiKey)
					if err != nil {
						return echo.ErrUnauthorized
					}
					if claims != nil {
						c.Set(string(claimsKey), claims)
						return next(c)
					}
					// nil,nil means not our format — fall through to JWT.
				}
			}

			raw := extractBearer(c.Request())
			if raw == "" {
				// Browser admin console authenticates via the HttpOnly cookie;
				// programmatic clients use the Authorization header above.
				if ck, cerr := c.Cookie(AdminCookieName); cerr == nil {
					raw = ck.Value
				}
			}
			if raw == "" {
				return echo.ErrUnauthorized
			}

			claims := &Claims{}
			token, err := jwt.ParseWithClaims(raw, claims, keyFunc(cfg))
			if err != nil || !token.Valid {
				return echo.ErrUnauthorized
			}

			if adminOnly && !claims.IsAdmin {
				return echo.NewHTTPError(http.StatusForbidden, "admin access required")
			}

			c.Set(string(claimsKey), claims)
			return next(c)
		}
	}
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get(echo.HeaderAuthorization)
	// RFC 9110 §11.1: auth scheme names are case-insensitive.
	if idx := strings.IndexByte(h, ' '); idx > 0 && strings.EqualFold(h[:idx], "bearer") {
		return h[idx+1:]
	}
	return ""
}

// keyFunc returns the HMAC verification key for admin-console JWTs.
func keyFunc(cfg *config.Config) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, echo.ErrUnauthorized
		}
		return []byte(cfg.Auth.AdminSecret), nil
	}
}

// GetClaims retrieves the parsed JWT claims from the echo context.
func GetClaims(c echo.Context) *Claims {
	v, _ := c.Get(string(claimsKey)).(*Claims)
	return v
}

// RequireOrgAccess enforces tenant isolation: the :org_id URL param must match
// the org_id in the admin JWT, unless the caller is a super_admin.
func RequireOrgAccess() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims := GetClaims(c)
			if claims == nil {
				return echo.ErrUnauthorized
			}
			// Super-admins may access any org.
			if claims.IsSuperAdmin {
				return next(c)
			}
			orgID := c.Param("org_id")
			if orgID == "" {
				return next(c)
			}
			if orgID != claims.OrgID {
				return echo.NewHTTPError(http.StatusForbidden, "access to this organization is not allowed")
			}
			return next(c)
		}
	}
}

// RequireSuperAdmin rejects requests from non-superadmin callers.
func RequireSuperAdmin() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims := GetClaims(c)
			if claims == nil || !claims.IsSuperAdmin {
				return echo.NewHTTPError(http.StatusForbidden, "superadmin access required")
			}
			return next(c)
		}
	}
}

// RequireResourcePermission enforces delegated admin permissions for a resource.
//
// Rule:
//   - Superadmins bypass all permission checks.
//   - Legacy org admins (Permissions == nil) retain full access.
//   - Delegated admins (Permissions != nil) must hold <resource>:read on GET/HEAD
//     requests or <resource>:write on all other methods.
//     Write permission implicitly satisfies read.
//
// Add this middleware to Echo route groups to restrict access for delegated admins:
//
//	adminUsers := orgScoped.Group("/users", middleware.RequireResourcePermission("users"))
func RequireResourcePermission(resource string) echo.MiddlewareFunc {
	readPerm := resource + ":read"
	writePerm := resource + ":write"
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims := GetClaims(c)
			if claims == nil {
				return echo.ErrUnauthorized
			}
			// Superadmins and legacy org admins (no delegated restriction) always pass.
			if claims.IsSuperAdmin || claims.Permissions == nil {
				return next(c)
			}
			// Delegated admin: check permissions.
			if isReadOnlyMethod(c.Request().Method) {
				if hasPermission(claims.Permissions, readPerm) || hasPermission(claims.Permissions, writePerm) {
					return next(c)
				}
				return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions: "+readPerm+" required")
			}
			if hasPermission(claims.Permissions, writePerm) {
				return next(c)
			}
			return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions: "+writePerm+" required")
		}
	}
}

// hasPermission reports whether perms contains target.
func hasPermission(perms []string, target string) bool {
	for _, p := range perms {
		if p == target {
			return true
		}
	}
	return false
}

// isReadOnlyMethod reports whether the HTTP method is a read-only operation.
func isReadOnlyMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}
