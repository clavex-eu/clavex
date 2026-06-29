package handler

import (
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	mw "github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// AuthHandler handles admin-console authentication (not OIDC flows).
type AuthHandler struct {
	cfg        *config.Config
	users      *repository.UserRepository
	orgs       *repository.OrgRepository
	adminRoles *repository.AdminRoleRepository
}

func NewAuthHandler(cfg *config.Config, pool *pgxpool.Pool) *AuthHandler {
	return &AuthHandler{
		cfg:        cfg,
		users:      repository.NewUserRepository(pool),
		orgs:       repository.NewOrgRepository(pool),
		adminRoles: repository.NewAdminRoleRepository(pool),
	}
}

type adminLoginRequest struct {
	OrgSlug  string `json:"org_slug"  validate:"required"`
	Email    string `json:"email"     validate:"required,email"`
	Password string `json:"password"  validate:"required"`
}

type adminLoginResponse struct {
	// The session JWT is delivered exclusively as an HttpOnly cookie (set below)
	// so it never touches JS-readable storage. The body carries only non-secret
	// state the SPA needs to hydrate its UI.
	ExpiresIn    int    `json:"expires_in"`
	OrgID        string `json:"org_id"`
	OrgSlug      string `json:"org_slug"`
	IsSuperAdmin bool   `json:"is_super_admin"`
	// Permissions is nil for full-access admins and a (possibly empty)
	// list for delegated admins. nil = unrestricted; empty = no permissions.
	Permissions []string `json:"permissions"`
}

// Login authenticates an admin user and returns a short-lived JWT for the admin console.
// POST /api/v1/auth/login
func (h *AuthHandler) Login(c echo.Context) error {
	var req adminLoginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	ctx := c.Request().Context()

	org, err := h.orgs.GetBySlug(ctx, req.OrgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
	}

	user, err := h.users.GetByEmail(ctx, org.ID, req.Email)
	if err != nil || !user.IsActive {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
	}

	if user.PasswordHash == nil || !h.users.CheckPassword(*user.PasswordHash, req.Password) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
	}

	// Require the user to have the "admin" or "super_admin" role.
	roles, err := h.users.ListRolesByUser(ctx, user.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	isAdmin := false
	isSuperAdmin := false
	for _, r := range roles {
		switch r.Name {
		case "super_admin":
			isSuperAdmin = true
			isAdmin = true
		case "admin":
			isAdmin = true
		}
	}
	if !isAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "admin role required")
	}

	// For org admins (not superadmins) check for delegated admin role assignments.
	// If the user has any assignments, their JWT is restricted to those permissions.
	// No assignments = legacy full-access (permissions omitted from JWT).
	var permissions []string
	if isAdmin && !isSuperAdmin {
		perms, permErr := h.adminRoles.GetPermissionsForUser(ctx, user.ID, org.ID)
		if permErr != nil {
			// Non-fatal: log and fall through to full-access (safe degradation).
			c.Logger().Warnf("admin login: could not load delegated permissions for user %s: %v", user.ID, permErr)
		} else {
			permissions = perms // nil = full access; []string = delegated
		}
	}

	ttl := 8 * time.Hour
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":            user.ID.String(),
		"email":          user.Email,
		"org_id":         user.OrgID.String(),
		"org_slug":       org.Slug,
		"is_admin":       true,
		"is_super_admin": isSuperAdmin,
		"iat":            now.Unix(),
		"exp":            now.Add(ttl).Unix(),
		"jti":            uuid.NewString(),
	}
	if permissions != nil {
		claims["permissions"] = permissions
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(h.cfg.Auth.AdminSecret))
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Dual-transport: also deliver the JWT as an HttpOnly cookie so the browser
	// console never has to store it in JS-readable storage (XSS exfiltration
	// defence). Programmatic clients keep using the JSON token + Bearer header.
	// SameSite=Lax suits an SPA+API on the same registrable domain.
	c.SetCookie(&http.Cookie{
		Name:     mw.AdminCookieName,
		Value:    signed,
		Path:     "/",
		Domain:   h.cfg.Auth.AdminCookieDomain,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.Auth.AdminCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	return c.JSON(http.StatusOK, adminLoginResponse{
		ExpiresIn:    int(ttl.Seconds()),
		OrgID:        user.OrgID.String(),
		OrgSlug:      org.Slug,
		IsSuperAdmin: isSuperAdmin,
		Permissions:  permissions,
	})
}

// Logout clears the admin session and CSRF cookies. HttpOnly cookies cannot be
// cleared from JS, so this must be a server endpoint.
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c echo.Context) error {
	h.expireCookie(c, mw.AdminCookieName, true)
	h.expireCookie(c, mw.CSRFCookieName, false)
	return c.NoContent(http.StatusNoContent)
}

func (h *AuthHandler) expireCookie(c echo.Context, name string, httpOnly bool) {
	c.SetCookie(&http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   h.cfg.Auth.AdminCookieDomain,
		MaxAge:   -1,
		HttpOnly: httpOnly,
		Secure:   h.cfg.Auth.AdminCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
