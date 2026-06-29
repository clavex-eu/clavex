package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/lockout"
	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// LockoutHandler serves the admin API for per-org adaptive lockout configuration.
//
//	GET    /lockout                      → current bands
//	PUT    /lockout                      → upsert bands
//	DELETE /lockout                      → reset to defaults
//	PUT    /lockout/unlock/:email        → immediate admin unlock (clears Redis)
//	POST   /lockout/unlock-link/:email   → send one-time magic-link email
//	GET    /lockout/redeem               → public: consume token, clear lockout
type LockoutHandler struct {
	repo  *repository.LockoutRepository
	guard *lockout.Guard
	store *session.Store
	smtp  *repository.SMTPRepository
	orgs  *repository.OrgRepository
	cfg   *config.Config
}

// NewLockoutHandler creates a LockoutHandler.
func NewLockoutHandler(repo *repository.LockoutRepository) *LockoutHandler {
	return &LockoutHandler{repo: repo}
}

// WithGuard attaches the lockout guard so the handler can clear Redis keys.
func (h *LockoutHandler) WithGuard(g *lockout.Guard) *LockoutHandler {
	h.guard = g
	return h
}

// WithSessionStore attaches the session store for magic-link token management.
func (h *LockoutHandler) WithSessionStore(s *session.Store) *LockoutHandler {
	h.store = s
	return h
}

// WithSMTP attaches the SMTP repository for sending unlock emails.
func (h *LockoutHandler) WithSMTP(s *repository.SMTPRepository) *LockoutHandler {
	h.smtp = s
	return h
}

// WithOrgRepository attaches the org repository for org name lookups.
func (h *LockoutHandler) WithOrgRepository(r *repository.OrgRepository) *LockoutHandler {
	h.orgs = r
	return h
}

// WithConfig attaches the server config for base URL construction.
func (h *LockoutHandler) WithConfig(c *config.Config) *LockoutHandler {
	h.cfg = c
	return h
}

// GetLockoutConfig returns the current lockout config for an org.
// GET /api/v1/organizations/:org_id/lockout
func (h *LockoutHandler) GetLockoutConfig(c echo.Context) error {
	orgID := c.Param("org_id")
	if _, err := uuid.Parse(orgID); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	cfg, err := h.repo.GetLockoutConfig(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not load lockout config")
	}
	return c.JSON(http.StatusOK, cfg)
}

// upsertLockoutConfigRequest is the request body for PUT /lockout.
type upsertLockoutConfigRequest struct {
	Bands      []lockout.Band `json:"bands"`
	AlertAdmin bool           `json:"alert_admin"`
}

// UpsertLockoutConfig creates or replaces the lockout config for an org.
// PUT /api/v1/organizations/:org_id/lockout
func (h *LockoutHandler) UpsertLockoutConfig(c echo.Context) error {
	orgID := c.Param("org_id")
	if _, err := uuid.Parse(orgID); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	var req upsertLockoutConfigRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if len(req.Bands) == 0 {
		req.Bands = lockout.DefaultBands
	}
	// Validate bands: ranges must not overlap and every band needs positive values.
	for _, b := range req.Bands {
		if b.ScoreMin < 0 || b.ScoreMax > 100 || b.ScoreMin > b.ScoreMax {
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "band score range invalid")
		}
		if b.MaxAttempts <= 0 || b.LockoutSecs <= 0 {
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "band max_attempts and lockout_seconds must be positive")
		}
	}

	if err := h.repo.UpsertLockoutConfig(c.Request().Context(), orgID, req.Bands, req.AlertAdmin); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not save lockout config")
	}
	cfg, _ := h.repo.GetLockoutConfig(c.Request().Context(), orgID)
	return c.JSON(http.StatusOK, cfg)
}

// DeleteLockoutConfig resets an org to the global defaults by removing the custom row.
// DELETE /api/v1/organizations/:org_id/lockout
func (h *LockoutHandler) DeleteLockoutConfig(c echo.Context) error {
	orgID := c.Param("org_id")
	if _, err := uuid.Parse(orgID); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	if err := h.repo.DeleteLockoutConfig(c.Request().Context(), orgID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not reset lockout config")
	}
	return c.NoContent(http.StatusNoContent)
}

// UnlockUser immediately clears the Redis lockout for a (orgID, email) pair.
// PUT /api/v1/organizations/:org_id/lockout/unlock/:email
func (h *LockoutHandler) UnlockUser(c echo.Context) error {
	orgID := c.Param("org_id")
	if _, err := uuid.Parse(orgID); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	email := c.Param("email")
	if email == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "email required")
	}
	if h.guard == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "lockout guard not configured")
	}
	h.guard.ClearFailures(c.Request().Context(), orgID, email)
	return c.NoContent(http.StatusNoContent)
}

// SendUnlockMagicLink generates a one-time 15-minute unlock token and emails it
// to the locked user. The link points to the public RedeemUnlockToken endpoint.
//
// POST /api/v1/organizations/:org_id/lockout/unlock-link
// Body: { "email": "user@example.com" }
func (h *LockoutHandler) SendUnlockMagicLink(c echo.Context) error {
	ctx := c.Request().Context()
	orgID := c.Param("org_id")
	if _, err := uuid.Parse(orgID); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	orgUUID, _ := uuid.Parse(orgID)

	var body struct {
		Email string `json:"email"`
	}
	if err := c.Bind(&body); err != nil || strings.TrimSpace(body.Email) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "email is required")
	}
	email := strings.TrimSpace(body.Email)

	if h.store == nil || h.guard == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "lockout service not configured")
	}

	// Generate a 24-byte URL-safe random token.
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return echo.ErrInternalServerError
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	if err := h.store.SaveUnlockToken(ctx, token, orgID, email); err != nil {
		return echo.ErrInternalServerError
	}

	// Build the public unlock URL.
	scheme := c.Request().Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if c.Request().TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := c.Request().Host
	unlockURL := fmt.Sprintf("%s://%s/api/v1/lockout/redeem?token=%s", scheme, host, token)

	// Best-effort email — do not fail if SMTP is unconfigured.
	if h.smtp != nil {
		if m, err := mailer.ForOrg(ctx, h.smtp, orgUUID); err == nil {
			orgName := orgID
			if h.orgs != nil {
				if org, err2 := h.orgs.GetByID(ctx, orgUUID); err2 == nil && org != nil {
					orgName = org.Name
				}
			}
			_ = m.SendUnlockMagicLink(email, orgName, unlockURL)
		}
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "unlock link sent",
		"email":   email,
	})
}

// RedeemUnlockToken is the public one-time endpoint embedded in the unlock email.
// It consumes the token and clears the lockout, then redirects to the org login.
//
// GET /api/v1/lockout/redeem?token=<token>
func (h *LockoutHandler) RedeemUnlockToken(c echo.Context) error {
	ctx := c.Request().Context()
	token := c.QueryParam("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing token")
	}
	if h.store == nil || h.guard == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "lockout service not configured")
	}

	orgID, email, err := h.store.ConsumeUnlockToken(ctx, token)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if orgID == "" || email == "" {
		return echo.NewHTTPError(http.StatusGone, "unlock link has expired or was already used")
	}

	h.guard.ClearFailures(ctx, orgID, email)

	// Redirect to the org login page on success.
	// If we know the org slug we can build a nicer URL; fall back to root.
	redirectTo := "/"
	if h.orgs != nil {
		if orgUUID, err2 := uuid.Parse(orgID); err2 == nil {
			if org, err3 := h.orgs.GetByID(ctx, orgUUID); err3 == nil && org != nil {
				redirectTo = "/" + org.Slug + "/login?unlocked=1"
			}
		}
	}

	return c.Redirect(http.StatusFound, redirectTo)
}
