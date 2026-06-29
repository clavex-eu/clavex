package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// AutoEnrollHandler manages domain-based organization enrollment config.
//
//	GET  /api/v1/organizations/:org_id/auto-enroll
//	PUT  /api/v1/organizations/:org_id/auto-enroll
type AutoEnrollHandler struct {
	orgs *repository.OrgRepository
}

func NewAutoEnrollHandler(pool *pgxpool.Pool) *AutoEnrollHandler {
	return &AutoEnrollHandler{orgs: repository.NewOrgRepository(pool)}
}

type autoEnrollConfig struct {
	Domains []string   `json:"domains"`
	RoleID  *uuid.UUID `json:"role_id,omitempty"`
}

// Get returns the current auto-enroll configuration for an org.
func (h *AutoEnrollHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	domains, roleID, err := h.orgs.GetAutoEnrollConfig(c.Request().Context(), orgID)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("get auto-enroll config failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load config"})
	}
	return c.JSON(http.StatusOK, autoEnrollConfig{Domains: domains, RoleID: roleID})
}

// Put replaces the auto-enroll configuration.
// Domains are normalised to lowercase and de-duplicated.
func (h *AutoEnrollHandler) Put(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req autoEnrollConfig
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Normalise domains.
	seen := make(map[string]bool)
	clean := make([]string, 0, len(req.Domains))
	for _, d := range req.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		// Reject anything that looks like a full email address.
		if strings.Contains(d, "@") {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "domains must not contain '@'; provide only the domain part (e.g. 'acme.com')"})
		}
		seen[d] = true
		clean = append(clean, d)
	}

	if err := h.orgs.SetAutoEnrollConfig(c.Request().Context(), orgID, clean, req.RoleID); err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("set auto-enroll config failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save config"})
	}
	return c.JSON(http.StatusOK, autoEnrollConfig{Domains: clean, RoleID: req.RoleID})
}

// ── Auto-enroll hook ──────────────────────────────────────────────────────────

// applyAutoEnrollRole checks whether the org has domain-based enrollment enabled
// and, if the user's email domain matches, assigns the configured role.
// It is intentionally a best-effort helper: errors are logged but not returned.
// Call this immediately after creating a new user.
func applyAutoEnrollRole(ctx context.Context, orgs *repository.OrgRepository, users *repository.UserRepository, orgID uuid.UUID, user *models.User) {
	domains, roleID, err := orgs.GetAutoEnrollConfig(ctx, orgID)
	if err != nil || roleID == nil || len(domains) == 0 {
		return
	}
	parts := strings.SplitN(user.Email, "@", 2)
	if len(parts) != 2 {
		return
	}
	emailDomain := strings.ToLower(parts[1])
	for _, d := range domains {
		if strings.ToLower(d) == emailDomain {
			if err := users.AssignRole(ctx, user.ID, *roleID); err != nil {
				log.Error().Err(err).
					Str("user_id", user.ID.String()).
					Str("role_id", roleID.String()).
					Msg("auto-enroll: failed to assign role")
			}
			return
		}
	}
}

// checkEmailPolicy validates that email complies with the org's blocklist/allowlist policy.
// It returns a non-empty human-readable reason string when the email is rejected, or ""
// when it is allowed.
//
// Rules:
//   - If allowlist is non-empty, the email domain MUST match one entry (allowlist wins).
//   - If only blocklist is set, the email domain must NOT match any entry.
//   - Patterns can use a "*" wildcard prefix, e.g. "*.tempmail.com" matches any subdomain.
func checkEmailPolicy(email string, blocklist, allowlist []string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	domain := strings.ToLower(parts[1])

	if len(allowlist) > 0 {
		for _, pattern := range allowlist {
			if emailDomainMatches(domain, pattern) {
				return ""
			}
		}
		return "email domain is not permitted for this organization"
	}

	for _, pattern := range blocklist {
		if emailDomainMatches(domain, pattern) {
			return "email domain is blocked for this organization"
		}
	}
	return ""
}

// emailDomainMatches reports whether domain matches pattern.
// Pattern may be an exact domain ("acme.com") or a wildcard prefix ("*.acme.com").
func emailDomainMatches(domain, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g. ".acme.com"
		return strings.HasSuffix(domain, suffix)
	}
	return domain == pattern
}
