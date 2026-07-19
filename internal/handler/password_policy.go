package handler

import (
	"net/http"
	"unicode"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// PasswordPolicyHandler manages per-org password policies.
type PasswordPolicyHandler struct {
	repo    *repository.PasswordPolicyRepository
	auditor *audit.Emitter
}

func NewPasswordPolicyHandler(pool *pgxpool.Pool) *PasswordPolicyHandler {
	return &PasswordPolicyHandler{repo: repository.NewPasswordPolicyRepository(pool)}
}

// WithAuditor attaches the audit emitter. Password-policy changes are part of
// the org settings the Kubernetes operator (ClavexOrg) reconciles, so they emit
// an "org" event on the live stream.
func (h *PasswordPolicyHandler) WithAuditor(a *audit.Emitter) *PasswordPolicyHandler {
	h.auditor = a
	return h
}

// Get returns the current password policy for an org.
// GET /api/v1/organizations/:org_id/password-policy
func (h *PasswordPolicyHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	p, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, p)
}

// ReleaseManagedMarker clears the declarative-management marker on an org's
// password policy without touching its configured values. The Kubernetes
// operator calls this when it stops managing the password-policy section (the
// section is removed from a ClavexOrg spec, or the CR is deleted) so the
// console badge disappears while the live policy is preserved.
//
// DELETE /api/v1/organizations/:org_id/password-policy/managed-marker
func (h *PasswordPolicyHandler) ReleaseManagedMarker(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	if err := h.repo.SetManagedMarker(c.Request().Context(), orgID, repository.ManagedMarkerInput{Release: true}); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

type updatePolicyRequest struct {
	MinLength              int    `json:"min_length"              validate:"min=1,max=128"`
	RequireUppercase       bool   `json:"require_uppercase"`
	RequireNumber          bool   `json:"require_number"`
	RequireSymbol          bool   `json:"require_symbol"`
	MaxAgeDays             *int   `json:"max_age_days"`
	PreventReuseCount      int    `json:"prevent_reuse_count"     validate:"min=0,max=24"`
	BreachedPasswordAction string `json:"breached_password_action"`
}

// Put replaces the password policy for an org.
// PUT /api/v1/organizations/:org_id/password-policy
func (h *PasswordPolicyHandler) Put(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req updatePolicyRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	validActions := map[string]bool{"off": true, "warn": true, "block": true, "force_reset": true}
	if req.BreachedPasswordAction != "" && !validActions[req.BreachedPasswordAction] {
		return echo.NewHTTPError(http.StatusBadRequest,
			"breached_password_action must be one of: off, warn, block, force_reset")
	}
	p := &models.PasswordPolicy{
		OrgID:                  orgID,
		MinLength:              req.MinLength,
		RequireUppercase:       req.RequireUppercase,
		RequireNumber:          req.RequireNumber,
		RequireSymbol:          req.RequireSymbol,
		MaxAgeDays:             req.MaxAgeDays,
		PreventReuseCount:      req.PreventReuseCount,
		BreachedPasswordAction: req.BreachedPasswordAction,
	}
	out, err := h.repo.Upsert(c.Request().Context(), p)
	if err != nil {
		return err
	}
	if mk := managedMarkerFromRequest(c); mk.Active() {
		if err := h.repo.SetManagedMarker(c.Request().Context(), orgID, mk); err != nil {
			return echo.ErrInternalServerError
		}
		reflectManagedMarker(&out.ManagedMarker, mk)
	}
	emitEntityAudit(c, h.auditor, orgID, "org.updated", auditResourceOrg, orgID.String(),
		map[string]interface{}{"setting": "password_policy"})
	return c.JSON(http.StatusOK, out)
}

// ValidatePassword checks a plaintext password against a policy.
// Returns nil if the password is acceptable, or an HTTP error describing the violation.
func ValidatePassword(password string, policy *models.PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return echo.NewHTTPError(http.StatusBadRequest, passwordTooShortMsg(policy.MinLength))
	}
	if policy.RequireUppercase {
		has := false
		for _, r := range password {
			if unicode.IsUpper(r) {
				has = true
				break
			}
		}
		if !has {
			return echo.NewHTTPError(http.StatusBadRequest, "password must contain at least one uppercase letter")
		}
	}
	if policy.RequireNumber {
		has := false
		for _, r := range password {
			if unicode.IsDigit(r) {
				has = true
				break
			}
		}
		if !has {
			return echo.NewHTTPError(http.StatusBadRequest, "password must contain at least one number")
		}
	}
	if policy.RequireSymbol {
		has := false
		for _, r := range password {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
				has = true
				break
			}
		}
		if !has {
			return echo.NewHTTPError(http.StatusBadRequest, "password must contain at least one special character")
		}
	}
	return nil
}

func passwordTooShortMsg(min int) string {
	return "password must be at least " + itoa(min) + " characters long"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

// GetPolicyForOrg is a helper used by other handlers to load the policy for an org UUID.
func GetPolicyForOrg(c echo.Context, pool *pgxpool.Pool, orgID uuid.UUID) (*models.PasswordPolicy, error) {
	repo := repository.NewPasswordPolicyRepository(pool)
	return repo.Get(c.Request().Context(), orgID)
}
