package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// AdminAPIKeyHandler manages machine-to-machine API keys for the superadmin API.
type AdminAPIKeyHandler struct {
	repo *repository.AdminAPIKeyRepository
}

func NewAdminAPIKeyHandler(pool *pgxpool.Pool) *AdminAPIKeyHandler {
	return &AdminAPIKeyHandler{repo: repository.NewAdminAPIKeyRepository(pool)}
}

type createAPIKeyRequest struct {
	Name        string   `json:"name"       validate:"required,min=1,max=120"`
	Scope       string   `json:"scope"      validate:"omitempty,oneof=read-only read-write provision-only"`
	OrgID       *string  `json:"org_id,omitempty"`      // optional; scopes the key to a single org (UUID)
	Permissions []string `json:"permissions,omitempty"` // optional fine-grained restriction, e.g. "clients:write"
	ExpiresAt   *string  `json:"expires_at"`             // optional ISO-8601 timestamp
}

type createAPIKeyResponse struct {
	Key  string      `json:"key"` // raw key — shown once
	Meta interface{} `json:"meta"`
}

// POST /api/v1/superadmin/api-keys
func (h *AdminAPIKeyHandler) Create(c echo.Context) error {
	var req createAPIKeyRequest
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}
	if req.Scope == "" {
		req.Scope = "read-write"
	}

	var orgID *uuid.UUID
	if req.OrgID != nil && *req.OrgID != "" {
		id, err := uuid.Parse(*req.OrgID)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
		}
		orgID = &id
	}

	// Best-effort: record who created the key.
	var createdBy *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, err := uuid.Parse(claims.Subject); err == nil {
			createdBy = &id
		}
	}

	k, rawKey, err := h.repo.Create(c.Request().Context(), req.Name, req.Scope, orgID, req.Permissions, createdBy, req.ExpiresAt)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, createAPIKeyResponse{Key: rawKey, Meta: k})
}

// GET /api/v1/superadmin/api-keys
// Optional ?org_id= filters to keys scoped to that org; omitted returns all
// keys (superadmin- and org-scoped alike).
func (h *AdminAPIKeyHandler) List(c echo.Context) error {
	var orgID *uuid.UUID
	if raw := c.QueryParam("org_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
		}
		orgID = &id
	}
	keys, err := h.repo.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, keys)
}

// DELETE /api/v1/superadmin/api-keys/:id
func (h *AdminAPIKeyHandler) Revoke(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	if err := h.repo.Revoke(c.Request().Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrNotFound
		}
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Org-scoped self-service keys ──────────────────────────────────────────────
//
// These endpoints let an org admin mint API keys for their *own* org without
// superadmin involvement. Two invariants distinguish them from the superadmin
// route above and are enforced server-side (never trusting the client):
//
//  1. The org is taken from the :org_id path param (already pinned to the
//     caller's org by RequireOrgAccess); the request body carries no org_id, so
//     there is no way to mint a key for another org. Unrestricted (org_id NULL,
//     cross-org) keys remain exclusively a superadmin operation.
//  2. Non-escalation: an explicit, non-empty permissions array is required and
//     every token must be one the caller already holds. Unrestricted-within-scope
//     keys (permissions omitted) are too broad for self-service and stay
//     superadmin-only.

type createOrgAPIKeyRequest struct {
	Name        string   `json:"name"`
	Scope       string   `json:"scope"`
	Permissions []string `json:"permissions"`
	ExpiresAt   *string  `json:"expires_at"`
}

// POST /api/v1/organizations/:org_id/api-keys
func (h *AdminAPIKeyHandler) CreateOrgScoped(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	claims := middleware.GetClaims(c)
	if claims == nil {
		return echo.ErrUnauthorized
	}

	var req createOrgAPIKeyRequest
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}
	if strings.TrimSpace(req.Name) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	if req.Scope == "" {
		req.Scope = "read-write"
	}
	switch req.Scope {
	case "read-only", "read-write", "provision-only":
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "invalid scope")
	}

	// Self-service keys must carry an explicit, non-empty permission set;
	// unrestricted-within-scope keys remain superadmin-only.
	if len(req.Permissions) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest,
			"permissions must be a non-empty array; unrestricted keys are superadmin-only")
	}
	if err := validatePermissions(req.Permissions); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	// Non-escalation: reject any permission the caller does not itself hold.
	if missing := middleware.PermissionsNotHeld(claims, req.Permissions); len(missing) > 0 {
		return echo.NewHTTPError(http.StatusForbidden,
			"cannot grant permissions you do not hold: "+strings.Join(missing, ", "))
	}

	var createdBy *uuid.UUID
	if id, err := uuid.Parse(claims.Subject); err == nil {
		createdBy = &id
	}

	k, rawKey, err := h.repo.Create(c.Request().Context(), req.Name, req.Scope, &orgID, req.Permissions, createdBy, req.ExpiresAt)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, createAPIKeyResponse{Key: rawKey, Meta: k})
}

// GET /api/v1/organizations/:org_id/api-keys
// Returns only keys scoped to this org (superadmin cross-org keys are excluded).
func (h *AdminAPIKeyHandler) ListOrgScoped(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	keys, err := h.repo.List(c.Request().Context(), &orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if keys == nil {
		keys = []*models.AdminAPIKey{}
	}
	return c.JSON(http.StatusOK, keys)
}

// DELETE /api/v1/organizations/:org_id/api-keys/:id
func (h *AdminAPIKeyHandler) RevokeOrgScoped(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	if err := h.repo.RevokeForOrg(c.Request().Context(), id, orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrNotFound
		}
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
