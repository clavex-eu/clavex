package handler

import (
	"errors"
	"net/http"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// AdminDelegationHandler manages delegated admin roles and their user assignments.
type AdminDelegationHandler struct {
	repo *repository.AdminRoleRepository
}

// NewAdminDelegationHandler creates a new AdminDelegationHandler.
func NewAdminDelegationHandler(pool *pgxpool.Pool) *AdminDelegationHandler {
	return &AdminDelegationHandler{repo: repository.NewAdminRoleRepository(pool)}
}

// ── Admin role CRUD ───────────────────────────────────────────────────────────

type createAdminRoleRequest struct {
	Name        string   `json:"name"        validate:"required,min=1,max=120"`
	Description string   `json:"description" validate:"max=512"`
	Permissions []string `json:"permissions" validate:"required"`
}

// Create registers a new delegated admin role for an org.
// POST /api/v1/organizations/:org_id/admin-roles
func (h *AdminDelegationHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createAdminRoleRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	// Validate permission tokens against the canonical list.
	if err := validatePermissions(req.Permissions); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	var desc *string
	if req.Description != "" {
		desc = &req.Description
	}
	role, err := h.repo.Create(c.Request().Context(), orgID, req.Name, desc, req.Permissions)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "an admin role with this name already exists")
	}
	return c.JSON(http.StatusCreated, role)
}

// List returns all delegated admin roles for an org.
// GET /api/v1/organizations/:org_id/admin-roles
func (h *AdminDelegationHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	roles, err := h.repo.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if roles == nil {
		roles = []*models.AdminRole{}
	}
	return c.JSON(http.StatusOK, roles)
}

// Get returns a single delegated admin role.
// GET /api/v1/organizations/:org_id/admin-roles/:role_id
func (h *AdminDelegationHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid role_id")
	}
	role, err := h.repo.GetByID(c.Request().Context(), orgID, roleID)
	if err != nil || role == nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, role)
}

type updateAdminRoleRequest struct {
	Name        string   `json:"name"        validate:"required,min=1,max=120"`
	Description string   `json:"description" validate:"max=512"`
	Permissions []string `json:"permissions" validate:"required"`
}

// Update patches name, description, and permissions of a delegated admin role.
// System roles may have permissions updated but their name is immutable.
// PATCH /api/v1/organizations/:org_id/admin-roles/:role_id
func (h *AdminDelegationHandler) Update(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid role_id")
	}
	var req updateAdminRoleRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if err := validatePermissions(req.Permissions); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	var desc *string
	if req.Description != "" {
		desc = &req.Description
	}
	updated, err := h.repo.Update(c.Request().Context(), orgID, roleID, req.Name, desc, req.Permissions)
	if err != nil || updated == nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, updated)
}

// Delete removes a delegated admin role. System roles cannot be deleted.
// DELETE /api/v1/organizations/:org_id/admin-roles/:role_id
func (h *AdminDelegationHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid role_id")
	}
	if err := h.repo.Delete(c.Request().Context(), orgID, roleID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "role not found or is a system role")
		}
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// EnsureSystemRoles idempotently creates the built-in system roles for an org.
// POST /api/v1/organizations/:org_id/admin-roles/system/ensure
func (h *AdminDelegationHandler) EnsureSystemRoles(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	if err := h.repo.EnsureSystemRoles(c.Request().Context(), orgID); err != nil {
		return echo.ErrInternalServerError
	}
	roles, _ := h.repo.List(c.Request().Context(), orgID)
	return c.JSON(http.StatusOK, roles)
}

// ── User assignment endpoints ─────────────────────────────────────────────────

// ListUserRoles returns all admin role assignments for a user.
// GET /api/v1/organizations/:org_id/users/:user_id/admin-roles
func (h *AdminDelegationHandler) ListUserRoles(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}
	assignments, err := h.repo.ListByUser(c.Request().Context(), orgID, userID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if assignments == nil {
		assignments = []*models.AdminRoleAssignment{}
	}
	return c.JSON(http.StatusOK, assignments)
}

// AssignUserRole grants an admin role to a user.
// PUT /api/v1/organizations/:org_id/users/:user_id/admin-roles/:role_id
func (h *AdminDelegationHandler) AssignUserRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}
	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid role_id")
	}
	// Record who created the assignment.
	var createdBy *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, parseErr := uuid.Parse(claims.Subject); parseErr == nil {
			createdBy = &id
		}
	}
	if err := h.repo.Assign(c.Request().Context(), orgID, userID, roleID, createdBy); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// UnassignUserRole removes an admin role from a user.
// DELETE /api/v1/organizations/:org_id/users/:user_id/admin-roles/:role_id
func (h *AdminDelegationHandler) UnassignUserRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}
	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid role_id")
	}
	if err := h.repo.Unassign(c.Request().Context(), orgID, userID, roleID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrNotFound
		}
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Permission catalogue ──────────────────────────────────────────────────────

// ListPermissions returns every known permission token with human-readable descriptions.
// GET /api/v1/admin-roles/permissions
func (h *AdminDelegationHandler) ListPermissions(c echo.Context) error {
	return c.JSON(http.StatusOK, middleware.AllPermissions)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// validatePermissions checks that every token in perms exists in the canonical list.
// Returns a non-nil error message string on failure, nil on success.
func validatePermissions(perms []string) error {
	known := make(map[string]struct{}, len(middleware.AllPermissions))
	for _, p := range middleware.AllPermissions {
		known[p.Token] = struct{}{}
	}
	for _, p := range perms {
		if _, ok := known[p]; !ok {
			return &echo.HTTPError{Code: http.StatusBadRequest, Message: "unknown permission token: " + p}
		}
	}
	return nil
}
