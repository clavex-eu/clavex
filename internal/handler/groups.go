package handler

import (
	"net/http"
	"strconv"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// GroupHandler manages groups and their memberships/roles.
type GroupHandler struct {
	repo *repository.GroupRepository
}

func NewGroupHandler(pool *pgxpool.Pool) *GroupHandler {
	return &GroupHandler{repo: repository.NewGroupRepository(pool)}
}

// List returns all groups for an org.
func (h *GroupHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	p := models.PageParams{}
	if v := c.QueryParam("limit"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			p.Limit = n
		}
	}
	if v := c.QueryParam("after"); v != "" {
		if uid, e := uuid.Parse(v); e == nil {
			p.After = &uid
		} else {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid cursor")
		}
	}
	page, err := h.repo.ListByOrgPage(c.Request().Context(), orgID, p)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, page)
}

// Get returns a single group.
func (h *GroupHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	g, err := h.repo.GetForOrg(c.Request().Context(), id, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, g)
}

// requireGroupInOrg returns a 404 unless the group belongs to orgID. Every
// group-scoped sub-operation (members, roles) must call this first so a group
// id from another tenant cannot be operated on.
func (h *GroupHandler) requireGroupInOrg(c echo.Context, groupID, orgID uuid.UUID) error {
	if _, err := h.repo.GetForOrg(c.Request().Context(), groupID, orgID); err != nil {
		return echo.ErrNotFound
	}
	return nil
}

type createGroupRequest struct {
	Name        string `json:"name"        validate:"required"`
	Description string `json:"description"`
}

// Create creates a new group.
func (h *GroupHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createGroupRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	g, err := h.repo.Create(c.Request().Context(), orgID, req.Name, req.Description)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, g)
}

// Delete removes a group.
func (h *GroupHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.requireGroupInOrg(c, id, orgID); err != nil {
		return err
	}
	if err := h.repo.Delete(c.Request().Context(), id); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// ListMembers returns the users in a group.
func (h *GroupHandler) ListMembers(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.requireGroupInOrg(c, id, orgID); err != nil {
		return err
	}
	users, err := h.repo.ListMembers(c.Request().Context(), id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, users)
}

type memberRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
}

// AddMember adds a user to a group.
func (h *GroupHandler) AddMember(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	groupID, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.requireGroupInOrg(c, groupID, orgID); err != nil {
		return err
	}
	var req memberRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
	}
	// The member must belong to the same org, else a tenant admin could pull a
	// cross-org user into their group.
	if ok, err := h.repo.UserInOrg(c.Request().Context(), userID, orgID); err != nil || !ok {
		return echo.ErrNotFound
	}
	if err := h.repo.AddMember(c.Request().Context(), groupID, userID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// RemoveMember removes a user from a group.
func (h *GroupHandler) RemoveMember(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	groupID, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.requireGroupInOrg(c, groupID, orgID); err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}
	if err := h.repo.RemoveMember(c.Request().Context(), groupID, userID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ListRoles returns roles assigned to a group.
func (h *GroupHandler) ListRoles(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.requireGroupInOrg(c, id, orgID); err != nil {
		return err
	}
	roles, err := h.repo.ListRoles(c.Request().Context(), id)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, roles)
}

type roleRequest struct {
	RoleID string `json:"role_id" validate:"required,uuid"`
}

// AssignRole assigns a role to a group.
func (h *GroupHandler) AssignRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	groupID, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.requireGroupInOrg(c, groupID, orgID); err != nil {
		return err
	}
	var req roleRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid role_id")
	}
	// The role must belong to the same org, else assigning it would grant a
	// cross-org role to the group's members.
	if ok, err := h.repo.RoleInOrg(c.Request().Context(), roleID, orgID); err != nil || !ok {
		return echo.ErrNotFound
	}
	if err := h.repo.AssignRole(c.Request().Context(), groupID, roleID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// RemoveRole removes a role from a group.
func (h *GroupHandler) RemoveRole(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	groupID, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.requireGroupInOrg(c, groupID, orgID); err != nil {
		return err
	}
	roleID, err := uuidParam(c, "role_id")
	if err != nil {
		return err
	}
	if err := h.repo.RemoveRole(c.Request().Context(), groupID, roleID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
