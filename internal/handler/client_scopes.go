package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ClientScopeHandler manages reusable org-level client scopes.
type ClientScopeHandler struct {
	repo *repository.ClientScopeRepository
}

func NewClientScopeHandler(pool *pgxpool.Pool) *ClientScopeHandler {
	return &ClientScopeHandler{repo: repository.NewClientScopeRepository(pool)}
}

type createScopeRequest struct {
	Name        string  `json:"name"        validate:"required,min=1,max=80"`
	Description *string `json:"description"`
	Protocol    string  `json:"protocol"    validate:"omitempty"`
	IsDefault   bool    `json:"is_default"`
}

// Create — POST /api/v1/organizations/:org_id/client-scopes
func (h *ClientScopeHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createScopeRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.Protocol == "" {
		req.Protocol = "openid-connect"
	}
	scope, err := h.repo.Create(c.Request().Context(), orgID, req.Name, req.Description, req.Protocol, req.IsDefault)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "scope already exists")
	}
	return c.JSON(http.StatusCreated, scope)
}

// List — GET /api/v1/organizations/:org_id/client-scopes
func (h *ClientScopeHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	scopes, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	if scopes == nil {
		scopes = []*models.ClientScope{}
	}
	return c.JSON(http.StatusOK, scopes)
}

type updateScopeRequest struct {
	Name        string  `json:"name"        validate:"required,min=1,max=80"`
	Description *string `json:"description"`
	IsDefault   bool    `json:"is_default"`
}

// Update — PUT /api/v1/organizations/:org_id/client-scopes/:scope_id
func (h *ClientScopeHandler) Update(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "scope_id")
	if err != nil {
		return err
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	var req updateScopeRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	scope, err := h.repo.Update(c.Request().Context(), id, req.Name, req.Description, req.IsDefault)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, scope)
}

// Delete — DELETE /api/v1/organizations/:org_id/client-scopes/:scope_id
func (h *ClientScopeHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "scope_id")
	if err != nil {
		return err
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	if err := h.repo.Delete(c.Request().Context(), id); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// ListByClient — GET /api/v1/organizations/:org_id/clients/:client_id/scopes
func (h *ClientScopeHandler) ListByClient(c echo.Context) error {
	clientID := c.Param("client_id")
	if clientID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing client_id")
	}
	scopes, err := h.repo.ListByClient(c.Request().Context(), clientID)
	if err != nil {
		return err
	}
	if scopes == nil {
		scopes = []*models.ClientScope{}
	}
	return c.JSON(http.StatusOK, scopes)
}

// AssignToClient — PUT /api/v1/organizations/:org_id/clients/:client_id/scopes/:scope_id
func (h *ClientScopeHandler) AssignToClient(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	clientID := c.Param("client_id")
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid scope_id")
	}
	if err := h.assertClientAndScopeInOrg(c, clientID, scopeID, orgID); err != nil {
		return err
	}
	if err := h.repo.AssignToClient(c.Request().Context(), clientID, scopeID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// UnassignFromClient — DELETE /api/v1/organizations/:org_id/clients/:client_id/scopes/:scope_id
func (h *ClientScopeHandler) UnassignFromClient(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	clientID := c.Param("client_id")
	scopeID, err := uuid.Parse(c.Param("scope_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid scope_id")
	}
	if err := h.assertClientAndScopeInOrg(c, clientID, scopeID, orgID); err != nil {
		return err
	}
	if err := h.repo.UnassignFromClient(c.Request().Context(), clientID, scopeID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// assertClientAndScopeInOrg rejects (404) unless both the client and the scope
// belong to orgID — prevents cross-tenant scope/client assignment by id.
func (h *ClientScopeHandler) assertClientAndScopeInOrg(c echo.Context, clientID string, scopeID, orgID uuid.UUID) error {
	ctx := c.Request().Context()
	if ok, err := h.repo.ClientInOrg(ctx, clientID, orgID); err != nil || !ok {
		return echo.ErrNotFound
	}
	if _, err := h.repo.GetForOrg(ctx, scopeID, orgID); err != nil {
		return echo.ErrNotFound
	}
	return nil
}
