package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// MapperHandler exposes CRUD endpoints for protocol mappers.
type MapperHandler struct {
	repo    *repository.MapperRepository
	clients *repository.ClientRepository
}

func NewMapperHandler(pool *pgxpool.Pool) *MapperHandler {
	return &MapperHandler{
		repo:    repository.NewMapperRepository(pool),
		clients: repository.NewClientRepository(pool),
	}
}

type createMapperRequest struct {
	Name             string  `json:"name"                validate:"required,min=1,max=128"`
	MapperType       string  `json:"mapper_type"         validate:"required,oneof=user_property user_attribute hardcoded role_list group_membership"`
	ClaimName        string  `json:"claim_name"          validate:"required,min=1,max=128"`
	ClaimValue       *string `json:"claim_value"`
	AttributeName    *string `json:"attribute_name"`
	AddToAccessToken bool    `json:"add_to_access_token"`
	AddToIDToken     bool    `json:"add_to_id_token"`
	AddToUserinfo    bool    `json:"add_to_userinfo"`
}

// Create adds a protocol mapper to a client.
// POST /api/v1/organizations/:org_id/clients/:client_id/mappers
func (h *MapperHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	clientID := c.Param("client_id")
	if clientID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "client_id is required")
	}
	// Verify client belongs to org
	client, err := h.clients.GetByClientID(c.Request().Context(), clientID)
	if err != nil || client.OrgID != orgID {
		return echo.ErrNotFound
	}

	var req createMapperRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	m := &models.ProtocolMapper{
		OrgID:            orgID,
		ClientID:         clientID,
		Name:             req.Name,
		MapperType:       req.MapperType,
		ClaimName:        req.ClaimName,
		ClaimValue:       req.ClaimValue,
		AttributeName:    req.AttributeName,
		AddToAccessToken: req.AddToAccessToken,
		AddToIDToken:     req.AddToIDToken,
		AddToUserinfo:    req.AddToUserinfo,
	}
	created, err := h.repo.Create(c.Request().Context(), m)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "mapper name already exists for this client")
	}
	return c.JSON(http.StatusCreated, created)
}

// List returns all mappers for a client.
// GET /api/v1/organizations/:org_id/clients/:client_id/mappers
func (h *MapperHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	clientID := c.Param("client_id")
	client, err := h.clients.GetByClientID(c.Request().Context(), clientID)
	if err != nil || client.OrgID != orgID {
		return echo.ErrNotFound
	}
	mappers, err := h.repo.ListByClient(c.Request().Context(), clientID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, mappers)
}

// Update replaces the mutable fields of a protocol mapper.
// PATCH /api/v1/organizations/:org_id/clients/:client_id/mappers/:id
type updateMapperRequest struct {
	Name             string  `json:"name"       validate:"required,min=1,max=128"`
	ClaimName        string  `json:"claim_name" validate:"required,min=1,max=128"`
	ClaimValue       *string `json:"claim_value"`
	AttributeName    *string `json:"attribute_name"`
	AddToAccessToken bool    `json:"add_to_access_token"`
	AddToIDToken     bool    `json:"add_to_id_token"`
	AddToUserinfo    bool    `json:"add_to_userinfo"`
}

func (h *MapperHandler) Update(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid mapper id")
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	var req updateMapperRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	updated, err := h.repo.Update(c.Request().Context(), id,
		req.Name, req.ClaimName, req.ClaimValue, req.AttributeName,
		req.AddToAccessToken, req.AddToIDToken, req.AddToUserinfo,
	)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, updated)
}

// Delete removes a protocol mapper.
// DELETE /api/v1/organizations/:org_id/clients/:client_id/mappers/:id
func (h *MapperHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid mapper id")
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	if err := h.repo.Delete(c.Request().Context(), id); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
