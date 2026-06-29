package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/connectorregistry"
	"github.com/labstack/echo/v4"
)

// ConnectorCatalogHandler serves the connector marketplace catalog.
type ConnectorCatalogHandler struct{}

// NewConnectorCatalogHandler creates a ConnectorCatalogHandler.
func NewConnectorCatalogHandler() *ConnectorCatalogHandler {
	return &ConnectorCatalogHandler{}
}

// catalogResponse is the top-level response for GET /connector-catalog.
type catalogResponse struct {
	Social []*connectorregistry.SocialDef      `json:"social"`
	SMS    []*connectorregistry.SMSConnectorDef `json:"sms"`
	Email  []*connectorregistry.EmailConnectorDef `json:"email"`
}

// List returns the full connector catalog across all categories.
// An optional ?category=social|sms|email query parameter narrows the response.
//
// GET /api/v1/organizations/:org_id/connector-catalog
func (h *ConnectorCatalogHandler) List(c echo.Context) error {
	category := c.QueryParam("category")

	switch category {
	case "social":
		return c.JSON(http.StatusOK, connectorregistry.ListSocial())
	case "sms":
		return c.JSON(http.StatusOK, connectorregistry.ListSMS())
	case "email":
		return c.JSON(http.StatusOK, connectorregistry.ListEmail())
	default:
		return c.JSON(http.StatusOK, catalogResponse{
			Social: connectorregistry.ListSocial(),
			SMS:    connectorregistry.ListSMS(),
			Email:  connectorregistry.ListEmail(),
		})
	}
}
