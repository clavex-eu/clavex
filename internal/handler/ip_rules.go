package handler

// IPRulesHandler exposes CRUD endpoints for per-org IP allow/deny rules.
//
//	GET    /:org_id/ip-rules          — list all rules
//	POST   /:org_id/ip-rules          — create a rule
//	DELETE /:org_id/ip-rules/:rule_id — delete a rule

import (
	"errors"
	"net"
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// IPRulesHandler handles IP rule management.
type IPRulesHandler struct {
	rules *repository.IPRulesRepository
}

// NewIPRulesHandler creates an IPRulesHandler.
func NewIPRulesHandler(rules *repository.IPRulesRepository) *IPRulesHandler {
	return &IPRulesHandler{rules: rules}
}

// List returns all IP rules for an org.
//
//	GET /:org_id/ip-rules
func (h *IPRulesHandler) List(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	rules, err := h.rules.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list IP rules")
	}
	return c.JSON(http.StatusOK, rules)
}

// Create adds a new IP rule.
//
//	POST /:org_id/ip-rules
//	Body: {"type":"allow"|"deny","cidr":"10.0.0.0/8","notes":"..."}
func (h *IPRulesHandler) Create(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	var body struct {
		Type  string `json:"type"`
		CIDR  string `json:"cidr"`
		Notes string `json:"notes"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if body.Type != "allow" && body.Type != "deny" {
		return echo.NewHTTPError(http.StatusBadRequest, "type must be 'allow' or 'deny'")
	}
	if body.CIDR == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "cidr is required")
	}
	if _, _, err := net.ParseCIDR(body.CIDR); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid CIDR notation")
	}

	rule, err := h.rules.Add(c.Request().Context(), orgID, body.Type, body.CIDR, body.Notes, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create IP rule")
	}
	return c.JSON(http.StatusCreated, rule)
}

// Delete removes an IP rule by ID.
//
//	DELETE /:org_id/ip-rules/:rule_id
func (h *IPRulesHandler) Delete(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	ruleID, err := uuid.Parse(c.Param("rule_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid rule_id")
	}
	if err := h.rules.Delete(c.Request().Context(), orgID, ruleID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "rule not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete IP rule")
	}
	return c.NoContent(http.StatusNoContent)
}
