package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// LoginFlowHandler serves the admin API for the no-code login flow builder.
type LoginFlowHandler struct {
	repo *repository.LoginFlowRepository
}

func NewLoginFlowHandler(pool *pgxpool.Pool) *LoginFlowHandler {
	return &LoginFlowHandler{repo: repository.NewLoginFlowRepository(pool)}
}

// ── Flows CRUD ────────────────────────────────────────────────────────────────

// GET /api/v1/organizations/:org_id/login-flows
func (h *LoginFlowHandler) List(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	flows, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if flows == nil {
		flows = []*models.LoginFlow{}
	}
	return c.JSON(http.StatusOK, flows)
}

// GET /api/v1/organizations/:org_id/login-flows/:flow_id
func (h *LoginFlowHandler) Get(c echo.Context) error {
	orgID, flowID, err := h.parseParams(c)
	if err != nil {
		return err
	}
	flow, err := h.repo.GetByID(c.Request().Context(), orgID, flowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "flow not found")
		}
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, flow)
}

type createFlowRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
	IsDefault   bool    `json:"is_default"`
}

// POST /api/v1/organizations/:org_id/login-flows
func (h *LoginFlowHandler) Create(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	var req createFlowRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	flow, err := h.repo.Create(c.Request().Context(), repository.CreateFlowParams{
		OrgID:       orgID,
		Name:        req.Name,
		Description: req.Description,
		IsDefault:   req.IsDefault,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, flow)
}

type updateFlowRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
	IsDefault   bool    `json:"is_default"`
	IsActive    bool    `json:"is_active"`
}

// PUT /api/v1/organizations/:org_id/login-flows/:flow_id
func (h *LoginFlowHandler) Update(c echo.Context) error {
	orgID, flowID, err := h.parseParams(c)
	if err != nil {
		return err
	}
	var req updateFlowRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	flow, err := h.repo.Update(c.Request().Context(), repository.UpdateFlowParams{
		ID:          flowID,
		OrgID:       orgID,
		Name:        req.Name,
		Description: req.Description,
		IsDefault:   req.IsDefault,
		IsActive:    req.IsActive,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "flow not found")
		}
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, flow)
}

// DELETE /api/v1/organizations/:org_id/login-flows/:flow_id
func (h *LoginFlowHandler) Delete(c echo.Context) error {
	orgID, flowID, err := h.parseParams(c)
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.Request().Context(), orgID, flowID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Steps ─────────────────────────────────────────────────────────────────────

type stepInput struct {
	StepType string          `json:"step_type"`
	Position int             `json:"position"`
	Config   json.RawMessage `json:"config"`
	IsActive *bool           `json:"is_active"`
}

// PUT /api/v1/organizations/:org_id/login-flows/:flow_id/steps
// Replaces the full step list atomically (drag-drop reorder = PUT the new order).
func (h *LoginFlowHandler) ReplaceSteps(c echo.Context) error {
	orgID, flowID, err := h.parseParams(c)
	if err != nil {
		return err
	}
	var req []stepInput
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	validTypes := map[string]bool{
		"check_attribute": true, "require_mfa": true, "block_if_no_mfa": true,
		"enrich_claims": true, "set_claim": true, "webhook": true,
		"check_ip_risk": true, "require_email_verified": true,
	}
	steps := make([]repository.StepInput, 0, len(req))
	for i, s := range req {
		if !validTypes[s.StepType] {
			return echo.NewHTTPError(http.StatusBadRequest, "unknown step_type: "+s.StepType)
		}
		isActive := true
		if s.IsActive != nil {
			isActive = *s.IsActive
		}
		cfg := s.Config
		if len(cfg) == 0 {
			cfg = json.RawMessage("{}")
		}
		steps = append(steps, repository.StepInput{
			StepType: s.StepType,
			Position: i, // honour submitted order; client sets position
			Config:   cfg,
			IsActive: isActive,
		})
	}

	out, err := h.repo.ReplaceSteps(c.Request().Context(), repository.UpsertStepsParams{
		FlowID: flowID,
		OrgID:  orgID,
		Steps:  steps,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, out)
}

// ── Client assignments ────────────────────────────────────────────────────────

// POST /api/v1/organizations/:org_id/login-flows/:flow_id/clients
func (h *LoginFlowHandler) AssignClient(c echo.Context) error {
	orgID, flowID, err := h.parseParams(c)
	if err != nil {
		return err
	}
	var req struct {
		ClientID string `json:"client_id"`
	}
	if err := c.Bind(&req); err != nil || req.ClientID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "client_id is required")
	}
	if err := h.repo.AssignClient(c.Request().Context(), orgID, flowID, req.ClientID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// DELETE /api/v1/organizations/:org_id/login-flows/:flow_id/clients/:client_id
func (h *LoginFlowHandler) UnassignClient(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	clientID := c.Param("client_id")
	if err := h.repo.UnassignClient(c.Request().Context(), orgID, clientID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// GET /api/v1/organizations/:org_id/login-flows/:flow_id/clients
func (h *LoginFlowHandler) ListClients(c echo.Context) error {
	orgID, flowID, err := h.parseParams(c)
	if err != nil {
		return err
	}
	ids, err := h.repo.ListClientAssignments(c.Request().Context(), orgID, flowID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if ids == nil {
		ids = []string{}
	}
	return c.JSON(http.StatusOK, ids)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *LoginFlowHandler) parseParams(c echo.Context) (uuid.UUID, uuid.UUID, error) {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	flowID, err := uuid.Parse(c.Param("flow_id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "invalid flow_id")
	}
	return orgID, flowID, nil
}
