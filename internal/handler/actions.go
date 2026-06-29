package handler

import (
	"encoding/json"
	"net/http"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ActionsHandler serves the Actions V2 admin API.
//
// Actions V2 lets operators bind external HTTP endpoints (targets) to Clavex
// internal events (executions). For synchronous events (user.pre_login,
// user.pre_token) the response can deny login or inject claims. For
// asynchronous events (user.created, user.updated, user.deleted) the call
// is fire-and-forget.
//
// Routes (under /api/v1/organizations/:org_id/actions):
//
//	GET    /targets
//	PUT    /targets/:name
//	DELETE /targets/:target_id
//	GET    /executions
//	POST   /executions
//	PUT    /executions/:execution_id
//	DELETE /executions/:execution_id
type ActionsHandler struct {
	repo *repository.ActionsRepository
}

func NewActionsHandler(pool *pgxpool.Pool) *ActionsHandler {
	return &ActionsHandler{repo: repository.NewActionsRepository(pool)}
}

// ── Targets ───────────────────────────────────────────────────────────────────

func (h *ActionsHandler) ListTargets(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	targets, err := h.repo.ListTargets(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if targets == nil {
		targets = []*models.ActionTarget{}
	}
	return c.JSON(http.StatusOK, targets)
}

type upsertTargetRequest struct {
	TargetType    string  `json:"target_type"`
	URL           string  `json:"url"`
	SandboxCode   *string `json:"sandbox_code"`
	TimeoutMs     int     `json:"timeout_ms"`
	SigningSecret *string `json:"signing_secret"`
	IsActive      *bool   `json:"is_active"`
}

// PUT /actions/targets/:name  — idempotent create-or-update by name.
func (h *ActionsHandler) UpsertTarget(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	name := c.Param("name")
	if name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	var req upsertTargetRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	targetType := req.TargetType
	if targetType == "" {
		targetType = "http"
	}
	if targetType != "http" && targetType != "sandbox" {
		return echo.NewHTTPError(http.StatusBadRequest, "target_type must be 'http' or 'sandbox'")
	}
	if targetType == "http" && req.URL == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "url is required for http targets")
	}
	if targetType == "sandbox" && (req.SandboxCode == nil || *req.SandboxCode == "") {
		return echo.NewHTTPError(http.StatusBadRequest, "sandbox_code is required for sandbox targets")
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	timeout := req.TimeoutMs
	if timeout <= 0 {
		timeout = 3000
	}
	target, err := h.repo.UpsertTarget(c.Request().Context(), repository.UpsertTargetParams{
		OrgID:         orgID,
		Name:          name,
		TargetType:    targetType,
		URL:           req.URL,
		SandboxCode:   req.SandboxCode,
		TimeoutMs:     timeout,
		SigningSecret: req.SigningSecret,
		IsActive:      isActive,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, target)
}

func (h *ActionsHandler) DeleteTarget(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	targetID, err := uuidParam(c, "target_id")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteTarget(c.Request().Context(), orgID, targetID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Executions ────────────────────────────────────────────────────────────────

func (h *ActionsHandler) ListExecutions(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	execs, err := h.repo.ListExecutions(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if execs == nil {
		execs = []*models.ActionExecution{}
	}
	return c.JSON(http.StatusOK, execs)
}

type createExecutionRequest struct {
	TargetID  string          `json:"target_id"`
	Name      string          `json:"name"`
	EventType string          `json:"event_type"`
	Condition json.RawMessage `json:"condition"`
	// Mode: "fire_and_forget" (default) or "mutation".
	// mutation mode POSTs the request body to the target and uses the
	// (possibly modified) response as the actual data to process.
	Mode     string `json:"mode"`
	IsActive *bool  `json:"is_active"`
}

func (h *ActionsHandler) CreateExecution(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createExecutionRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	if !validActionEventType(req.EventType) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid event_type")
	}
	targetID, err := uuid.Parse(req.TargetID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid target_id")
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	ex, err := h.repo.CreateExecution(c.Request().Context(), repository.UpsertExecutionParams{
		OrgID:     orgID,
		TargetID:  targetID,
		Name:      req.Name,
		EventType: req.EventType,
		Condition: req.Condition,
		Mode:      req.Mode,
		IsActive:  isActive,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, ex)
}

func (h *ActionsHandler) UpdateExecution(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	execID, err := uuidParam(c, "execution_id")
	if err != nil {
		return err
	}
	var req createExecutionRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	if !validActionEventType(req.EventType) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid event_type")
	}
	targetID, err := uuid.Parse(req.TargetID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid target_id")
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	ex, err := h.repo.UpdateExecution(c.Request().Context(), orgID, execID, repository.UpsertExecutionParams{
		OrgID:     orgID,
		TargetID:  targetID,
		Name:      req.Name,
		EventType: req.EventType,
		Condition: req.Condition,
		Mode:      req.Mode,
		IsActive:  isActive,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "execution not found")
	}
	return c.JSON(http.StatusOK, ex)
}

func (h *ActionsHandler) DeleteExecution(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	execID, err := uuidParam(c, "execution_id")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteExecution(c.Request().Context(), orgID, execID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

var validActionEventTypes = map[string]bool{
	// Existing synchronous events.
	"user.pre_login":  true,
	"user.pre_token":  true,
	// Existing asynchronous events.
	"user.created": true,
	"user.updated": true,
	"user.deleted": true,
	// Mutation mode events (user.pre_* with mode=mutation).
	// These are fired synchronously before the operation; the target's response
	// can modify or deny the request.
	"user.pre_create":          true,
	"user.pre_update":          true,
	"user.pre_password_change": true,
}

func validActionEventType(t string) bool {
	return validActionEventTypes[t]
}
