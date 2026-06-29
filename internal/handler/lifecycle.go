package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// LifecycleHandler serves the admin API for Joiner/Mover/Leaver lifecycle rules.
type LifecycleHandler struct {
	repo *repository.LifecycleRepository
}

func NewLifecycleHandler(pool *pgxpool.Pool) *LifecycleHandler {
	return &LifecycleHandler{repo: repository.NewLifecycleRepository(pool)}
}

// ── List ─────────────────────────────────────────────────────────────────────

// GET /api/v1/organizations/:org_id/lifecycle-rules
func (h *LifecycleHandler) List(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	rules, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if rules == nil {
		rules = []*models.LifecycleRule{}
	}
	return c.JSON(http.StatusOK, rules)
}

// ── Create ───────────────────────────────────────────────────────────────────

type lifecycleRuleRequest struct {
	Name        string                       `json:"name"`
	Description *string                      `json:"description"`
	Trigger     models.LifecycleTrigger      `json:"trigger"`
	Priority    int                          `json:"priority"`
	Conditions  []models.LifecycleCondition  `json:"conditions"`
	Actions     []models.LifecycleAction     `json:"actions"`
	IsActive    *bool                        `json:"is_active"`
}

// POST /api/v1/organizations/:org_id/lifecycle-rules
func (h *LifecycleHandler) Create(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	var req lifecycleRuleRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	if !validTrigger(req.Trigger) {
		return echo.NewHTTPError(http.StatusBadRequest, "trigger must be joiner, mover, or leaver")
	}
	if err := validateConditions(req.Conditions); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := validateActions(req.Actions); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	rule, err := h.repo.Create(c.Request().Context(), repository.CreateLifecycleRuleParams{
		OrgID:       orgID,
		Name:        req.Name,
		Description: req.Description,
		Trigger:     req.Trigger,
		Priority:    req.Priority,
		Conditions:  req.Conditions,
		Actions:     req.Actions,
		IsActive:    isActive,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, rule)
}

// ── Get ──────────────────────────────────────────────────────────────────────

// GET /api/v1/organizations/:org_id/lifecycle-rules/:rule_id
func (h *LifecycleHandler) Get(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	ruleID, err := uuid.Parse(c.Param("rule_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid rule_id")
	}
	rule, err := h.repo.GetByID(c.Request().Context(), orgID, ruleID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "rule not found")
	}
	return c.JSON(http.StatusOK, rule)
}

// ── Update ───────────────────────────────────────────────────────────────────

// PUT /api/v1/organizations/:org_id/lifecycle-rules/:rule_id
func (h *LifecycleHandler) Update(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	ruleID, err := uuid.Parse(c.Param("rule_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid rule_id")
	}
	var req lifecycleRuleRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	if !validTrigger(req.Trigger) {
		return echo.NewHTTPError(http.StatusBadRequest, "trigger must be joiner, mover, or leaver")
	}
	if err := validateConditions(req.Conditions); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := validateActions(req.Actions); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	rule, err := h.repo.Update(c.Request().Context(), repository.UpdateLifecycleRuleParams{
		OrgID:       orgID,
		ID:          ruleID,
		Name:        req.Name,
		Description: req.Description,
		Trigger:     req.Trigger,
		Priority:    req.Priority,
		Conditions:  req.Conditions,
		Actions:     req.Actions,
		IsActive:    isActive,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "rule not found")
	}
	return c.JSON(http.StatusOK, rule)
}

// ── Delete ───────────────────────────────────────────────────────────────────

// DELETE /api/v1/organizations/:org_id/lifecycle-rules/:rule_id
func (h *LifecycleHandler) Delete(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	ruleID, err := uuid.Parse(c.Param("rule_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid rule_id")
	}
	if err := h.repo.Delete(c.Request().Context(), orgID, ruleID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Validation helpers ────────────────────────────────────────────────────────

func validTrigger(t models.LifecycleTrigger) bool {
	return t == models.TriggerJoiner || t == models.TriggerMover || t == models.TriggerLeaver
}

func validateConditions(cs []models.LifecycleCondition) error {
	validOps := map[string]bool{
		"eq": true, "neq": true, "contains": true,
		"starts_with": true, "ends_with": true,
		"exists": true, "not_exists": true,
	}
	for _, c := range cs {
		if c.Field == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "condition field is required")
		}
		if !validOps[c.Op] {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid condition op: "+c.Op)
		}
	}
	return nil
}

func validateActions(as []models.LifecycleAction) error {
	validTypes := map[string]bool{
		"assign_role": true, "remove_role": true,
		"add_to_group": true, "remove_from_group": true,
		"revoke_sessions": true, "send_notification": true,
	}
	for _, a := range as {
		if !validTypes[a.Type] {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid action type: "+a.Type)
		}
		if (a.Type == "assign_role" || a.Type == "remove_role") && a.RoleName == "" {
			return echo.NewHTTPError(http.StatusBadRequest, a.Type+" requires role_name")
		}
		if (a.Type == "add_to_group" || a.Type == "remove_from_group") && a.GroupName == "" {
			return echo.NewHTTPError(http.StatusBadRequest, a.Type+" requires group_name")
		}
	}
	return nil
}
