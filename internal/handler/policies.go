package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/policy"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// PolicyHandler exposes CRUD for per-org auth-flow policy rules and the
// dry-run simulate endpoint.
type PolicyHandler struct {
	repo         *policy.Repository
	history      *repository.LoginHistoryRepository
	users        *repository.UserRepository
	mfa          *repository.MFARepository
	defaultRules []policy.Rule // loaded from config YAML
	auditor      *audit.Emitter
}

func NewPolicyHandler(pool *pgxpool.Pool, defaults []policy.Rule) *PolicyHandler {
	return &PolicyHandler{
		repo:         policy.NewRepository(pool),
		history:      repository.NewLoginHistoryRepository(pool),
		users:        repository.NewUserRepository(pool),
		mfa:          repository.NewMFARepository(pool),
		defaultRules: defaults,
	}
}

// WithAuditor attaches the audit emitter so auth-policy mutations reach the
// audit log and the live event stream (consumed by the Kubernetes operator).
func (h *PolicyHandler) WithAuditor(a *audit.Emitter) *PolicyHandler {
	h.auditor = a
	return h
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

// List returns all policy rules for an org.
// GET /api/v1/organizations/:org_id/auth-policies
// reflectPolicyManagedMarker mirrors an applied marker onto a PolicyRow so the
// JSON response matches the persisted state without a re-read. PolicyRow does
// not embed models.ManagedMarker, so it gets its own tiny reflector.
func reflectPolicyManagedMarker(row *policy.PolicyRow, m repository.ManagedMarkerInput) {
	switch {
	case m.Release:
		row.ManagedBy = nil
		row.ManagedRef = nil
	case m.By != "":
		by := m.By
		row.ManagedBy = &by
		if ref := m.Ref; ref != "" {
			row.ManagedRef = &ref
		} else {
			row.ManagedRef = nil
		}
	}
}

func (h *PolicyHandler) List(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	rows, err := h.repo.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, rows)
}

type createPolicyRequest struct {
	Name       string            `json:"name"`
	Priority   int               `json:"priority"`
	Action     policy.Action     `json:"action"`
	Conditions policy.Conditions `json:"conditions"`
}

// Create adds a new policy rule.
// POST /api/v1/organizations/:org_id/auth-policies
func (h *PolicyHandler) Create(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	var req createPolicyRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	if !validAction(req.Action) {
		return echo.NewHTTPError(http.StatusBadRequest, "action must be one of: allow, deny, require_mfa, step_up")
	}
	if req.Priority == 0 {
		req.Priority = 100
	}
	row, err := h.repo.Create(c.Request().Context(), orgID, req.Name, req.Priority, req.Action, req.Conditions)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if mk := managedMarkerFromRequest(c); mk.By != "" {
		if err := h.repo.SetManagedMarker(c.Request().Context(), row.ID, orgID, mk); err != nil {
			return echo.ErrInternalServerError
		}
		reflectPolicyManagedMarker(row, mk)
	}
	emitEntityAudit(c, h.auditor, orgID, "auth_policy.created", auditResourceAuthPolicy, req.Name, nil)
	return c.JSON(http.StatusCreated, row)
}

type updatePolicyRuleRequest struct {
	Name       string            `json:"name"`
	Priority   int               `json:"priority"`
	Enabled    *bool             `json:"enabled"`
	Action     policy.Action     `json:"action"`
	Conditions policy.Conditions `json:"conditions"`
}

// Update modifies an existing policy rule.
// PUT /api/v1/organizations/:org_id/auth-policies/:rule_id
func (h *PolicyHandler) Update(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	ruleID, err := uuid.Parse(c.Param("rule_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	var req updatePolicyRuleRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if !validAction(req.Action) {
		return echo.NewHTTPError(http.StatusBadRequest, "action must be one of: allow, deny, require_mfa, step_up")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	row, err := h.repo.Update(c.Request().Context(), ruleID, orgID, req.Name, req.Priority, enabled, req.Action, req.Conditions)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrNotFound
		}
		return echo.ErrInternalServerError
	}
	if mk := managedMarkerFromRequest(c); mk.Active() {
		if err := h.repo.SetManagedMarker(c.Request().Context(), row.ID, orgID, mk); err != nil {
			return echo.ErrInternalServerError
		}
		reflectPolicyManagedMarker(row, mk)
	}
	emitEntityAudit(c, h.auditor, orgID, "auth_policy.updated", auditResourceAuthPolicy, req.Name, nil)
	return c.JSON(http.StatusOK, row)
}

// Delete removes a policy rule.
// DELETE /api/v1/organizations/:org_id/auth-policies/:rule_id
func (h *PolicyHandler) Delete(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	ruleID, err := uuid.Parse(c.Param("rule_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	if err := h.repo.Delete(c.Request().Context(), ruleID, orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrNotFound
		}
		return echo.ErrInternalServerError
	}
	emitEntityAudit(c, h.auditor, orgID, "auth_policy.deleted", auditResourceAuthPolicy, ruleID.String(), nil)
	return c.NoContent(http.StatusNoContent)
}

// ── Dry-run simulate ──────────────────────────────────────────────────────────

// SimulateRequest is the body for the dry-run simulate endpoint.
type SimulateRequest struct {
	// User to simulate (optional; when omitted only IP/country/client conditions fire).
	UserID string `json:"user_id"`
	// OIDC client_id being used in the flow.
	ClientID string `json:"client_id"`
	// IP address of the simulated request.
	IPAddress string `json:"ip_address"`
	// Country override (ISO 3166-1 alpha-2).
	// When empty and IPAddress is provided, geo-IP is used.
	Country string `json:"country"`
	// User-agent string.
	UserAgent string `json:"user_agent"`
	// Simulated request time (ISO 8601). Defaults to now.
	RequestTime string `json:"request_time"`
}

// SimulateResponse describes what the policy engine would decide for the given
// input, plus the full trace of all rule evaluations.
type SimulateResponse struct {
	Outcome     policy.Outcome      `json:"outcome"`
	MFARequired bool                `json:"mfa_required"` // true if org/user or policy forces MFA
	Trace       []SimulateTraceItem `json:"trace"`
	Input       policy.EvalInput    `json:"input"`
	EvaluatedAt time.Time           `json:"evaluated_at"`
}

// SimulateTraceItem describes one rule and whether it matched.
type SimulateTraceItem struct {
	RuleName string        `json:"rule_name"`
	Priority int           `json:"priority"`
	Enabled  bool          `json:"enabled"`
	Matched  bool          `json:"matched"`
	Action   policy.Action `json:"action"`
}

// Simulate performs a policy dry-run.
// POST /api/v1/organizations/:org_id/auth-policies/simulate
// POST /:org_slug/authorize/simulate
func (h *PolicyHandler) Simulate(c echo.Context) error {
	ctx := c.Request().Context()

	orgIDStr := c.Param("org_id")
	if orgIDStr == "" {
		return echo.ErrBadRequest
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return echo.ErrBadRequest
	}

	var req SimulateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if req.IPAddress == "" {
		req.IPAddress = c.RealIP()
	}

	// Parse optional request time.
	reqTime := time.Now().UTC()
	if req.RequestTime != "" {
		if t, err := time.Parse(time.RFC3339, req.RequestTime); err == nil {
			reqTime = t.UTC()
		}
	}

	// Build EvalInput.
	in := policy.EvalInput{
		IPAddress:   req.IPAddress,
		Country:     req.Country,
		UserAgent:   req.UserAgent,
		ClientID:    req.ClientID,
		RequestTime: reqTime,
	}

	// Populate user-specific signals if a user_id was supplied.
	mfaRequired := false
	if req.UserID != "" {
		userID, err := uuid.Parse(req.UserID)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
		}
		in.UserID = req.UserID

		user, err := h.users.GetByID(ctx, userID)
		if err == nil {
			in.LastLoginAt = user.LastLoginAt
			mfaRequired = user.MFARequired
		}

		if count, err := h.mfa.CountConfirmedByUser(ctx, userID); err == nil {
			in.MFAEnrolled = count > 0
		}

		signals, err := h.history.GetAnomalySignals(ctx, userID, req.IPAddress, req.Country)
		if err == nil {
			in.NewCountry = signals.NewCountry
		}
	}

	p, err := h.repo.LoadPolicy(ctx, orgID, h.defaultRules)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Build trace: evaluate each rule individually.
	claims := middleware.GetClaims(c)
	_ = claims // available for future audit logging

	trace := make([]SimulateTraceItem, 0, len(p.Rules))
	for _, rule := range policy.SortedRules(p.Rules) {
		matched := rule.Enabled && policy.MatchAll(rule.Conditions, in)
		trace = append(trace, SimulateTraceItem{
			RuleName: rule.Name,
			Priority: rule.Priority,
			Enabled:  rule.Enabled,
			Matched:  matched,
			Action:   rule.Action,
		})
	}

	outcome := policy.Evaluate(p, in)

	return c.JSON(http.StatusOK, SimulateResponse{
		Outcome:     outcome,
		MFARequired: mfaRequired || outcome.IsMFARequired(),
		Trace:       trace,
		Input:       in,
		EvaluatedAt: reqTime,
	})
}

// ── Simulate — parse org_id from org_slug variant ─────────────────────────────

// SimulateBySlug is the tenant-facing variant: POST /:org_slug/authorize/simulate.
// It resolves the org_id from the slug and delegates to Simulate.
func (h *PolicyHandler) SimulateBySlug(c echo.Context) error {
	// Resolve slug → id.  We reuse the user repository's org lookup.
	ctx := c.Request().Context()
	slug := c.Param("org_slug")
	if slug == "" {
		return echo.ErrBadRequest
	}
	// The user repo shares the pool; we can't import orgs repo here without
	// creating a cycle, so we accept the org_id as a query param in this variant.
	// The canonical admin endpoint uses :org_id directly.
	orgIDStr := c.QueryParam("org_id")
	if orgIDStr == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "org_id query param required when using /:org_slug/authorize/simulate")
	}
	// Swap the path param value so Simulate can read it.
	c.SetParamNames(append(c.ParamNames(), "org_id")...)
	c.SetParamValues(append(c.ParamValues(), orgIDStr)...)
	_ = ctx
	return h.Simulate(c)
}

// ── Batch simulate ────────────────────────────────────────────────────────────

// BatchSimulateScenario is one scenario in a batch simulation run.
// Identical fields to SimulateRequest, plus an optional label for the caller.
type BatchSimulateScenario struct {
	// Label is an opaque caller-provided identifier echoed back in the result
	// (e.g. "user:alice@example.com" or a row number from the caller's dataset).
	Label string `json:"label"`
	SimulateRequest
}

// BatchSimulateRequest is the body for the batch simulate endpoint.
type BatchSimulateRequest struct {
	// Scenarios is the list of inputs to evaluate (max 1 000).
	Scenarios []BatchSimulateScenario `json:"scenarios"`
}

// BatchSimulateResult is the per-scenario outcome.
type BatchSimulateResult struct {
	Label       string              `json:"label"`
	Index       int                 `json:"index"`
	Outcome     policy.Outcome      `json:"outcome"`
	MFARequired bool                `json:"mfa_required"`
	Trace       []SimulateTraceItem `json:"trace"`
	Input       policy.EvalInput    `json:"input"`
	EvaluatedAt time.Time           `json:"evaluated_at"`
}

// BatchSimulateSummary is aggregate statistics over all scenarios.
type BatchSimulateSummary struct {
	Total        int            `json:"total"`
	Allowed      int            `json:"allowed"`
	Denied       int            `json:"denied"`
	MFARequired  int            `json:"mfa_required"`
	StepUpNeeded int            `json:"step_up_needed"`
	DenyRate     float64        `json:"deny_rate"` // 0–1
	ByAction     map[string]int `json:"by_action"`
}

// BatchSimulateResponse wraps the per-scenario results and the summary.
type BatchSimulateResponse struct {
	Results     []BatchSimulateResult `json:"results"`
	Summary     BatchSimulateSummary  `json:"summary"`
	EvaluatedAt time.Time             `json:"evaluated_at"`
}

const maxBatchScenarios = 1_000

// SimulateBatch runs a policy dry-run for up to 1 000 scenarios in one call.
// The policy rules for the org are loaded once and reused for all scenarios.
//
//	POST /api/v1/organizations/:org_id/auth-policies/simulate/batch
func (h *PolicyHandler) SimulateBatch(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.ErrBadRequest
	}

	var req BatchSimulateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if len(req.Scenarios) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "scenarios must not be empty")
	}
	if len(req.Scenarios) > maxBatchScenarios {
		return echo.NewHTTPError(http.StatusBadRequest, "batch limit is 1 000 scenarios")
	}

	// Load policy once — shared across all scenarios.
	p, err := h.repo.LoadPolicy(ctx, orgID, h.defaultRules)
	if err != nil {
		return echo.ErrInternalServerError
	}

	now := time.Now().UTC()
	results := make([]BatchSimulateResult, 0, len(req.Scenarios))

	summary := BatchSimulateSummary{
		Total:    len(req.Scenarios),
		ByAction: make(map[string]int),
	}

	for i, s := range req.Scenarios {
		reqTime := now
		if s.RequestTime != "" {
			if t, parseErr := time.Parse(time.RFC3339, s.RequestTime); parseErr == nil {
				reqTime = t.UTC()
			}
		}
		ipAddr := s.IPAddress
		if ipAddr == "" {
			ipAddr = c.RealIP()
		}

		in := policy.EvalInput{
			IPAddress:   ipAddr,
			Country:     s.Country,
			UserAgent:   s.UserAgent,
			ClientID:    s.ClientID,
			RequestTime: reqTime,
		}

		mfaRequired := false
		if s.UserID != "" {
			userID, parseErr := uuid.Parse(s.UserID)
			if parseErr == nil {
				in.UserID = s.UserID
				if user, uErr := h.users.GetByID(ctx, userID); uErr == nil {
					in.LastLoginAt = user.LastLoginAt
					mfaRequired = user.MFARequired
				}
				if count, mErr := h.mfa.CountConfirmedByUser(ctx, userID); mErr == nil {
					in.MFAEnrolled = count > 0
				}
				if signals, sErr := h.history.GetAnomalySignals(ctx, userID, ipAddr, s.Country); sErr == nil {
					in.NewCountry = signals.NewCountry
				}
			}
		}

		// Per-rule trace.
		trace := make([]SimulateTraceItem, 0, len(p.Rules))
		for _, rule := range policy.SortedRules(p.Rules) {
			matched := rule.Enabled && policy.MatchAll(rule.Conditions, in)
			trace = append(trace, SimulateTraceItem{
				RuleName: rule.Name,
				Priority: rule.Priority,
				Enabled:  rule.Enabled,
				Matched:  matched,
				Action:   rule.Action,
			})
		}

		outcome := policy.Evaluate(p, in)
		thisMFA := mfaRequired || outcome.IsMFARequired()

		// Accumulate summary.
		switch outcome.Action {
		case policy.ActionAllow:
			summary.Allowed++
		case policy.ActionDeny:
			summary.Denied++
		}
		if thisMFA {
			summary.MFARequired++
		}
		if outcome.Action == policy.ActionStepUp {
			summary.StepUpNeeded++
		}
		summary.ByAction[string(outcome.Action)]++

		label := s.Label
		if label == "" {
			label = s.UserID
		}

		results = append(results, BatchSimulateResult{
			Label:       label,
			Index:       i,
			Outcome:     outcome,
			MFARequired: thisMFA,
			Trace:       trace,
			Input:       in,
			EvaluatedAt: reqTime,
		})
	}

	if summary.Total > 0 {
		summary.DenyRate = float64(summary.Denied) / float64(summary.Total)
	}

	return c.JSON(http.StatusOK, BatchSimulateResponse{
		Results:     results,
		Summary:     summary,
		EvaluatedAt: now,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func validAction(a policy.Action) bool {
	switch a {
	case policy.ActionAllow, policy.ActionDeny, policy.ActionRequireMFA, policy.ActionStepUp:
		return true
	}
	return false
}
