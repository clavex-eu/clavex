package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/clavex-eu/clavex/internal/fga"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// FGAHandler exposes the Fine-Grained Authorization API.
//
// Clavex wraps OpenFGA (CNCF Zanzibar implementation) with one OpenFGA store per
// organization. This provides complete tenant isolation of authorization models
// and relationship tuples.
//
// Routes (all scoped to /api/v1/organizations/:org_id/fga):
//
//	 POST   /stores          — initialise an OpenFGA store for the org
//	GET    /stores          — get store info (store_id, model_id)
//	PUT    /model           — upload an authorization model (Zanzibar type graph)
//	GET    /model           — retrieve the active authorization model
//	POST   /check           — evaluate a relationship query
//	POST   /write           — write or delete relationship tuples
//	GET    /read            — list relationship tuples (paginated)
//
// When FGA is not enabled (cfg.FGA.Enabled == false) every endpoint returns 501.
type FGAHandler struct {
	client *fga.Client
	repo   *repository.FGARepository
}

// NewFGAHandler creates an FGAHandler.
// client may be nil when FGA is disabled; all endpoints will return 501 in that case.
func NewFGAHandler(pool *pgxpool.Pool, client *fga.Client) *FGAHandler {
	return &FGAHandler{
		client: client,
		repo:   repository.NewFGARepository(pool),
	}
}

// ── route helpers ────────────────────────────────────────────────────────────

func (h *FGAHandler) disabled(c echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "FGA is not enabled on this server")
}

func (h *FGAHandler) getStore(c echo.Context) (*repository.FGAStoreRecord, uuid.UUID, error) {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return nil, uuid.Nil, err
	}
	rec, err := h.repo.Get(c.Request().Context(), orgID)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("fga: get store record: %w", err)
	}
	return rec, orgID, nil
}

// ── InitStore ─────────────────────────────────────────────────────────────────

// InitStore provisions a new OpenFGA store for the organization (idempotent).
// Calling it a second time is a no-op — returns the existing store info.
//
//	POST /api/v1/organizations/:org_id/fga/stores
func (h *FGAHandler) InitStore(c echo.Context) error {
	if h.client == nil {
		return h.disabled(c)
	}
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()

	// Idempotent — return existing store if already provisioned.
	rec, err := h.repo.Get(ctx, orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	if rec != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"store_id": rec.StoreID,
			"model_id": rec.ModelID,
			"message":  "store already exists",
		})
	}

	storeID, err := h.client.CreateStore(ctx, "org-"+orgID.String())
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("fga: create store")
		return echo.NewHTTPError(http.StatusBadGateway, "could not create FGA store")
	}
	if err := h.repo.Upsert(ctx, orgID, storeID, ""); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	return c.JSON(http.StatusCreated, map[string]any{
		"store_id": storeID,
		"model_id": nil,
	})
}

// ── GetStoreInfo ──────────────────────────────────────────────────────────────

// GetStoreInfo returns the org's OpenFGA store ID and active model ID.
//
//	GET /api/v1/organizations/:org_id/fga/stores
func (h *FGAHandler) GetStoreInfo(c echo.Context) error {
	if h.client == nil {
		return h.disabled(c)
	}
	rec, _, err := h.getStore(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	if rec == nil {
		return echo.NewHTTPError(http.StatusNotFound, "FGA store not provisioned — call POST /fga/stores first")
	}
	return c.JSON(http.StatusOK, map[string]any{
		"store_id":   rec.StoreID,
		"model_id":   rec.ModelID,
		"created_at": rec.CreatedAt,
		"updated_at": rec.UpdatedAt,
	})
}

// ── WriteModel ────────────────────────────────────────────────────────────────

// WriteModel uploads a Zanzibar-style authorization model to the org's store.
// The body must be a valid OpenFGA schema_version 1.1 JSON object.
//
//	PUT /api/v1/organizations/:org_id/fga/model
func (h *FGAHandler) WriteModel(c echo.Context) error {
	if h.client == nil {
		return h.disabled(c)
	}
	rec, orgID, err := h.getStore(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	if rec == nil {
		return echo.NewHTTPError(http.StatusConflict, "FGA store not provisioned — call POST /fga/stores first")
	}

	var body json.RawMessage
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON")
	}

	ctx := c.Request().Context()
	modelID, err := h.client.WriteModel(ctx, rec.StoreID, body)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("fga: write model")
		return echo.NewHTTPError(http.StatusBadGateway, "could not write authorization model")
	}
	if err := h.repo.Upsert(ctx, orgID, rec.StoreID, modelID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	return c.JSON(http.StatusOK, map[string]any{
		"authorization_model_id": modelID,
	})
}

// ── GetModel ──────────────────────────────────────────────────────────────────

// GetModel retrieves the active authorization model for the org's store.
//
//	GET /api/v1/organizations/:org_id/fga/model
func (h *FGAHandler) GetModel(c echo.Context) error {
	if h.client == nil {
		return h.disabled(c)
	}
	rec, orgID, err := h.getStore(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	if rec == nil {
		return echo.NewHTTPError(http.StatusNotFound, "FGA store not provisioned")
	}

	modelID := ""
	if rec.ModelID != nil {
		modelID = *rec.ModelID
	}

	ctx := c.Request().Context()
	model, err := h.client.GetModel(ctx, rec.StoreID, modelID)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("fga: get model")
		return echo.NewHTTPError(http.StatusBadGateway, "could not retrieve authorization model")
	}
	return c.JSONBlob(http.StatusOK, model)
}

// ── Check ─────────────────────────────────────────────────────────────────────

// checkRequest is the body for a relationship check.
//
// Example:
//
//	{
//	  "user":     "user:01925f3a-...",
//	  "relation": "can_read",
//	  "object":   "document:budget-Q1"
//	}
//
// Clavex access token subjects (UUIDs) are used as the user identifier:
// the caller prefixes them with "user:" per the OpenFGA type system convention.
type checkRequest struct {
	User     string `json:"user"     validate:"required"`
	Relation string `json:"relation" validate:"required"`
	Object   string `json:"object"   validate:"required"`
}

// Check evaluates a relationship query against the org's OpenFGA store.
//
// Resource servers call this endpoint (using their admin API key) to determine
// whether an end-user has a particular relationship with an object.
//
//	POST /api/v1/organizations/:org_id/fga/check
//	→ {"allowed": true}
func (h *FGAHandler) Check(c echo.Context) error {
	if h.client == nil {
		return h.disabled(c)
	}
	rec, orgID, err := h.getStore(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	if rec == nil {
		return echo.NewHTTPError(http.StatusConflict, "FGA store not provisioned")
	}

	var req checkRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	modelID := ""
	if rec.ModelID != nil {
		modelID = *rec.ModelID
	}

	ctx := c.Request().Context()
	allowed, err := h.client.Check(ctx, rec.StoreID, modelID, fga.TupleKey{
		User:     req.User,
		Relation: req.Relation,
		Object:   req.Object,
	})
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("fga: check")
		return echo.NewHTTPError(http.StatusBadGateway, "FGA check failed")
	}
	return c.JSON(http.StatusOK, map[string]bool{"allowed": allowed})
}

// ── Write ─────────────────────────────────────────────────────────────────────

// writeRequest is the body for a tuple write operation.
//
// Both "writes" and "deletes" are optional; at least one must be non-empty.
// Each entry is a TupleKey: {user, relation, object}.
type writeRequest struct {
	Writes  []fga.TupleKey `json:"writes"`
	Deletes []fga.TupleKey `json:"deletes"`
}

// Write creates and/or deletes relationship tuples in the org's OpenFGA store.
//
//	POST /api/v1/organizations/:org_id/fga/write
func (h *FGAHandler) Write(c echo.Context) error {
	if h.client == nil {
		return h.disabled(c)
	}
	rec, orgID, err := h.getStore(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	if rec == nil {
		return echo.NewHTTPError(http.StatusConflict, "FGA store not provisioned")
	}

	var req writeRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON")
	}
	if len(req.Writes) == 0 && len(req.Deletes) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "writes or deletes must be non-empty")
	}

	modelID := ""
	if rec.ModelID != nil {
		modelID = *rec.ModelID
	}

	ctx := c.Request().Context()
	if err := h.client.Write(ctx, rec.StoreID, modelID, req.Writes, req.Deletes); err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("fga: write tuples")
		return echo.NewHTTPError(http.StatusBadGateway, "FGA write failed")
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Read ──────────────────────────────────────────────────────────────────────

// Read lists relationship tuples from the org's OpenFGA store.
// Optional query params: user, relation, object, page_size, continuation_token.
//
//	GET /api/v1/organizations/:org_id/fga/read
func (h *FGAHandler) Read(c echo.Context) error {
	if h.client == nil {
		return h.disabled(c)
	}
	rec, orgID, err := h.getStore(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	if rec == nil {
		return echo.NewHTTPError(http.StatusNotFound, "FGA store not provisioned")
	}

	filter := fga.TupleKey{
		User:     c.QueryParam("user"),
		Relation: c.QueryParam("relation"),
		Object:   c.QueryParam("object"),
	}
	pageSize := 0
	if ps := c.QueryParam("page_size"); ps != "" {
		if n, err := fmt.Sscanf(ps, "%d", &pageSize); n != 1 || err != nil {
			pageSize = 0
		}
	}
	contToken := c.QueryParam("continuation_token")

	ctx := c.Request().Context()
	tuples, nextToken, err := h.client.Read(ctx, rec.StoreID, filter, pageSize, contToken)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("fga: read tuples")
		return echo.NewHTTPError(http.StatusBadGateway, "FGA read failed")
	}
	return c.JSON(http.StatusOK, map[string]any{
		"tuples":             tuples,
		"continuation_token": nextToken,
	})
}

// ── Template library ─────────────────────────────────────────────────────────

// GetTemplates returns the full list of built-in OpenFGA model templates.
//
//	GET /api/v1/organizations/:org_id/fga/templates
//
// Response:
//
//	{ "templates": [ { "id", "name", "description", "use_cases", "model" }, … ] }
//
// This endpoint is intentionally org-scoped (uses the FGA auth middleware) but
// does not require a provisioned store — templates are static server-side data.
func (h *FGAHandler) GetTemplates(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"templates": fga.All(),
	})
}

// GetTemplate returns a single template by ID.
//
//	GET /api/v1/organizations/:org_id/fga/templates/:template_id
//
// Useful when the console wants to preview the model JSON before importing.
func (h *FGAHandler) GetTemplate(c echo.Context) error {
	id := c.Param("template_id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "template_id is required")
	}
	t, err := fga.Get(id)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("template %q not found", id))
	}
	return c.JSON(http.StatusOK, t)
}

// ImportTemplate imports a built-in template as the active authorization model
// for the org's FGA store.
//
//	POST /api/v1/organizations/:org_id/fga/templates/:template_id/import
//
// This is a convenience shortcut for:
//  1. GET /fga/templates/:id  (preview model JSON)
//  2. PUT /fga/model          (upload model JSON)
//
// The org must have a provisioned FGA store (call POST /fga/stores first).
func (h *FGAHandler) ImportTemplate(c echo.Context) error {
	if h.client == nil {
		return h.disabled(c)
	}
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	templateID := c.Param("template_id")
	if templateID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "template_id is required")
	}

	t, err := fga.Get(templateID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("template %q not found", templateID))
	}

	rec, _, err := h.getStore(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	if rec == nil {
		return echo.NewHTTPError(http.StatusConflict, "FGA store not provisioned — call POST /fga/stores first")
	}

	ctx := c.Request().Context()
	modelID, err := h.client.WriteModel(ctx, rec.StoreID, t.Model)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Str("template", templateID).Msg("fga: import template")
		return echo.NewHTTPError(http.StatusBadGateway, "FGA model write failed")
	}

	if err := h.repo.UpdateModelID(ctx, orgID, modelID); err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("fga: store model_id after import")
		// Non-fatal: the model was pushed to OpenFGA; only the cached ID in our DB failed.
	}

	return c.JSON(http.StatusOK, map[string]any{
		"model_id":    modelID,
		"template_id": templateID,
		"template":    t.Name,
	})
}
