package handler

// federation_ta.go — Admin API handlers for the EUDIW Trust Anchor.
//
// These endpoints allow TA operators to manage the federation via the admin API:
//
//   POST   /api/v1/organizations/:id/federation/subordinates
//   GET    /api/v1/organizations/:id/federation/subordinates
//   PUT    /api/v1/organizations/:id/federation/subordinates/:entity_id
//   DELETE /api/v1/organizations/:id/federation/subordinates/:entity_id  (revoke)
//
//   POST   /api/v1/organizations/:id/federation/trust-mark-types
//   GET    /api/v1/organizations/:id/federation/trust-mark-types
//   POST   /api/v1/organizations/:id/federation/trust-marks             (issue)
//   DELETE /api/v1/organizations/:id/federation/trust-marks             (revoke)

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// FederationTAHandler handles admin-side Trust Anchor operations.
type FederationTAHandler struct {
	fed     *repository.FederationRepository
	auditor *audit.Emitter
}

// NewFederationTAHandler constructs a FederationTAHandler.
func NewFederationTAHandler(pool *pgxpool.Pool, auditor *audit.Emitter) *FederationTAHandler {
	return &FederationTAHandler{
		fed:     repository.NewFederationRepository(pool),
		auditor: auditor,
	}
}

// ── Subordinates ──────────────────────────────────────────────────────────────

// upsertSubordinateRequest is the body for registering/updating a subordinate.
type upsertSubordinateRequest struct {
	EntityID          string          `json:"entity_id"`
	Name              string          `json:"name"`
	EntityTypes       []string        `json:"entity_types"`
	JWKS              json.RawMessage `json:"jwks,omitempty"`
	JWKSUri           string          `json:"jwks_uri,omitempty"`
	MetadataOverride  json.RawMessage `json:"metadata_override,omitempty"`
	MetadataPolicy    json.RawMessage `json:"metadata_policy,omitempty"`
	TrustMarkIDs      []string        `json:"trust_mark_ids,omitempty"`
	Status            string          `json:"status,omitempty"`
	StatementLifetime int             `json:"statement_lifetime_seconds,omitempty"`
}

// RegisterSubordinate handles POST /api/v1/organizations/:id/federation/subordinates
func (h *FederationTAHandler) RegisterSubordinate(c echo.Context) error {
	orgID, err := fedUUIDParam(c, "id")
	if err != nil {
		return err
	}

	var req upsertSubordinateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.EntityID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "entity_id is required")
	}
	if !isValidURI(req.EntityID) {
		return echo.NewHTTPError(http.StatusBadRequest, "entity_id must be a valid URI")
	}

	ctx := c.Request().Context()
	sub, dbErr := h.fed.UpsertSubordinate(ctx, repository.UpsertSubordinateParams{
		OrgID:             orgID,
		EntityID:          req.EntityID,
		Name:              req.Name,
		EntityTypes:       req.EntityTypes,
		JWKS:              req.JWKS,
		JWKSUri:           req.JWKSUri,
		MetadataOverride:  req.MetadataOverride,
		MetadataPolicy:    req.MetadataPolicy,
		TrustMarkIDs:      req.TrustMarkIDs,
		Status:            req.Status,
		StatementLifetime: req.StatementLifetime,
	})
	if dbErr != nil {
		c.Logger().Errorf("federation/ta: upsert subordinate: %v", dbErr)
		h.fedAudit(c, orgID, "federation.subordinate.register", req.EntityID, "failure", nil)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to register subordinate")
	}
	entityType := "subordinate"
	entityID := req.EntityID
	h.fedAudit(c, orgID, "federation.subordinate.register", entityID, "success", map[string]any{
		"name":          req.Name,
		"entity_types":  req.EntityTypes,
		"trust_mark_ids": req.TrustMarkIDs,
		"status":        sub.Status,
	})
	_ = entityType
	return c.JSON(http.StatusCreated, subordinateResponse(sub))
}

// ListSubordinatesAdmin handles GET /api/v1/organizations/:id/federation/subordinates
//
// Optional query param: status — filter by "active" (default), "suspended", "revoked", or "all".
func (h *FederationTAHandler) ListSubordinatesAdmin(c echo.Context) error {
	orgID, err := fedUUIDParam(c, "id")
	if err != nil {
		return err
	}
	statusFilter := c.QueryParam("status")
	if statusFilter == "all" {
		statusFilter = ""
	}

	subs, dbErr := h.fed.ListSubordinatesFull(c.Request().Context(), orgID, statusFilter)
	if dbErr != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list subordinates")
	}
	out := make([]map[string]any, 0, len(subs))
	for _, s := range subs {
		out = append(out, subordinateResponse(s))
	}
	return c.JSON(http.StatusOK, map[string]any{
		"subordinates": out,
		"count":        len(out),
	})
}

// GetSubordinate handles GET /api/v1/organizations/:id/federation/subordinates/detail?entity_id=...
func (h *FederationTAHandler) GetSubordinate(c echo.Context) error {
	orgID, err := fedUUIDParam(c, "id")
	if err != nil {
		return err
	}
	entityID := c.QueryParam("entity_id")
	if entityID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "entity_id query parameter is required")
	}
	sub, dbErr := h.fed.GetSubordinateByEntityID(c.Request().Context(), orgID, entityID)
	if dbErr != nil {
		return echo.NewHTTPError(http.StatusNotFound, "subordinate not found")
	}
	return c.JSON(http.StatusOK, subordinateResponse(sub))
}

// UpdateSubordinate handles PUT /api/v1/organizations/:id/federation/subordinates?entity_id=...
func (h *FederationTAHandler) UpdateSubordinate(c echo.Context) error {
	orgID, err := fedUUIDParam(c, "id")
	if err != nil {
		return err
	}
	entityID := c.QueryParam("entity_id")
	if entityID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "entity_id query parameter is required")
	}

	var req upsertSubordinateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	// entity_id from query param takes precedence.
	req.EntityID = entityID

	ctx := c.Request().Context()
	sub, dbErr := h.fed.UpsertSubordinate(ctx, repository.UpsertSubordinateParams{
		OrgID:             orgID,
		EntityID:          req.EntityID,
		Name:              req.Name,
		EntityTypes:       req.EntityTypes,
		JWKS:              req.JWKS,
		JWKSUri:           req.JWKSUri,
		MetadataOverride:  req.MetadataOverride,
		MetadataPolicy:    req.MetadataPolicy,
		TrustMarkIDs:      req.TrustMarkIDs,
		Status:            req.Status,
		StatementLifetime: req.StatementLifetime,
	})
	if dbErr != nil {
		c.Logger().Errorf("federation/ta: update subordinate: %v", dbErr)
		h.fedAudit(c, orgID, "federation.subordinate.update", entityID, "failure", nil)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to update subordinate")
	}
	h.fedAudit(c, orgID, "federation.subordinate.update", entityID, "success", map[string]any{
		"name":          req.Name,
		"entity_types":  req.EntityTypes,
		"trust_mark_ids": req.TrustMarkIDs,
		"status":        sub.Status,
	})
	return c.JSON(http.StatusOK, subordinateResponse(sub))
}

// RevokeSubordinate handles DELETE /api/v1/organizations/:id/federation/subordinates
// Query param: entity_id — the subordinate to revoke.
func (h *FederationTAHandler) RevokeSubordinate(c echo.Context) error {
	orgID, err := fedUUIDParam(c, "id")
	if err != nil {
		return err
	}
	entityID := c.QueryParam("entity_id")
	if entityID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "entity_id query parameter is required")
	}
	if dbErr := h.fed.UpdateSubordinateStatus(c.Request().Context(), orgID, entityID, "revoked"); dbErr != nil {
		h.fedAudit(c, orgID, "federation.subordinate.revoke", entityID, "failure", nil)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to revoke subordinate")
	}
	h.fedAudit(c, orgID, "federation.subordinate.revoke", entityID, "success", map[string]any{
		"entity_id": entityID,
	})
	return c.NoContent(http.StatusNoContent)
}

// ── Trust Mark Types ──────────────────────────────────────────────────────────

type upsertTrustMarkTypeRequest struct {
	TrustMarkID  string `json:"trust_mark_id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	LogoURI      string `json:"logo_uri,omitempty"`
	RefURI       string `json:"ref_uri,omitempty"`
	LifetimeSecs int    `json:"lifetime_seconds,omitempty"`
}

// UpsertTrustMarkType handles POST /api/v1/organizations/:id/federation/trust-mark-types
func (h *FederationTAHandler) UpsertTrustMarkType(c echo.Context) error {
	orgID, err := fedUUIDParam(c, "id")
	if err != nil {
		return err
	}
	var req upsertTrustMarkTypeRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.TrustMarkID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "trust_mark_id is required")
	}
	if !isValidURI(req.TrustMarkID) {
		return echo.NewHTTPError(http.StatusBadRequest, "trust_mark_id must be a valid URI")
	}
	lifetime := req.LifetimeSecs
	if lifetime == 0 {
		lifetime = 365 * 24 * 3600
	}

	t, dbErr := h.fed.UpsertTrustMarkType(c.Request().Context(), orgID, repository.FederationTrustMarkType{
		TrustMarkID:  req.TrustMarkID,
		Name:         req.Name,
		Description:  req.Description,
		LogoURI:      req.LogoURI,
		RefURI:       req.RefURI,
		LifetimeSecs: lifetime,
	})
	if dbErr != nil {
		c.Logger().Errorf("federation/ta: upsert trust mark type: %v", dbErr)
		h.fedAudit(c, orgID, "federation.trust_mark_type.upsert", req.TrustMarkID, "failure", nil)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save trust mark type")
	}
	h.fedAudit(c, orgID, "federation.trust_mark_type.upsert", req.TrustMarkID, "success", map[string]any{
		"name":             req.Name,
		"lifetime_seconds": lifetime,
		"ref_uri":          req.RefURI,
	})
	return c.JSON(http.StatusCreated, t)
}

// ListTrustMarkTypes handles GET /api/v1/organizations/:id/federation/trust-mark-types
func (h *FederationTAHandler) ListTrustMarkTypes(c echo.Context) error {
	orgID, err := fedUUIDParam(c, "id")
	if err != nil {
		return err
	}
	types, dbErr := h.fed.ListTrustMarkTypes(c.Request().Context(), orgID)
	if dbErr != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list trust mark types")
	}
	return c.JSON(http.StatusOK, types)
}

// ── Trust Mark Issuance (admin-triggered) ─────────────────────────────────────

type revokeTrustMarkRequest struct {
	TrustMarkID string `json:"trust_mark_id"`
	Subject     string `json:"sub"`
	Reason      string `json:"reason,omitempty"`
}

// RevokeTrustMark handles DELETE /api/v1/organizations/:id/federation/trust-marks
func (h *FederationTAHandler) RevokeTrustMark(c echo.Context) error {
	orgID, err := fedUUIDParam(c, "id")
	if err != nil {
		return err
	}
	var req revokeTrustMarkRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.TrustMarkID == "" || req.Subject == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "trust_mark_id and sub are required")
	}
	_, getErr := h.fed.GetTrustMark(c.Request().Context(), orgID, req.TrustMarkID, req.Subject)
	if getErr != nil {
		if errors.Is(getErr, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "trust mark not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to look up trust mark")
	}
	if dbErr := h.fed.RevokeTrustMark(c.Request().Context(), orgID, req.TrustMarkID, req.Subject, req.Reason); dbErr != nil {
		h.fedAudit(c, orgID, "federation.trust_mark.revoke", req.Subject, "failure", map[string]any{
			"trust_mark_id": req.TrustMarkID,
		})
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to revoke trust mark")
	}
	h.fedAudit(c, orgID, "federation.trust_mark.revoke", req.Subject, "success", map[string]any{
		"trust_mark_id": req.TrustMarkID,
		"reason":        req.Reason,
	})
	return c.NoContent(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// fedAudit emits a federation event into the Merkle-chained audit log.
// resourceID is the entity_id (URI) of the affected resource.
func (h *FederationTAHandler) fedAudit(c echo.Context, orgID uuid.UUID, action, resourceID, status string, meta map[string]any) {
	if h.auditor == nil {
		return
	}
	resType := "federation_entity"
	p := audit.EmitParams{
		OrgID:        orgID,
		Action:       action,
		ResourceType: &resType,
		ResourceID:   &resourceID,
		Status:       status,
		Metadata:     meta,
	}
	// Extract actor from the Bearer JWT when present.
	if claims := middleware.GetClaims(c); claims != nil {
		if id, err := uuid.Parse(claims.Subject); err == nil {
			p.ActorID = &id
		}
		if claims.Email != "" {
			p.ActorEmail = &claims.Email
		}
	}
	h.auditor.Emit(c.Request().Context(), p)
}

func fedUUIDParam(c echo.Context, name string) (uuid.UUID, error) {
	raw := c.Param(name)
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "invalid UUID: "+name)
	}
	return id, nil
}

func isValidURI(s string) bool {
	u, err := url.ParseRequestURI(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func subordinateResponse(s *repository.FederationSubordinate) map[string]any {
	return map[string]any{
		"id":                        s.ID,
		"entity_id":                 s.EntityID,
		"name":                      s.Name,
		"entity_types":              s.EntityTypes,
		"trust_mark_ids":            s.TrustMarkIDs,
		"status":                    s.Status,
		"statement_lifetime_seconds": s.StatementLifetime,
		"created_at":                s.CreatedAt,
		"updated_at":                s.UpdatedAt,
	}
}
