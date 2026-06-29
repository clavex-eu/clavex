package handler

// marketplace.go — Clavex Credential Marketplace handler.
//
// Public endpoints (no auth):
//   GET  /api/v1/marketplace/credentials         — list verified public listings
//   GET  /api/v1/marketplace/credentials/:id     — get single listing
//
// Org-admin endpoints (admin JWT, org-scoped):
//   GET    /api/v1/organizations/:org_id/marketplace/listings           — list org's listings
//   POST   /api/v1/organizations/:org_id/marketplace/listings           — publish new listing
//   PUT    /api/v1/organizations/:org_id/marketplace/listings/:id       — update listing
//   DELETE /api/v1/organizations/:org_id/marketplace/listings/:id       — delete listing
//
// Superadmin endpoints (admin JWT, no org scope):
//   GET  /api/v1/superadmin/marketplace/pending          — list pending moderation
//   POST /api/v1/superadmin/marketplace/:id/approve      — approve + publish
//   POST /api/v1/superadmin/marketplace/:id/reject       — reject with note

import (
	"errors"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
)

// MarketplaceHandler handles the Credential Marketplace endpoints.
type MarketplaceHandler struct {
	repo *repository.MarketplaceRepository
}

// NewMarketplaceHandler creates a MarketplaceHandler.
func NewMarketplaceHandler(repo *repository.MarketplaceRepository) *MarketplaceHandler {
	return &MarketplaceHandler{repo: repo}
}

// ── Public endpoints ──────────────────────────────────────────────────────────

// ListPublic godoc
// GET /api/v1/marketplace/credentials
// Query params: lang, tag, q (full-text search)
func (h *MarketplaceHandler) ListPublic(c echo.Context) error {
	lang := c.QueryParam("lang")
	tag := c.QueryParam("tag")
	q := c.QueryParam("q")

	listings, err := h.repo.ListPublic(c.Request().Context(), lang, tag, q)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list marketplace"})
	}
	if listings == nil {
		listings = []models.MarketplaceListingPublic{}
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"items": listings,
		"total": len(listings),
	})
}

// GetPublic godoc
// GET /api/v1/marketplace/credentials/:id
func (h *MarketplaceHandler) GetPublic(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid listing id"})
	}
	listing, err := h.repo.GetPublic(c.Request().Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "listing not found"})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get listing"})
	}
	return c.JSON(http.StatusOK, listing)
}

// ── Org-admin endpoints ───────────────────────────────────────────────────────

// ListForOrg godoc
// GET /api/v1/organizations/:org_id/marketplace/listings
func (h *MarketplaceHandler) ListForOrg(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid org_id"})
	}
	listings, err := h.repo.ListForOrg(c.Request().Context(), orgID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list listings"})
	}
	if listings == nil {
		listings = []models.MarketplaceListing{}
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"items": listings,
		"total": len(listings),
	})
}

type publishListingRequest struct {
	CredentialConfigID *string                `json:"credential_config_id,omitempty"`
	DisplayName        string                 `json:"display_name"`
	Description        *string                `json:"description,omitempty"`
	IssuerName         string                 `json:"issuer_name"`
	VCT                string                 `json:"vct"`
	CredentialFormat   string                 `json:"credential_format"`
	Lang               string                 `json:"lang"`
	IssuerEndpoint     string                 `json:"issuer_endpoint"`
	SchemaJSON         map[string]interface{} `json:"schema_json"`
	OfferTemplate      *string                `json:"offer_template,omitempty"`
	Tags               []string               `json:"tags"`
}

// Publish godoc
// POST /api/v1/organizations/:org_id/marketplace/listings
func (h *MarketplaceHandler) Publish(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid org_id"})
	}

	var req publishListingRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	if strings.TrimSpace(req.DisplayName) == "" || strings.TrimSpace(req.IssuerName) == "" ||
		strings.TrimSpace(req.VCT) == "" || strings.TrimSpace(req.IssuerEndpoint) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "display_name, issuer_name, vct, and issuer_endpoint are required"})
	}
	if req.CredentialFormat == "" {
		req.CredentialFormat = "vc+sd-jwt"
	}
	if req.Lang == "" {
		req.Lang = "it"
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}
	if req.SchemaJSON == nil {
		req.SchemaJSON = map[string]interface{}{}
	}

	listing := &models.MarketplaceListing{
		OrgID:            orgID,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		IssuerName:       req.IssuerName,
		VCT:              req.VCT,
		CredentialFormat: req.CredentialFormat,
		Lang:             req.Lang,
		IssuerEndpoint:   req.IssuerEndpoint,
		SchemaJSON:       req.SchemaJSON,
		OfferTemplate:    req.OfferTemplate,
		Tags:             req.Tags,
	}

	if req.CredentialConfigID != nil && *req.CredentialConfigID != "" {
		parsed, parseErr := uuid.Parse(*req.CredentialConfigID)
		if parseErr != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid credential_config_id"})
		}
		listing.CredentialConfigID = &parsed
	}

	if err := h.repo.Create(c.Request().Context(), listing); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to publish listing"})
	}
	return c.JSON(http.StatusCreated, listing)
}

// UpdateListing godoc
// PUT /api/v1/organizations/:org_id/marketplace/listings/:id
func (h *MarketplaceHandler) UpdateListing(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid org_id"})
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid listing id"})
	}

	existing, err := h.repo.GetForOrg(c.Request().Context(), id, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "listing not found"})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get listing"})
	}

	var req publishListingRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	existing.DisplayName = req.DisplayName
	existing.Description = req.Description
	existing.IssuerName = req.IssuerName
	existing.VCT = req.VCT
	existing.CredentialFormat = req.CredentialFormat
	existing.Lang = req.Lang
	existing.IssuerEndpoint = req.IssuerEndpoint
	existing.SchemaJSON = req.SchemaJSON
	existing.OfferTemplate = req.OfferTemplate
	if req.Tags != nil {
		existing.Tags = req.Tags
	}

	if err := h.repo.Update(c.Request().Context(), existing); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update listing"})
	}
	return c.JSON(http.StatusOK, existing)
}

// DeleteListing godoc
// DELETE /api/v1/organizations/:org_id/marketplace/listings/:id
func (h *MarketplaceHandler) DeleteListing(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid org_id"})
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid listing id"})
	}

	if err := h.repo.Delete(c.Request().Context(), id, orgID); errors.Is(err, pgx.ErrNoRows) {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "listing not found"})
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete listing"})
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Superadmin endpoints ──────────────────────────────────────────────────────

// ListPending godoc
// GET /api/v1/superadmin/marketplace/pending
func (h *MarketplaceHandler) ListPending(c echo.Context) error {
	listings, err := h.repo.ListPending(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list pending"})
	}
	if listings == nil {
		listings = []models.MarketplaceListing{}
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"items": listings,
		"total": len(listings),
	})
}

// Approve godoc
// POST /api/v1/superadmin/marketplace/:id/approve
func (h *MarketplaceHandler) Approve(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid listing id"})
	}
	if err := h.repo.Approve(c.Request().Context(), id); errors.Is(err, pgx.ErrNoRows) {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "listing not found"})
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to approve"})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "verified"})
}

// Reject godoc
// POST /api/v1/superadmin/marketplace/:id/reject
func (h *MarketplaceHandler) Reject(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid listing id"})
	}
	var body struct {
		Note string `json:"note"`
	}
	_ = c.Bind(&body)

	if err := h.repo.Reject(c.Request().Context(), id, body.Note); errors.Is(err, pgx.ErrNoRows) {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "listing not found"})
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to reject"})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "rejected"})
}
