package handler

import (
	"errors"
	"net/http"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// IACAHandler manages per-org IACA (Issuer Authority CA) root certificates
// used to verify the mdoc IssuerAuth x5chain (ISO 18013-5 §9.3.3).
//
// Routes (all under /api/v1/organizations/:org_id):
//
//	POST   /mdoc/iaca-roots           → Upload
//	GET    /mdoc/iaca-roots           → List
//	DELETE /mdoc/iaca-roots/:root_id  → Delete
type IACAHandler struct {
	repo *repository.IACARepository
}

func NewIACAHandler(pool *pgxpool.Pool) *IACAHandler {
	return &IACAHandler{
		repo: repository.NewIACARepository(pool),
	}
}

// Upload handles POST /api/v1/organizations/:org_id/mdoc/iaca-roots
//
// Body (JSON):
//
//	{
//	  "label":     "IT PID Issuer Root CA",
//	  "pem":       "-----BEGIN CERTIFICATE-----\n...",
//	  "doc_types": ["eu.europa.ec.eudi.pid.1"]   // optional, empty=all
//	}
//
// Response: 201 Created with the stored OrgIACARoot object.
func (h *IACAHandler) Upload(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return echo.ErrBadRequest
	}

	var req struct {
		Label    string   `json:"label"`
		PEM      string   `json:"pem"`
		DocTypes []string `json:"doc_types"`
	}
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.Label == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "label is required",
		})
	}
	if req.PEM == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "pem is required",
		})
	}

	// Resolve caller user ID from JWT (optional — may be nil for API key callers).
	var callerID *uuid.UUID
	if claims := middleware.GetClaims(c); claims != nil {
		if id, err := uuid.Parse(claims.Subject); err == nil {
			callerID = &id
		}
	}

	root, err := h.repo.Create(c.Request().Context(), orgID, req.Label, req.PEM, req.DocTypes, callerID)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateCert) {
			return c.JSON(http.StatusConflict, map[string]string{
				"error": "certificate_already_registered",
			})
		}
		// Surface validation errors (not CA, bad PEM, etc.) as 400.
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, root)
}

// List handles GET /api/v1/organizations/:org_id/mdoc/iaca-roots
func (h *IACAHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return echo.ErrBadRequest
	}
	roots, err := h.repo.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if roots == nil {
		return c.JSON(http.StatusOK, []any{})
	}
	return c.JSON(http.StatusOK, roots)
}

// Delete handles DELETE /api/v1/organizations/:org_id/mdoc/iaca-roots/:root_id
func (h *IACAHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return echo.ErrBadRequest
	}
	rootID, err := uuidParam(c, "root_id")
	if err != nil {
		return echo.ErrBadRequest
	}
	if err := h.repo.Delete(c.Request().Context(), rootID, orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrNotFound
		}
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
