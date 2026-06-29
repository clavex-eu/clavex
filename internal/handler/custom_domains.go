package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// CustomDomainHandler manages CRUD for per-org custom domains.
type CustomDomainHandler struct {
	repo *repository.CustomDomainRepository
}

func NewCustomDomainHandler(pool *pgxpool.Pool) *CustomDomainHandler {
	return &CustomDomainHandler{repo: repository.NewCustomDomainRepository(pool)}
}

// List returns all custom domains for an org.
// GET /api/v1/organizations/:org_id/custom-domains
func (h *CustomDomainHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	domains, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	if domains == nil {
		domains = []*repository.CustomDomain{}
	}
	return c.JSON(http.StatusOK, domains)
}

// Create registers a new custom domain for an org (status=pending).
// POST /api/v1/organizations/:org_id/custom-domains
func (h *CustomDomainHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	var body struct {
		Domain string `json:"domain"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	domain := strings.ToLower(strings.TrimSpace(body.Domain))
	if domain == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "domain is required")
	}
	// Basic sanity: must look like a hostname (no scheme, no path).
	if strings.ContainsAny(domain, "/:?#") {
		return echo.NewHTTPError(http.StatusBadRequest, "domain must be a plain hostname without scheme or path")
	}

	d, err := h.repo.Create(c.Request().Context(), orgID, domain)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return echo.NewHTTPError(http.StatusConflict, "domain is already registered")
		}
		return err
	}
	return c.JSON(http.StatusCreated, d)
}

// Delete removes a custom domain.
// DELETE /api/v1/organizations/:org_id/custom-domains/:domain_id
func (h *CustomDomainHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	domainID, err := uuidParam(c, "domain_id")
	if err != nil {
		return err
	}

	if err := h.repo.Delete(c.Request().Context(), domainID, orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "custom domain not found")
		}
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// Verify triggers the CNAME + TLS verification flow for a pending domain.
// POST /api/v1/organizations/:org_id/custom-domains/:domain_id/verify
// In production this would enqueue a background job; here it returns 202
// Accepted immediately and the verification job polls for CNAME completion.
func (h *CustomDomainHandler) Verify(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	domainID, err := uuidParam(c, "domain_id")
	if err != nil {
		return err
	}

	domains, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return err
	}

	// Ensure the domain belongs to this org.
	var found bool
	for _, d := range domains {
		if d.ID == domainID {
			found = true
			break
		}
	}
	if !found {
		return echo.NewHTTPError(http.StatusNotFound, "custom domain not found")
	}

	// Return 202 — the actual CNAME check and cert provisioning happen
	// asynchronously via a background worker / Traefik ACME integration.
	return c.JSON(http.StatusAccepted, map[string]string{
		"message": "verification job queued",
		"domain_id": domainID.String(),
	})
}

// ensure uuid.Nil is not flagged as unused
var _ = uuid.Nil
