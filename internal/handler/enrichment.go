package handler

import (
	"net/http"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// EnrichmentHandler manages the per-org synchronous claims-enrichment hook.
type EnrichmentHandler struct {
	orgs *repository.OrgRepository
}

func NewEnrichmentHandler(pool *pgxpool.Pool) *EnrichmentHandler {
	return &EnrichmentHandler{orgs: repository.NewOrgRepository(pool)}
}

type enrichmentConfigResponse struct {
	URL    *string `json:"url"`
	HasSecret bool `json:"has_secret"`
}

type setEnrichmentConfigRequest struct {
	// URL is the HTTPS endpoint to POST to during token issuance.
	// Set to null or empty string to disable the hook.
	URL    *string `json:"url"`
	// Secret is sent as "Authorization: Bearer <secret>" to the endpoint.
	// Omit or set to null to leave the existing secret unchanged.
	// Set to "" (empty string) to clear the secret.
	Secret *string `json:"secret"`
}

// GET /api/v1/organizations/:org_id/enrichment-hook
func (h *EnrichmentHandler) Get(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	org, err := h.orgs.GetByID(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	resp := enrichmentConfigResponse{
		URL:       org.ClaimsEnrichmentURL,
		HasSecret: org.ClaimsEnrichmentSecret != nil && *org.ClaimsEnrichmentSecret != "",
	}
	return c.JSON(http.StatusOK, resp)
}

// PUT /api/v1/organizations/:org_id/enrichment-hook
func (h *EnrichmentHandler) Put(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	var body setEnrichmentConfigRequest
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	// Normalise: treat empty string URL as nil (disabled).
	var urlPtr *string
	if body.URL != nil && *body.URL != "" {
		u := *body.URL
		urlPtr = &u
	}

	// If the caller omits secret entirely, read the existing value and keep it.
	var secretPtr *string
	if body.Secret != nil {
		if *body.Secret == "" {
			secretPtr = nil // clear the secret
		} else {
			s := *body.Secret
			secretPtr = &s
		}
	} else {
		// secret field absent: preserve whatever is stored.
		org, err := h.orgs.GetByID(c.Request().Context(), orgID)
		if err != nil {
			return echo.ErrInternalServerError
		}
		secretPtr = org.ClaimsEnrichmentSecret
	}

	if err := h.orgs.SetEnrichmentConfig(c.Request().Context(), orgID, urlPtr, secretPtr); err != nil {
		return echo.ErrInternalServerError
	}

	resp := enrichmentConfigResponse{
		URL:       urlPtr,
		HasSecret: secretPtr != nil && *secretPtr != "",
	}
	return c.JSON(http.StatusOK, resp)
}

// DELETE /api/v1/organizations/:org_id/enrichment-hook
func (h *EnrichmentHandler) Delete(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	if err := h.orgs.SetEnrichmentConfig(c.Request().Context(), orgID, nil, nil); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
