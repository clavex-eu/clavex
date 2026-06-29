package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// CrossOrgTrustHandler exposes admin endpoints for managing RFC 8693 cross-org
// token exchange trust relationships.
//
//	GET    /api/v1/organizations/:org_id/cross-org-trusts
//	POST   /api/v1/organizations/:org_id/cross-org-trusts
//	DELETE /api/v1/organizations/:org_id/cross-org-trusts/:trust_id
//	GET    /api/v1/organizations/:org_id/cross-org-trusts/inbound  (trusts into this org)
type CrossOrgTrustHandler struct {
	repo *repository.CrossOrgTrustRepository
	orgs *repository.OrgRepository
}

func NewCrossOrgTrustHandler(pool *pgxpool.Pool) *CrossOrgTrustHandler {
	return &CrossOrgTrustHandler{
		repo: repository.NewCrossOrgTrustRepository(pool),
		orgs: repository.NewOrgRepository(pool),
	}
}

type createCrossOrgTrustRequest struct {
	// TargetOrgSlug is the slug of the organization that users of the source org
	// should be allowed to exchange tokens into.
	TargetOrgSlug    string   `json:"target_org_slug"`
	AllowedScopes    []string `json:"allowed_scopes"`     // nil or empty → any scope
	AllowedClientIDs []string `json:"allowed_client_ids"` // nil or empty → any client
	// MaxTokenTTL limits the exchanged access-token lifetime (seconds). 0/nil = no limit.
	MaxTokenTTL *int `json:"max_token_ttl,omitempty"`
	// RequireMFA, when true, rejects the exchange unless the subject_token carries an MFA amr.
	RequireMFA bool `json:"require_mfa"`
}

// List handles GET /api/v1/organizations/:org_id/cross-org-trusts
// Returns all outbound trust records for which :org_id is the source.
func (h *CrossOrgTrustHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	trusts, err := h.repo.ListBySourceOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if trusts == nil {
		trusts = []*models.CrossOrgTrust{}
	}
	return c.JSON(http.StatusOK, trusts)
}

// ListInbound handles GET /api/v1/organizations/:org_id/cross-org-trusts/inbound
// Returns all trusts where :org_id is the TARGET — i.e., which source orgs can
// exchange tokens into this org.
func (h *CrossOrgTrustHandler) ListInbound(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	trusts, err := h.repo.ListByTargetOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if trusts == nil {
		trusts = []*models.CrossOrgTrust{}
	}
	return c.JSON(http.StatusOK, trusts)
}

// Create handles POST /api/v1/organizations/:org_id/cross-org-trusts
func (h *CrossOrgTrustHandler) Create(c echo.Context) error {
	ctx := c.Request().Context()

	sourceOrgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createCrossOrgTrustRequest
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}
	req.TargetOrgSlug = strings.TrimSpace(req.TargetOrgSlug)
	if req.TargetOrgSlug == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "target_org_slug is required")
	}

	// Resolve target org.
	targetOrg, err := h.orgs.GetBySlug(ctx, req.TargetOrgSlug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "target organization not found")
		}
		return echo.ErrInternalServerError
	}
	if targetOrg.ID == sourceOrgID {
		return echo.NewHTTPError(http.StatusBadRequest, "source and target organization must differ")
	}

	// Who triggered the creation.
	createdBy := ""
	if claims := middleware.GetClaims(c); claims != nil {
		createdBy = claims.Email
	}

	trust, err := h.repo.Create(ctx, sourceOrgID, targetOrg.ID,
		req.AllowedScopes, req.AllowedClientIDs,
		req.MaxTokenTTL, req.RequireMFA,
		createdBy)
	if err != nil {
		// Unique constraint violation: trust pair already exists.
		if strings.Contains(err.Error(), "uq_cross_org_trust_pair") ||
			strings.Contains(err.Error(), "unique") {
			return echo.NewHTTPError(http.StatusConflict,
				"a trust relationship between these organizations already exists")
		}
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, trust)
}

// Revoke handles DELETE /api/v1/organizations/:org_id/cross-org-trusts/:trust_id
func (h *CrossOrgTrustHandler) Revoke(c echo.Context) error {
	sourceOrgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	trustID, err := uuid.Parse(c.Param("trust_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid trust_id")
	}
	err = h.repo.Revoke(c.Request().Context(), trustID, sourceOrgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "trust not found or already revoked")
		}
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
