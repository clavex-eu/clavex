package handler

import (
	"encoding/json"
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
	jwkPkg "github.com/lestrrat-go/jwx/v2/jwk"
)

// JWTBearerTrustedIssuerHandler exposes admin endpoints for configuring
// per-org trusted issuers for the RFC 7523 JWT Bearer authorization grant.
//
//	GET    /api/v1/organizations/:org_id/jwt-bearer-trusted-issuers
//	POST   /api/v1/organizations/:org_id/jwt-bearer-trusted-issuers
//	DELETE /api/v1/organizations/:org_id/jwt-bearer-trusted-issuers/:issuer_id
type JWTBearerTrustedIssuerHandler struct {
	repo *repository.JWTBearerTrustedIssuerRepository
}

func NewJWTBearerTrustedIssuerHandler(pool *pgxpool.Pool) *JWTBearerTrustedIssuerHandler {
	return &JWTBearerTrustedIssuerHandler{repo: repository.NewJWTBearerTrustedIssuerRepository(pool)}
}

type createJWTBearerTrustedIssuerRequest struct {
	Issuer  string          `json:"issuer"`
	JWKS    json.RawMessage `json:"jwks,omitempty"`
	JWKSUri string          `json:"jwks_uri,omitempty"`
	// ClaimMappings maps assertion claim names to Clavex access-token claim names.
	ClaimMappings map[string]string `json:"claim_mappings"`
	// AllowedScopes, if non-empty, restricts which scopes this issuer's assertions may request.
	AllowedScopes []string `json:"allowed_scopes"`
}

// List handles GET /api/v1/organizations/:org_id/jwt-bearer-trusted-issuers
func (h *JWTBearerTrustedIssuerHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	issuers, err := h.repo.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if issuers == nil {
		issuers = []*models.JWTBearerTrustedIssuer{}
	}
	return c.JSON(http.StatusOK, issuers)
}

// Create handles POST /api/v1/organizations/:org_id/jwt-bearer-trusted-issuers
func (h *JWTBearerTrustedIssuerHandler) Create(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createJWTBearerTrustedIssuerRequest
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}
	req.Issuer = strings.TrimSpace(req.Issuer)
	if req.Issuer == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "issuer is required")
	}
	if len(req.JWKS) == 0 && req.JWKSUri == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "either jwks or jwks_uri is required")
	}
	if len(req.JWKS) > 0 {
		if _, parseErr := jwkPkg.Parse(req.JWKS); parseErr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "jwks is not a valid JSON Web Key Set")
		}
	}

	var jwksPtr *json.RawMessage
	if len(req.JWKS) > 0 {
		jwksPtr = &req.JWKS
	}
	var jwksURIPtr *string
	if req.JWKSUri != "" {
		jwksURIPtr = &req.JWKSUri
	}

	createdBy := ""
	if claims := middleware.GetClaims(c); claims != nil {
		createdBy = claims.Email
	}

	issuer, err := h.repo.Create(ctx, orgID, req.Issuer, jwksPtr, jwksURIPtr,
		req.ClaimMappings, req.AllowedScopes, createdBy)
	if err != nil {
		if strings.Contains(err.Error(), "uq_jwt_bearer_trusted_issuer") ||
			strings.Contains(err.Error(), "unique") {
			return echo.NewHTTPError(http.StatusConflict, "this issuer is already trusted for this organization")
		}
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, issuer)
}

// Revoke handles DELETE /api/v1/organizations/:org_id/jwt-bearer-trusted-issuers/:issuer_id
func (h *JWTBearerTrustedIssuerHandler) Revoke(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	issuerID, err := uuid.Parse(c.Param("issuer_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid issuer_id")
	}
	err = h.repo.Revoke(c.Request().Context(), issuerID, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "trusted issuer not found or already revoked")
		}
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
