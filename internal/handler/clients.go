package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// ClientHandler manages OIDC client registrations.
type ClientHandler struct {
	repo    *repository.ClientRepository
	orgRepo *repository.OrgRepository
}

func NewClientHandler(pool *pgxpool.Pool) *ClientHandler {
	return &ClientHandler{
		repo:    repository.NewClientRepository(pool),
		orgRepo: repository.NewOrgRepository(pool),
	}
}

type createClientRequest struct {
	ClientID               string   `json:"client_id"                  validate:"omitempty,min=1,max=120,alphanumunicode"`
	Name                   string   `json:"name"                       validate:"required,min=1,max=120"`
	RedirectURIs           []string `json:"redirect_uris"              validate:"required,min=1,dive,redirect_uri"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"  validate:"omitempty,dive,url"`
	GrantTypes             []string `json:"grant_types"                validate:"omitempty"`
	IsPublic               bool     `json:"is_public"`
	LogoURL                *string  `json:"logo_url"                   validate:"omitempty,url"`
}

func (h *ClientHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createClientRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	client, secret, err := h.repo.Create(c.Request().Context(), orgID, req.ClientID, req.Name, req.RedirectURIs, req.IsPublic)
	if err != nil {
		return err
	}
	// Return the plain-text secret only at creation time, never again.
	resp := map[string]interface{}{
		"client":        client,
		"client_secret": secret,
	}
	if req.IsPublic {
		resp["client_secret"] = nil
	}
	return c.JSON(http.StatusCreated, resp)
}

func (h *ClientHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	limit := 50
	offset := 0
	if v := c.QueryParam("limit"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			limit = n
		}
	}
	if v := c.QueryParam("offset"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			offset = n
		}
	}
	page, err := h.repo.ListByOrgPage(c.Request().Context(), orgID, limit, offset)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, page)
}

func (h *ClientHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id := c.Param("id")
	client, err := h.repo.GetForOrg(c.Request().Context(), id, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, client)
}

type updateClientRequest struct {
	Name                   *string  `json:"name"                      validate:"omitempty,min=1,max=120"`
	RedirectURIs           []string `json:"redirect_uris"             validate:"omitempty,dive,redirect_uri"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris" validate:"omitempty,dive,url"`
	LogoURL                *string  `json:"logo_url"                  validate:"omitempty,url"`
	IsActive               *bool    `json:"is_active"`
	MFARequired            *bool    `json:"mfa_required"`
	KeycloakCompat         *bool    `json:"keycloak_compat"`
	// AccessTokenTTL overrides the access token lifetime (seconds) for this client.
	// Pass 0 to clear the override and revert to org/server default.
	AccessTokenTTL  *int `json:"access_token_ttl"`
	// RefreshTokenTTL overrides the refresh token lifetime (seconds) for this client.
	// Pass 0 to clear the override and revert to org/server default.
	RefreshTokenTTL *int `json:"refresh_token_ttl"`
	// EnabledLoginProviders, when non-nil, restricts which national eID / federated
	// login buttons appear on the login page for this client.
	// Empty slice resets to the default (all active providers).
	// Supported values: "spid", "cie", "itsme", "bundid", "bundidsaml", "digid",
	//   "clave", "franceconnect", "eidas", or any identity_providers.provider_type.
	EnabledLoginProviders []string `json:"enabled_login_providers"`
}

func (h *ClientHandler) Update(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id := c.Param("id")
	var req updateClientRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	client, err := h.repo.Update(c.Request().Context(), id, orgID, req.Name, req.RedirectURIs, req.IsActive, req.MFARequired, req.KeycloakCompat, req.AccessTokenTTL, req.RefreshTokenTTL)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return echo.ErrNotFound
		}
		log.Error().Err(err).Str("client_id", id).Msg("clients: Update failed")
		return echo.ErrInternalServerError
	}
	if req.EnabledLoginProviders != nil {
		if err := h.repo.SetEnabledLoginProviders(c.Request().Context(), id, orgID, req.EnabledLoginProviders); err != nil {
			log.Error().Err(err).Str("client_id", id).Msg("clients: SetEnabledLoginProviders failed")
			return echo.ErrInternalServerError
		}
		client.EnabledLoginProviders = req.EnabledLoginProviders
	}
	return c.JSON(http.StatusOK, client)
}

func (h *ClientHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id := c.Param("id")
	if err := h.repo.Delete(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// RotateSecret generates a new client secret and returns it once.
func (h *ClientHandler) RotateSecret(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id := c.Param("id")
	newSecret, err := h.repo.RotateSecret(c.Request().Context(), id, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, map[string]string{"client_secret": newSecret})
}

type quickRegisterRequest struct {
	AppURL  string `json:"app_url"  validate:"required,url"`
	AppName string `json:"app_name" validate:"required,min=1,max=120"`
}

// QuickRegister creates an OIDC client pre-configured for the given app URL,
// deriving standard redirect URIs automatically and returning client credentials
// plus a ready-to-paste .env snippet.
//
// POST /api/v1/organizations/:org_id/quick-register
func (h *ClientHandler) QuickRegister(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req quickRegisterRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	// Only http / https are accepted — reject javascript:, file:, etc.
	parsed, err := url.Parse(req.AppURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return echo.NewHTTPError(http.StatusBadRequest, "app_url must be an http or https URL")
	}
	if parsed.Host == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "app_url must include a host")
	}

	base := strings.TrimRight(req.AppURL, "/")
	redirectURIs := []string{
		base + "/callback",
		base + "/api/auth/callback",
		base + "/auth/callback",
	}

	client, secret, err := h.repo.Create(c.Request().Context(), orgID, "", req.AppName, redirectURIs, false)
	if err != nil {
		return err
	}

	org, err := h.orgRepo.GetByID(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	issuer := c.Scheme() + "://" + c.Request().Host + "/" + org.Slug

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"client_id":                client.ClientID,
		"client_secret":            secret,
		"redirect_uris_registered": redirectURIs,
		"issuer":                   issuer,
		"env": map[string]string{
			"NEXT_PUBLIC_CLAVEX_URL":       issuer,
			"NEXT_PUBLIC_CLAVEX_CLIENT_ID": client.ClientID,
			"VITE_CLAVEX_URL":              issuer,
			"VITE_CLAVEX_CLIENT_ID":        client.ClientID,
		},
	})
}
