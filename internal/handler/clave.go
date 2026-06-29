package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/clave"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// ClaveHandler handles Cl@ve (Spanish state authentication system) OIDC authentication.
// Cl@ve uses standard OIDC Authorization Code Flow with PKCE (S256) and nonce.
//
// Registration: https://administracionelectronica.gob.es/ctt/clave
// Pre-production: https://preprod.clave.gob.es
type ClaveHandler struct {
	idpRepo *repository.IDPRepository
	users   *repository.UserRepository
	orgs    *repository.OrgRepository
	store   *session.Store
}

func NewClaveHandler(pool *pgxpool.Pool, store *session.Store) *ClaveHandler {
	return &ClaveHandler{
		idpRepo: repository.NewIDPRepository(pool),
		users:   repository.NewUserRepository(pool),
		orgs:    repository.NewOrgRepository(pool),
		store:   store,
	}
}

// ── Admin CRUD (provider_type = "clave") ──────────────────────────────────────

type createClaveRequest struct {
	Name         string `json:"name" validate:"required,min=1,max=128"`
	ClientID     string `json:"client_id"     validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
	// Environment: "production" or "preproduction"
	Environment string `json:"environment" validate:"required,oneof=production preproduction"`
	// AuthLevel selects the Cl@ve authentication method (acr_values).
	// Leave empty to let Cl@ve choose. Supported values:
	//   clave.LevelPIN         — Cl@ve PIN (OTP, eIDAS Substantial)
	//   clave.LevelCertificate — certificado electrónico / DNIe (eIDAS High)
	AuthLevel string `json:"auth_level"`
	AllowJIT  bool   `json:"allow_jit"`
	IsActive  bool   `json:"is_active"`
}

// CreateClave registers a Cl@ve provider for an org.
// POST /api/v1/organizations/:org_id/clave
func (h *ClaveHandler) CreateClave(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createClaveRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	eps := clave.GetEndpoints(req.Environment)
	userinfoURL := eps.UserinfoURL

	p := &models.IdentityProvider{
		OrgID:             orgID,
		Name:              req.Name,
		ProviderType:      "clave",
		ClientID:          req.ClientID,
		AuthorizationURL:  eps.AuthorizationURL,
		TokenURL:          eps.TokenURL,
		UserinfoURL:       &userinfoURL,
		Scopes:            clave.DefaultScopes,
		EmailClaim:        clave.DefaultClaimMapping.EmailClaim,
		FirstNameClaim:    clave.DefaultClaimMapping.FirstNameClaim,
		LastNameClaim:     clave.DefaultClaimMapping.LastNameClaim,
		IsActive:          req.IsActive,
		AllowJIT:          req.AllowJIT,
		RoleClaimMappings: map[string]string{},
	}
	if req.AuthLevel != "" {
		p.RoleClaimMappings["__auth_level__"] = req.AuthLevel
	}

	created, err := h.idpRepo.Create(c.Request().Context(), p, req.ClientSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "provider name already exists for this organization")
	}
	return c.JSON(http.StatusCreated, created)
}

// ── OIDC SSO flow ──────────────────────────────────────────────────────────────

// StartSSO initiates the Cl@ve OIDC flow using PKCE + nonce.
// GET /:org_slug/clave/:idp_id?login_session_id=...
func (h *ClaveHandler) StartSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idpIDStr := c.Param("idp_id")
	loginSessionID := c.QueryParam("login_session_id")
	orgSlug := c.Param("org_slug")

	if loginSessionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}
	providerID, err := uuid.Parse(idpIDStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid idp_id")
	}

	provider, err := h.idpRepo.GetByID(ctx, providerID)
	if err != nil || !provider.IsActive || provider.ProviderType != "clave" {
		return echo.NewHTTPError(http.StatusNotFound, "Cl@ve provider not found or inactive")
	}

	codeVerifier := newCIERandom(43)
	state := newCIERandom(24)
	nonce := newCIERandom(24)

	redirectURI := buildClaveRedirectURI(c, orgSlug, idpIDStr)
	env := claveEnvFromTokenURL(provider.TokenURL)

	acrValues := provider.RoleClaimMappings["__auth_level__"]

	authURL := clave.BuildAuthzURL(env, provider.ClientID, redirectURI, state, nonce, codeVerifier, acrValues)

	if err := h.store.SaveIDPState(ctx, state, &session.IDPState{
		ProviderID:     providerID.String(),
		LoginSessionID: loginSessionID,
		OrgSlug:        orgSlug,
		CodeVerifier:   codeVerifier,
		Nonce:          nonce,
	}); err != nil {
		return echo.ErrInternalServerError
	}

	return c.Redirect(http.StatusFound, authURL)
}

// CallbackSSO handles the Cl@ve OIDC callback.
// GET /:org_slug/clave/:idp_id/callback?code=...&state=...
func (h *ClaveHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idpIDStr := c.Param("idp_id")
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	if state == "" || code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing state or code parameters")
	}

	stateData, err := h.store.GetIDPState(ctx, state)
	if err != nil || stateData == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Cl@ve session expired — please restart the login")
	}
	if stateData.ProviderID != idpIDStr {
		return echo.NewHTTPError(http.StatusBadRequest, "state mismatch")
	}

	loginSess, err := h.store.GetLoginSession(ctx, stateData.LoginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please restart the login")
	}

	providerID, _ := uuid.Parse(stateData.ProviderID)
	provider, err := h.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	clientSecret, _, _, _, err := h.idpRepo.GetClientSecret(ctx, provider.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	redirectURI := buildClaveRedirectURI(c, stateData.OrgSlug, idpIDStr)

	tokenResp, err := exchangeUpstreamCode(ctx, provider.TokenURL, provider.ClientID, clientSecret, code, redirectURI)
	if err != nil {
		log.Warn().Err(err).Str("provider_id", idpIDStr).Msg("clave: token exchange failed")
		return echo.NewHTTPError(http.StatusBadGateway, "Cl@ve token exchange failed")
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "Cl@ve did not return an access token")
	}

	rawClaims, err := fetchClaveUserInfo(ctx, *provider.UserinfoURL, accessToken)
	if err != nil {
		log.Warn().Err(err).Str("provider_id", idpIDStr).Msg("clave: userinfo fetch failed")
		return echo.NewHTTPError(http.StatusBadGateway, "could not retrieve identity from Cl@ve")
	}

	identity := clave.ParseUserInfo(rawClaims)
	if identity.Sub == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "Cl@ve did not return a valid identity (missing sub)")
	}

	orgID, _ := uuid.Parse(loginSess.OrgID)
	user, err := h.users.GetByEmail(ctx, orgID, identity.Email)
	if err != nil {
		if !provider.AllowJIT {
			return echo.NewHTTPError(http.StatusForbidden, "automatic user provisioning is not enabled for this organisation")
		}
		fn := &identity.FirstName
		ln := &identity.LastName
		user, err = h.users.Create(ctx, orgID, identity.Email, fn, ln)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Cl@ve user provisioning failed")
		}
		applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
		log.Info().Str("sub", identity.Sub).Str("org_id", orgID.String()).Msg("clave: jit provisioned user")
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "account disabled")
	}

	// OpenID Connect for Identity Assurance 1.0: store Cl@ve verification evidence.
	storeIDAMetadata(h.users, user.ID, claveIDAMetadata())

	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + stateData.OrgSlug + "/authorize/resume?login_session_id=" + stateData.LoginSessionID
	return c.Redirect(http.StatusFound, resumeURL)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func buildClaveRedirectURI(c echo.Context, orgSlug, idpID string) string {
	scheme := "http"
	if c.Request().TLS != nil || c.Request().Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/%s/clave/%s/callback", scheme, c.Request().Host, orgSlug, idpID)
}

func claveEnvFromTokenURL(tokenURL string) string {
	if strings.Contains(tokenURL, "preprod") {
		return "preproduction"
	}
	return "production"
}

func fetchClaveUserInfo(ctx context.Context, userinfoURL, accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clave userinfo: status %d", resp.StatusCode)
	}
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
