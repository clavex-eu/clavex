package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/bundid"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/tracing"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
)

// BundIDHandler handles BundID (German federal eID) OIDC authentication.
// BundID uses a standard OIDC Authorization Code Flow with PKCE (S256) and nonce.
//
// Registration: https://id.bund.de/de/fuer-dienstleister/registrierung
// FITKO test system (integration): https://int.id.bund.de/oidc
type BundIDHandler struct {
	idpRepo *repository.IDPRepository
	users   *repository.UserRepository
	orgs    *repository.OrgRepository
	store   *session.Store
}

func NewBundIDHandler(pool *pgxpool.Pool, store *session.Store) *BundIDHandler {
	return &BundIDHandler{
		idpRepo: repository.NewIDPRepository(pool),
		users:   repository.NewUserRepository(pool),
		orgs:    repository.NewOrgRepository(pool),
		store:   store,
	}
}

// ── Admin CRUD (provider_type = "bundid") ─────────────────────────────────────
// BundID is stored as a normal IdentityProvider row.
// The admin provides: client_id, client_secret, environment (production|integration),
// assurance_level (optional), allow_jit, is_active.
// Authorization/Token URLs are hardcoded per environment.

type createBundIDRequest struct {
	Name         string `json:"name"            validate:"required,min=1,max=128"`
	ClientID     string `json:"client_id"       validate:"required"`
	ClientSecret string `json:"client_secret"   validate:"required"`
	// Environment selects the BundID endpoint set.
	// "production" → id.bund.de, "integration" → int.id.bund.de (FITKO test)
	Environment string `json:"environment"     validate:"required,oneof=production integration"`
	// AssuranceLevel is the acr_values to request. Leave empty to let BundID choose.
	// Use bundid.LoAHigh ("https://www.authenticationlevel.bund.de/ns/eID/internet")
	// for Online-Ausweis / nPA. Use bundid.LoASubstantial for username+password.
	AssuranceLevel string `json:"assurance_level"`
	AllowJIT       bool   `json:"allow_jit"`
	IsActive       bool   `json:"is_active"`
}

// CreateBundID registers a BundID provider for an org.
// POST /api/v1/organizations/:org_id/bundid
func (h *BundIDHandler) CreateBundID(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createBundIDRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	eps := bundid.GetEndpoints(req.Environment)
	userinfoURL := eps.UserinfoURL

	p := &models.IdentityProvider{
		OrgID:             orgID,
		Name:              req.Name,
		ProviderType:      "bundid",
		ClientID:          req.ClientID,
		AuthorizationURL:  eps.AuthorizationURL,
		TokenURL:          eps.TokenURL,
		UserinfoURL:       &userinfoURL,
		Scopes:            bundid.DefaultScopes,
		EmailClaim:        bundid.DefaultClaimMapping.EmailClaim,
		FirstNameClaim:    bundid.DefaultClaimMapping.FirstNameClaim,
		LastNameClaim:     bundid.DefaultClaimMapping.LastNameClaim,
		IsActive:          req.IsActive,
		AllowJIT:          req.AllowJIT,
		RoleClaimMappings: map[string]string{},
	}
	// Persist the assurance level in provider metadata for use in StartSSO.
	if req.AssuranceLevel != "" {
		p.RoleClaimMappings["__assurance_level__"] = req.AssuranceLevel
	}

	created, err := h.idpRepo.Create(c.Request().Context(), p, req.ClientSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "provider name already exists for this organization")
	}
	return c.JSON(http.StatusCreated, created)
}

// ── OIDC SSO flow ──────────────────────────────────────────────────────────────

// StartSSO initiates the BundID OIDC flow using PKCE + nonce.
// GET /:org_slug/bundid/:idp_id?login_session_id=...
func (h *BundIDHandler) StartSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idpIDStr := c.Param("idp_id")
	loginSessionID := c.QueryParam("login_session_id")
	orgSlug := c.Param("org_slug")

	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.bundid.start_sso")
	defer span.End()
	span.SetAttributes(
		attribute.String("org_slug", orgSlug),
		attribute.String("idp_id", idpIDStr),
	)

	if loginSessionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}
	providerID, err := uuid.Parse(idpIDStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid idp_id")
	}

	// Cross-tenant guard: bind the provider to the login session's org so an
	// IdP registered in another tenant cannot be used to authenticate here.
	loginSess, err := h.store.GetLoginSession(ctx, loginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please restart the login")
	}
	orgID, err := uuid.Parse(loginSess.OrgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	provider, err := h.idpRepo.GetForOrg(ctx, providerID, orgID)
	if err != nil || !provider.IsActive || provider.ProviderType != "bundid" {
		return echo.NewHTTPError(http.StatusNotFound, "BundID provider not found or inactive")
	}

	codeVerifier := newCIERandom(43)
	state := newCIERandom(24)
	nonce := newCIERandom(24)

	redirectURI := buildBundIDRedirectURI(c, orgSlug, idpIDStr)
	env := bundidEnvFromTokenURL(provider.TokenURL)

	acrValues := provider.RoleClaimMappings["__assurance_level__"]

	authURL := bundid.BuildAuthzURL(env, provider.ClientID, redirectURI, state, nonce, codeVerifier, acrValues)

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

// CallbackSSO handles the BundID OIDC callback.
// GET /:org_slug/bundid/:idp_id/callback?code=...&state=...
func (h *BundIDHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idpIDStr := c.Param("idp_id")
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.bundid.callback_sso")
	defer span.End()
	span.SetAttributes(attribute.String("idp_id", idpIDStr))

	if state == "" || code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing state or code parameters")
	}

	stateData, err := h.store.GetIDPState(ctx, state)
	if err != nil || stateData == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "BundID session expired — please restart the login")
	}
	if stateData.ProviderID != idpIDStr {
		return echo.NewHTTPError(http.StatusBadRequest, "state mismatch")
	}

	loginSess, err := h.store.GetLoginSession(ctx, stateData.LoginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please restart the login")
	}

	orgID, err := uuid.Parse(loginSess.OrgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	providerID, _ := uuid.Parse(stateData.ProviderID)
	// Cross-tenant guard: the provider must belong to the login session's org.
	provider, err := h.idpRepo.GetForOrg(ctx, providerID, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	clientSecret, _, _, _, err := h.idpRepo.GetClientSecret(ctx, provider.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	redirectURI := buildBundIDRedirectURI(c, stateData.OrgSlug, idpIDStr)

	tokenResp, err := exchangeUpstreamCode(ctx, provider.TokenURL, provider.ClientID, clientSecret, code, redirectURI)
	if err != nil {
		log.Warn().Err(err).Str("provider_id", idpIDStr).Msg("bundid: token exchange failed")
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "token exchange failed")
		return echo.NewHTTPError(http.StatusBadGateway, "BundID token exchange failed")
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "BundID did not return an access token")
	}

	rawClaims, err := fetchBundIDUserInfo(ctx, *provider.UserinfoURL, accessToken)
	if err != nil {
		log.Warn().Err(err).Str("provider_id", idpIDStr).Msg("bundid: userinfo fetch failed")
		return echo.NewHTTPError(http.StatusBadGateway, "could not retrieve identity from BundID")
	}

	identity := bundid.ParseUserInfo(rawClaims)
	if identity.Sub == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "BundID did not return a valid identity (missing sub)")
	}

	user, err := h.users.GetByEmail(ctx, orgID, identity.Email)
	if err != nil {
		if !provider.AllowJIT {
			return echo.NewHTTPError(http.StatusForbidden, "automatic user provisioning is not enabled for this organisation")
		}
		fn := &identity.FirstName
		ln := &identity.LastName
		user, err = h.users.Create(ctx, orgID, identity.Email, fn, ln)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "BundID user provisioning failed")
		}
		applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
		log.Info().Str("sub", identity.Sub).Str("org_id", orgID.String()).Msg("bundid: jit provisioned user")
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "account disabled")
	}

	// OpenID Connect for Identity Assurance 1.0: store BundID verification evidence.
	bundIDLoA := provider.RoleClaimMappings["__assurance_level__"]
	storeIDAMetadata(h.users, user.ID, bundIDOIDCIDAMetadata(bundIDLoA))

	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + stateData.OrgSlug + "/authorize/resume?login_session_id=" + stateData.LoginSessionID
	span.SetAttributes(attribute.String("org_slug", stateData.OrgSlug))
	return c.Redirect(http.StatusFound, resumeURL)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func buildBundIDRedirectURI(c echo.Context, orgSlug, idpID string) string {
	scheme := "http"
	if c.Request().TLS != nil || c.Request().Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/%s/bundid/%s/callback", scheme, c.Request().Host, orgSlug, idpID)
}

// bundidEnvFromTokenURL infers the BundID environment from the stored token endpoint URL.
func bundidEnvFromTokenURL(tokenURL string) string {
	if strings.Contains(tokenURL, "int.id.bund.de") {
		return "integration"
	}
	return "production"
}

func fetchBundIDUserInfo(ctx context.Context, userinfoURL, accessToken string) (map[string]interface{}, error) {
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
		return nil, fmt.Errorf("bundid userinfo: status %d", resp.StatusCode)
	}
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
