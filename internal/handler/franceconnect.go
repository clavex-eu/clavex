package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/clavex-eu/clavex/internal/franceconnect"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// FranceConnectHandler handles FranceConnect v2 OIDC authentication.
// FranceConnect uses OIDC Authorization Code Flow with PKCE (S256) and nonce.
// The `sub` claim is pseudonymous and per-SP — it is stored as ExternalID on the user.
type FranceConnectHandler struct {
	idpRepo *repository.IDPRepository
	users   *repository.UserRepository
	orgs    *repository.OrgRepository
	store   *session.Store
	oid4w   *repository.OID4WRepository
	baseURL string // e.g. "https://auth.example.com" — used to build credential_offer_uri
}

func NewFranceConnectHandler(pool *pgxpool.Pool, store *session.Store, baseURL string) *FranceConnectHandler {
	return &FranceConnectHandler{
		idpRepo: repository.NewIDPRepository(pool),
		users:   repository.NewUserRepository(pool),
		orgs:    repository.NewOrgRepository(pool),
		store:   store,
		oid4w:   repository.NewOID4WRepository(pool),
		baseURL: baseURL,
	}
}

// ── Admin CRUD (provider_type = "franceconnect") ───────────────────────────────

type createFCRequest struct {
	Name         string `json:"name"          validate:"required,min=1,max=128"`
	ClientID     string `json:"client_id"     validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
	// Environment: "sandbox" (default, public) or "production" (requires DINUM approval).
	Environment string `json:"environment" validate:"required,oneof=sandbox production"`
	// AcrValues selects the eIDAS assurance level: "eidas1" | "eidas2" | "eidas3".
	// Defaults to "eidas1" if omitted.
	AcrValues string `json:"acr_values"`
	AllowJIT  bool   `json:"allow_jit"`
	IsActive  bool   `json:"is_active"`
}

// CreateFC registers a FranceConnect provider for an org.
// POST /api/v1/organizations/:org_id/franceconnect
func (h *FranceConnectHandler) CreateFC(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createFCRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.AcrValues == "" {
		req.AcrValues = "eidas1"
	}

	eps := franceconnect.GetEndpoints(req.Environment)
	userinfoURL := eps.UserinfoURL

	// Store acr_values in the Scopes field as a space-separated extra string for simplicity.
	// The handler reads it back at SSO start time.
	scopes := franceconnect.DefaultScopes

	p := &models.IdentityProvider{
		OrgID:            orgID,
		Name:             req.Name,
		ProviderType:     "franceconnect",
		ClientID:         req.ClientID,
		AuthorizationURL: eps.AuthorizationURL,
		TokenURL:         eps.TokenURL,
		UserinfoURL:      &userinfoURL,
		Scopes:           scopes,
		EmailClaim:       franceconnect.DefaultClaimMapping.EmailClaim,
		FirstNameClaim:   franceconnect.DefaultClaimMapping.FirstNameClaim,
		LastNameClaim:    franceconnect.DefaultClaimMapping.LastNameClaim,
		IsActive:         req.IsActive,
		AllowJIT:         req.AllowJIT,
		RoleClaimMappings: map[string]string{
			// Store acr_values in role claim mappings extra field as a workaround.
			"__acr_values__": req.AcrValues,
		},
	}

	created, err := h.idpRepo.Create(c.Request().Context(), p, req.ClientSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "provider name already exists for this organization")
	}
	return c.JSON(http.StatusCreated, created)
}

// ── OIDC SSO flow ──────────────────────────────────────────────────────────────

// StartSSO initiates the FranceConnect OIDC flow using PKCE+nonce.
// GET /:org_slug/franceconnect/:idp_id?login_session_id=...
func (h *FranceConnectHandler) StartSSO(c echo.Context) error {
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
	if err != nil || !provider.IsActive || provider.ProviderType != "franceconnect" {
		return echo.NewHTTPError(http.StatusNotFound, "FranceConnect provider not found or inactive")
	}

	codeVerifier := newCIERandom(43)
	state := newCIERandom(24)
	nonce := newCIERandom(24)

	redirectURI := buildFCRedirectURI(c, orgSlug, idpIDStr)
	env := franceconnect.EnvFromTokenURL(provider.TokenURL)

	acrValues := "eidas1"
	if v, ok := provider.RoleClaimMappings["__acr_values__"]; ok && v != "" {
		acrValues = v
	}

	authURL, _ := franceconnect.BuildAuthzURL(env, provider.ClientID, redirectURI, state, nonce, codeVerifier, acrValues)

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

// CallbackSSO handles the FranceConnect OIDC callback.
// GET /:org_slug/franceconnect/:idp_id/callback?code=...&state=...
func (h *FranceConnectHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idpIDStr := c.Param("idp_id")
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	if state == "" || code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing state or code")
	}

	stateData, err := h.store.GetIDPState(ctx, state)
	if err != nil || stateData == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "FranceConnect session expired — please try again")
	}
	if stateData.ProviderID != idpIDStr {
		return echo.NewHTTPError(http.StatusBadRequest, "state mismatch")
	}

	loginSess, err := h.store.GetLoginSession(ctx, stateData.LoginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired")
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

	redirectURI := buildFCRedirectURI(c, stateData.OrgSlug, idpIDStr)

	tokenResp, err := exchangeUpstreamCode(ctx, provider.TokenURL, provider.ClientID, clientSecret, code, redirectURI)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "token exchange with FranceConnect failed")
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "FranceConnect did not return an access token")
	}

	rawClaims, err := fetchFCUserInfo(ctx, *provider.UserinfoURL, accessToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "failed to fetch user info from FranceConnect")
	}

	fcUser := franceconnect.ParseUserInfo(rawClaims)
	if fcUser.Sub == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "FranceConnect did not return a valid identity")
	}

	// FranceConnect may not return an email if the user didn't consent to the email scope.
	// In that case we synthesise a stable placeholder to satisfy the user model's email constraint.
	email := fcUser.Email
	if email == "" {
		email = franceconnect.SynthesiseEmail(fcUser.Sub)
	}

	// Look up by external_id (FC sub) first; fall back to email for existing users
	// who may have linked their account before sub-based lookup was added.
	user, err := h.users.GetByExternalID(ctx, orgID, "franceconnect", fcUser.Sub)
	if err != nil {
		// Fallback: try email lookup (handles first-time login for existing users).
		user, err = h.users.GetByEmail(ctx, orgID, email)
		if err != nil {
			if !provider.AllowJIT {
				return echo.NewHTTPError(http.StatusForbidden, "automatic provisioning not enabled for this organization")
			}
			fn := &fcUser.FirstName
			ln := &fcUser.LastName
			user, err = h.users.CreateWithExternalID(ctx, orgID, email, fn, ln, "franceconnect", fcUser.Sub)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "FranceConnect JIT provisioning failed")
			}
			applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
			log.Info().Str("sub", fcUser.Sub).Str("org_id", orgID.String()).Msg("franceconnect: jit provisioned user")
		}
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "account disabled")
	}

	// OpenID Connect for Identity Assurance 1.0: store FranceConnect verification evidence.
	storeIDAMetadata(h.users, user.ID, franceConnectIDAMetadata())

	// Persist extended FC identity claims (birthdate, gender, etc.) in user metadata
	// so the OID4VCI issuance pipeline can include them in credentials via ClaimsMapping.
	storeFCIdentityClaims(h.users, user.ID, fcUser)

	// If the org has credential configs linked to "franceconnect", automatically
	// create a pre-authorized credential offer for each one.
	offerURIs := createIdpCredentialOffers(ctx, h.oid4w, h.baseURL, orgID, user, loginSess.OrgSlug, "franceconnect")

	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + stateData.OrgSlug + "/authorize/resume?login_session_id=" + stateData.LoginSessionID
	if len(offerURIs) > 0 {
		// Embed the first credential offer URI in the redirect so the authorize/resume
		// handler can present it to the wallet or include it in the OIDC response.
		resumeURL += "&credential_offer_uri=" + url.QueryEscape(offerURIs[0])
	}
	return c.Redirect(http.StatusFound, resumeURL)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func buildFCRedirectURI(c echo.Context, orgSlug, idpID string) string {
	scheme := "http"
	if c.Request().TLS != nil || c.Request().Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/%s/franceconnect/%s/callback", scheme, c.Request().Host, orgSlug, idpID)
}

func fetchFCUserInfo(ctx context.Context, userinfoURL, accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := upstreamHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("franceconnect userinfo: status %d", resp.StatusCode)
	}
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// storeFCIdentityClaims persists the verified identity claims returned by FranceConnect
// into user metadata under the "fc_*" namespace. These claims are later surfaced in
// OID4VCI credentials via ClaimsMapping (e.g. "birthdate" → "metadata.fc_birthdate").
// The update runs in a goroutine to not block the authentication flow.
func storeFCIdentityClaims(users *repository.UserRepository, userID uuid.UUID, fc *franceconnect.FCUserInfo) {
	patch := map[string]interface{}{}
	if fc.Birthdate != "" {
		patch["fc_birthdate"] = fc.Birthdate
	}
	if fc.Gender != "" {
		patch["fc_gender"] = fc.Gender
	}
	if fc.Birthplace != "" {
		patch["fc_birthplace"] = fc.Birthplace
	}
	if fc.Birthcountry != "" {
		patch["fc_birthcountry"] = fc.Birthcountry
	}
	if len(patch) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := users.MergeMetadata(ctx, userID, patch); err != nil {
			log.Warn().Err(err).Str("user_id", userID.String()).Msg("franceconnect: failed to store identity claims in user metadata")
		}
	}()
}
