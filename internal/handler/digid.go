package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/digid"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// DigiDHandler handles DigiD (Dutch national digital identity) OIDC authentication.
// DigiD uses OIDC Authorization Code Flow with PKCE (S256) and nonce.
// Note: DigiD only releases BSN + assurance level — NOT name or email.
// Enrich user data from BRP (Basisregistratie Personen) after authentication.
//
// Registration: https://www.logius.nl/diensten/digid
// Acceptance (pre-production): https://authenticatie-machtigen.acc.digid.nl
type DigiDHandler struct {
	idpRepo *repository.IDPRepository
	users   *repository.UserRepository
	orgs    *repository.OrgRepository
	store   *session.Store
}

func NewDigiDHandler(pool *pgxpool.Pool, store *session.Store) *DigiDHandler {
	return &DigiDHandler{
		idpRepo: repository.NewIDPRepository(pool),
		users:   repository.NewUserRepository(pool),
		orgs:    repository.NewOrgRepository(pool),
		store:   store,
	}
}

// ── Admin CRUD (provider_type = "digid") ──────────────────────────────────────

type createDigiDRequest struct {
	Name         string `json:"name"          validate:"required,min=1,max=128"`
	ClientID     string `json:"client_id"     validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
	// Environment: "production" or "acceptance"
	Environment string `json:"environment" validate:"required,oneof=production acceptance"`
	// AssuranceLevel is the minimum DigiD level required (acr_values).
	// Leave empty to let DigiD choose. Supported values:
	//   digid.LoA2 — DigiD Midden (SMS OTP, ~eIDAS Low+)
	//   digid.LoA3 — DigiD Substantieel (DigiD app, eIDAS Substantial)
	//   digid.LoA4 — DigiD Hoog (NFC ID card / rijbewijs, eIDAS High)
	AssuranceLevel string `json:"assurance_level"`
	AllowJIT       bool   `json:"allow_jit"`
	IsActive       bool   `json:"is_active"`
}

// CreateDigiD registers a DigiD provider for an org.
// POST /api/v1/organizations/:org_id/digid
func (h *DigiDHandler) CreateDigiD(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createDigiDRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	eps := digid.GetEndpoints(req.Environment)
	userinfoURL := eps.UserinfoURL

	p := &models.IdentityProvider{
		OrgID:            orgID,
		Name:             req.Name,
		ProviderType:     "digid",
		ClientID:         req.ClientID,
		AuthorizationURL: eps.AuthorizationURL,
		TokenURL:         eps.TokenURL,
		UserinfoURL:      &userinfoURL,
		Scopes:           digid.DefaultScopes,
		// DigiD does not release email, name, or address directly.
		// Use BSN claim as the primary identifier; name comes from BRP.
		EmailClaim:        "sub", // internal: we synthesise email from BSN hash
		FirstNameClaim:    "",    // not available — must fetch from BRP
		LastNameClaim:     "",    // not available — must fetch from BRP
		IsActive:          req.IsActive,
		AllowJIT:          req.AllowJIT,
		RoleClaimMappings: map[string]string{},
	}
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

// StartSSO initiates the DigiD OIDC flow using PKCE + nonce.
// GET /:org_slug/digid/:idp_id?login_session_id=...
func (h *DigiDHandler) StartSSO(c echo.Context) error {
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
	if err != nil || !provider.IsActive || provider.ProviderType != "digid" {
		return echo.NewHTTPError(http.StatusNotFound, "DigiD provider not found or inactive")
	}

	codeVerifier := newCIERandom(43)
	state := newCIERandom(24)
	nonce := newCIERandom(24)

	redirectURI := buildDigiDRedirectURI(c, orgSlug, idpIDStr)
	env := digidEnvFromTokenURL(provider.TokenURL)

	acrValues := provider.RoleClaimMappings["__assurance_level__"]

	authURL := digid.BuildAuthzURL(env, provider.ClientID, redirectURI, state, nonce, codeVerifier, acrValues)

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

// CallbackSSO handles the DigiD OIDC callback.
// GET /:org_slug/digid/:idp_id/callback?code=...&state=...
func (h *DigiDHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idpIDStr := c.Param("idp_id")
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	if state == "" || code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing state or code parameters")
	}

	stateData, err := h.store.GetIDPState(ctx, state)
	if err != nil || stateData == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "DigiD session expired — please restart the login")
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

	redirectURI := buildDigiDRedirectURI(c, stateData.OrgSlug, idpIDStr)

	tokenResp, err := exchangeUpstreamCode(ctx, provider.TokenURL, provider.ClientID, clientSecret, code, redirectURI)
	if err != nil {
		log.Warn().Err(err).Str("provider_id", idpIDStr).Msg("digid: token exchange failed")
		return echo.NewHTTPError(http.StatusBadGateway, "DigiD token exchange failed")
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "DigiD did not return an access token")
	}

	rawClaims, err := fetchDigiDUserInfo(ctx, *provider.UserinfoURL, accessToken)
	if err != nil {
		log.Warn().Err(err).Str("provider_id", idpIDStr).Msg("digid: userinfo fetch failed")
		return echo.NewHTTPError(http.StatusBadGateway, "could not retrieve identity from DigiD")
	}

	identity := digid.ParseUserInfo(rawClaims)
	if identity.Sub == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "DigiD did not return a valid identity (missing sub)")
	}

	orgID, _ := uuid.Parse(loginSess.OrgID)

	// DigiD does not release name — use empty strings for JIT provisioning.
	// The calling application should enrich the user record from BRP using the BSN.
	user, err := h.users.GetByEmail(ctx, orgID, identity.Email)
	if err != nil {
		if !provider.AllowJIT {
			return echo.NewHTTPError(http.StatusForbidden, "automatic user provisioning is not enabled for this organisation")
		}
		// No name available from DigiD; the service must enrich from BRP.
		emptyName := ""
		user, err = h.users.Create(ctx, orgID, identity.Email, &emptyName, &emptyName)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "DigiD user provisioning failed")
		}
		applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
		log.Info().
			Str("sub", identity.Sub).
			Str("bsn_hash", digid.HashBSN(identity.BSN)).
			Str("org_id", orgID.String()).
			Msg("digid: jit provisioned user — enrich from BRP")
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "account disabled")
	}

	// OpenID Connect for Identity Assurance 1.0: store DigiD verification evidence.
	storeIDAMetadata(h.users, user.ID, digiDIDAMetadata())

	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + stateData.OrgSlug + "/authorize/resume?login_session_id=" + stateData.LoginSessionID
	return c.Redirect(http.StatusFound, resumeURL)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func buildDigiDRedirectURI(c echo.Context, orgSlug, idpID string) string {
	scheme := "http"
	if c.Request().TLS != nil || c.Request().Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/%s/digid/%s/callback", scheme, c.Request().Host, orgSlug, idpID)
}

func digidEnvFromTokenURL(tokenURL string) string {
	if strings.Contains(tokenURL, "acc.digid.nl") {
		return "acceptance"
	}
	return "production"
}

func fetchDigiDUserInfo(ctx context.Context, userinfoURL, accessToken string) (map[string]interface{}, error) {
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
		return nil, fmt.Errorf("digid userinfo: status %d", resp.StatusCode)
	}
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
