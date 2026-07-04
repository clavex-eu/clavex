package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/cie"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// CIEHandler handles CIE (Carta d'Identità Elettronica) OIDC authentication.
// CIE uses a standard OIDC Authorization Code Flow with PKCE (S256) and nonce.
type CIEHandler struct {
	idpRepo *repository.IDPRepository
	users   *repository.UserRepository
	orgs    *repository.OrgRepository
	store   *session.Store
	oid4w   *repository.OID4WRepository
	baseURL string
}

func NewCIEHandler(pool *pgxpool.Pool, store *session.Store, baseURL string) *CIEHandler {
	return &CIEHandler{
		idpRepo: repository.NewIDPRepository(pool),
		users:   repository.NewUserRepository(pool),
		orgs:    repository.NewOrgRepository(pool),
		store:   store,
		oid4w:   repository.NewOID4WRepository(pool),
		baseURL: baseURL,
	}
}

// ── Admin CRUD (provider_type = "cie") ────────────────────────────────────────
// CIE is registered as a normal IdentityProvider row with provider_type="cie".
// The admin only needs to provide: client_id, client_secret, environment (prod|preprod),
// allow_jit, is_active. Authorization/Token URLs are hardcoded by environment.

type createCIERequest struct {
	Name         string `json:"name"         validate:"required,min=1,max=128"`
	ClientID     string `json:"client_id"    validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
	Environment  string `json:"environment"  validate:"required,oneof=production preproduction"`
	AllowJIT     bool   `json:"allow_jit"`
	IsActive     bool   `json:"is_active"`
}

// CreateCIE registers a CIE provider for an org.
// POST /api/v1/organizations/:org_id/cie
func (h *CIEHandler) CreateCIE(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createCIERequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	eps := cie.GetEndpoints(req.Environment)
	userinfoURL := eps.UserinfoURL

	p := &models.IdentityProvider{
		OrgID:             orgID,
		Name:              req.Name,
		ProviderType:      "cie",
		ClientID:          req.ClientID,
		AuthorizationURL:  eps.AuthorizationURL,
		TokenURL:          eps.TokenURL,
		UserinfoURL:       &userinfoURL,
		Scopes:            cie.DefaultScopes,
		EmailClaim:        cie.DefaultClaimMapping.EmailClaim,
		FirstNameClaim:    cie.DefaultClaimMapping.FirstNameClaim,
		LastNameClaim:     cie.DefaultClaimMapping.LastNameClaim,
		IsActive:          req.IsActive,
		AllowJIT:          req.AllowJIT,
		RoleClaimMappings: map[string]string{},
	}

	created, err := h.idpRepo.Create(c.Request().Context(), p, req.ClientSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "provider name already exists for this organization")
	}
	return c.JSON(http.StatusCreated, created)
}

// ── OIDC SSO flow ──────────────────────────────────────────────────────────────

// StartSSO initiates the CIE OIDC flow using PKCE+nonce.
// GET /:org_slug/cie/:idp_id?login_session_id=...
func (h *CIEHandler) StartSSO(c echo.Context) error {
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
	if err != nil || !provider.IsActive || provider.ProviderType != "cie" {
		return echo.NewHTTPError(http.StatusNotFound, "CIE provider not found or inactive")
	}

	// Generate PKCE code verifier + state + nonce.
	codeVerifier := newCIERandom(43) // 43-char verifier per RFC 7636
	state := newCIERandom(24)
	nonce := newCIERandom(24)

	redirectURI := buildCIERedirectURI(c, orgSlug, idpIDStr)

	// Build auth URL (environment is derived from the stored TokenURL prefix).
	env := cieEnvFromTokenURL(provider.TokenURL)
	authURL, _ := cie.BuildAuthzURL(env, provider.ClientID, redirectURI, state, nonce, codeVerifier)

	// Persist state for callback validation.
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

// CallbackSSO handles the CIE OIDC callback.
// GET /:org_slug/cie/:idp_id/callback?code=...&state=...
func (h *CIEHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idpIDStr := c.Param("idp_id")
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	if state == "" || code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "parametri mancanti (state, code)")
	}

	stateData, err := h.store.GetIDPState(ctx, state)
	if err != nil || stateData == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "sessione CIE scaduta — riprovare")
	}
	if stateData.ProviderID != idpIDStr {
		return echo.NewHTTPError(http.StatusBadRequest, "state mismatch")
	}

	loginSess, err := h.store.GetLoginSession(ctx, stateData.LoginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "sessione di login scaduta")
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

	redirectURI := buildCIERedirectURI(c, stateData.OrgSlug, idpIDStr)

	// Exchange code → tokens (PKCE: include code_verifier, no client_secret in body per some implementations).
	tokenResp, err := exchangeCIECode(ctx, provider.TokenURL, provider.ClientID, clientSecret, code, redirectURI, stateData.CodeVerifier)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "scambio token con CIE fallito")
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "CIE non ha restituito un access token")
	}

	// Fetch userinfo.
	rawClaims, err := fetchCIEUserInfo(ctx, *provider.UserinfoURL, accessToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "impossibile ottenere i dati utente da CIE")
	}

	cieUser := cie.ParseUserInfo(rawClaims)
	if cieUser.FiscalNumber == "" && cieUser.Email == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "CIE non ha restituito dati di identità validi")
	}

	user, err := h.users.GetByEmail(ctx, orgID, cieUser.Email)
	if err != nil {
		if !provider.AllowJIT {
			return echo.NewHTTPError(http.StatusForbidden, "provisioning automatico non abilitato per questa organizzazione")
		}
		fn := &cieUser.FirstName
		ln := &cieUser.LastName
		user, err = h.users.Create(ctx, orgID, cieUser.Email, fn, ln)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "provisioning utente CIE fallito")
		}
		applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
		log.Info().Str("fiscal_number", cieUser.FiscalNumber).Str("org_id", orgID.String()).Msg("cie: jit provisioned user")
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "account disabilitato")
	}

	// OpenID Connect for Identity Assurance 1.0: store CIE verification evidence.
	// CIE is always eIDAS High assurance.
	storeIDAMetadata(h.users, user.ID, cieIDAMetadata())

	// Persist CIE verified identity claims in user metadata so the OID4VCI
	// issuance pipeline can include them via ClaimsMapping (e.g.
	// "fiscalNumber" → "metadata.cie_fiscal_number").
	storeCIEIdentityClaims(h.users, user.ID, cieUser)

	// Auto-create pre-authorized credential offers for any credential config
	// linked to source_idp_type = "cie" in this org.
	offerURIs := createIdpCredentialOffers(ctx, h.oid4w, h.baseURL, orgID, user, stateData.OrgSlug, "cie")

	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	loginSess.LastCIEProviderID = idpIDStr
	// Clear the upgrade flag if this callback is completing an in-session upgrade.
	loginSess.RequiredCIEUpgrade = false
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + stateData.OrgSlug + "/authorize/resume?login_session_id=" + stateData.LoginSessionID
	if len(offerURIs) > 0 {
		resumeURL += "&credential_offer_uri=" + url.QueryEscape(offerURIs[0])
	}
	return c.Redirect(http.StatusFound, resumeURL)
}

// UpgradeSSO initiates an in-session CIE re-authentication to raise the user's
// assurance_level to eIDAS High (triggered by a check_verified flow step with
// upgrade:"cie"). The session must have RequiredCIEUpgrade=true.
//
// If LastCIEProviderID is set the user is silently redirected to the same
// provider; otherwise the first active CIE provider for the org is used.
//
// GET /:org_slug/cie/upgrade?login_session_id=...
func (h *CIEHandler) UpgradeSSO(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	loginSessionID := c.QueryParam("login_session_id")
	if loginSessionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}

	loginSess, err := h.store.GetLoginSession(ctx, loginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "sessione scaduta — riprovare dall'inizio")
	}
	if !loginSess.RequiredCIEUpgrade {
		return echo.NewHTTPError(http.StatusBadRequest, "nessun upgrade CIE in corso per questa sessione")
	}

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.ErrNotFound
	}

	// Find the CIE provider to use: prefer the last used one, else first active.
	var provider *models.IdentityProvider
	if loginSess.LastCIEProviderID != "" {
		if pid, err := uuid.Parse(loginSess.LastCIEProviderID); err == nil {
			p, err := h.idpRepo.GetForOrg(ctx, pid, org.ID)
			if err == nil && p != nil && p.IsActive && p.ProviderType == "cie" {
				provider = p
			}
		}
	}
	if provider == nil {
		// Fall back to first active CIE provider for this org.
		all, err := h.idpRepo.ListActivePromoted(ctx, org.ID)
		if err != nil {
			return echo.ErrInternalServerError
		}
		for _, p := range all {
			if p.ProviderType == "cie" {
				provider = p
				break
			}
		}
	}
	if provider == nil {
		return echo.NewHTTPError(http.StatusNotFound, "nessun provider CIE attivo per questa organizzazione")
	}

	// Generate PKCE + state + nonce for the upgrade auth request.
	codeVerifier := newCIERandom(43)
	state := newCIERandom(24)
	nonce := newCIERandom(24)
	redirectURI := buildCIERedirectURI(c, orgSlug, provider.ID.String())

	env := cieEnvFromTokenURL(provider.TokenURL)
	authURL, _ := cie.BuildAuthzURL(env, provider.ClientID, redirectURI, state, nonce, codeVerifier)

	if err := h.store.SaveIDPState(ctx, state, &session.IDPState{
		ProviderID:     provider.ID.String(),
		LoginSessionID: loginSessionID,
		OrgSlug:        orgSlug,
		CodeVerifier:   codeVerifier,
		Nonce:          nonce,
	}); err != nil {
		return echo.ErrInternalServerError
	}

	return c.Redirect(http.StatusFound, authURL)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func buildCIERedirectURI(c echo.Context, orgSlug, idpID string) string {
	scheme := "http"
	if c.Request().TLS != nil || c.Request().Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/%s/cie/%s/callback", scheme, c.Request().Host, orgSlug, idpID)
}

// cieEnvFromTokenURL infers the CIE environment from the token endpoint URL.
func cieEnvFromTokenURL(tokenURL string) string {
	if strings.Contains(tokenURL, "preproduzione") {
		return "preproduction"
	}
	return "production"
}

// exchangeCIECode exchanges an authorization code for CIE tokens using PKCE.
func exchangeCIECode(ctx context.Context, tokenURL, clientID, clientSecret, code, redirectURI, codeVerifier string) (map[string]interface{}, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}
	// CIE supports client_secret_basic; pass secret only if non-empty.
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	return exchangeUpstreamCode(ctx, tokenURL, clientID, clientSecret, code, redirectURI)
}

// fetchCIEUserInfo fetches userinfo claims from the CIE userinfo endpoint.
func fetchCIEUserInfo(ctx context.Context, userinfoURL, accessToken string) (map[string]interface{}, error) {
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cie userinfo: status %d", resp.StatusCode)
	}
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// newCIERandom generates a cryptographically random URL-safe string of length n.
func newCIERandom(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// storeCIEIdentityClaims persists the verified CIE identity claims in user
// metadata under the "cie_*" namespace for later use by OID4VCI ClaimsMapping.
// The update runs in a goroutine so it does not block the authentication flow.
func storeCIEIdentityClaims(users *repository.UserRepository, userID uuid.UUID, u *cie.CIEUserInfo) {
	patch := map[string]interface{}{
		"cie_fiscal_number": u.FiscalNumber,
		"cie_name":          u.FirstName,
		"cie_family_name":   u.LastName,
	}
	if u.DateOfBirth != "" {
		patch["cie_date_of_birth"] = u.DateOfBirth
	}
	if u.Gender != "" {
		patch["cie_gender"] = u.Gender
	}
	if !u.EmailSynthetic && u.Email != "" {
		patch["cie_email"] = u.Email
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := users.MergeMetadata(bctx, userID, patch); err != nil {
			log.Warn().Err(err).Str("user_id", userID.String()).
				Msg("cie: failed to store identity claims in user metadata")
		}
	}()
}
