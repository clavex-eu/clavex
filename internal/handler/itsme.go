package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/itsme"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"
)

// ItsmeHandler handles itsme® OIDC authentication (Belgium / Luxembourg).
// itsme uses OIDC Authorization Code Flow with PKCE (S256) and nonce.
// Sandbox:    token endpoint accepts client_secret_post.
// Production: token endpoint requires private_key_jwt (RFC 7523) signed with RS256.
//             ItsmeHandler uses the Clavex signing KeySet for the assertion.
type ItsmeHandler struct {
	idpRepo *repository.IDPRepository
	users   *repository.UserRepository
	orgs    *repository.OrgRepository
	store   *session.Store
	keys    oidc.Signer // used for private_key_jwt assertion in production
}

func NewItsmeHandler(pool *pgxpool.Pool, store *session.Store, keys oidc.Signer) *ItsmeHandler {
	return &ItsmeHandler{
		idpRepo: repository.NewIDPRepository(pool),
		users:   repository.NewUserRepository(pool),
		orgs:    repository.NewOrgRepository(pool),
		store:   store,
		keys:    keys,
	}
}

// ── Admin CRUD (provider_type = "itsme") ──────────────────────────────────────

type createItsmeRequest struct {
	Name         string `json:"name"          validate:"required,min=1,max=128"`
	ClientID     string `json:"client_id"     validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
	// ServiceCode is the itsme service code assigned during onboarding (required).
	ServiceCode string `json:"service_code" validate:"required"`
	// Environment: "sandbox" (default) or "production".
	Environment string `json:"environment" validate:"required,oneof=sandbox production"`
	// AcrValues: use "http://eidas.europa.eu/LoA/low" (loa2) or "http://eidas.europa.eu/LoA/high" (loa3).
	AcrValues string `json:"acr_values"`
	AllowJIT  bool   `json:"allow_jit"`
	IsActive  bool   `json:"is_active"`
}

// CreateItsme registers an itsme provider for an org.
// POST /api/v1/organizations/:org_id/itsme
func (h *ItsmeHandler) CreateItsme(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createItsmeRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.AcrValues == "" {
		req.AcrValues = itsme.LoA2
	}

	eps := itsme.GetEndpoints(req.Environment)
	userinfoURL := eps.UserinfoURL

	p := &models.IdentityProvider{
		OrgID:            orgID,
		Name:             req.Name,
		ProviderType:     "itsme",
		ClientID:         req.ClientID,
		AuthorizationURL: eps.AuthorizationURL,
		TokenURL:         eps.TokenURL,
		UserinfoURL:      &userinfoURL,
		Scopes:           itsme.DefaultScopes,
		EmailClaim:       itsme.DefaultClaimMapping.EmailClaim,
		FirstNameClaim:   itsme.DefaultClaimMapping.FirstNameClaim,
		LastNameClaim:    itsme.DefaultClaimMapping.LastNameClaim,
		IsActive:         req.IsActive,
		AllowJIT:         req.AllowJIT,
		RoleClaimMappings: map[string]string{
			"__service_code__": req.ServiceCode,
			"__acr_values__":   req.AcrValues,
		},
	}

	created, err := h.idpRepo.Create(c.Request().Context(), p, req.ClientSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "provider name already exists for this organization")
	}
	return c.JSON(http.StatusCreated, created)
}

// ── OIDC SSO flow ──────────────────────────────────────────────────────────────

// StartSSO initiates the itsme OIDC flow using PKCE+nonce.
// GET /:org_slug/itsme/:idp_id?login_session_id=...
func (h *ItsmeHandler) StartSSO(c echo.Context) error {
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
	if err != nil || !provider.IsActive || provider.ProviderType != "itsme" {
		return echo.NewHTTPError(http.StatusNotFound, "itsme provider not found or inactive")
	}

	codeVerifier := newCIERandom(43)
	state := newCIERandom(24)
	nonce := newCIERandom(24)

	redirectURI := buildItsmeRedirectURI(c, orgSlug, idpIDStr)
	env := itsme.EnvFromTokenURL(provider.TokenURL)

	serviceCode := provider.RoleClaimMappings["__service_code__"]
	acrValues := provider.RoleClaimMappings["__acr_values__"]
	if acrValues == "" {
		acrValues = itsme.LoA2
	}

	authURL, _ := itsme.BuildAuthzURL(env, provider.ClientID, redirectURI, state, nonce, codeVerifier, serviceCode, acrValues)

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

// CallbackSSO handles the itsme OIDC callback.
// GET /:org_slug/itsme/:idp_id/callback?code=...&state=...
func (h *ItsmeHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idpIDStr := c.Param("idp_id")
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	if state == "" || code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing state or code")
	}

	stateData, err := h.store.GetIDPState(ctx, state)
	if err != nil || stateData == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "itsme session expired — please try again")
	}
	if stateData.ProviderID != idpIDStr {
		return echo.NewHTTPError(http.StatusBadRequest, "state mismatch")
	}

	loginSess, err := h.store.GetLoginSession(ctx, stateData.LoginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired")
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

	redirectURI := buildItsmeRedirectURI(c, stateData.OrgSlug, idpIDStr)

	// Route to the correct token exchange based on environment:
	//   sandbox    → client_secret_post  (standard)
	//   production → private_key_jwt     (RFC 7523, RS256)
	var tokenResp map[string]interface{}
	if itsme.EnvFromTokenURL(provider.TokenURL) == "production" {
		tokenResp, err = exchangeItsmeProduction(ctx, provider.TokenURL, provider.ClientID, code, redirectURI, h.keys)
	} else {
		tokenResp, err = exchangeUpstreamCode(ctx, provider.TokenURL, provider.ClientID, clientSecret, code, redirectURI)
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "token exchange with itsme failed")
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "itsme did not return an access token")
	}

	rawClaims, err := fetchItsmeUserInfo(ctx, *provider.UserinfoURL, accessToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "failed to fetch user info from itsme")
	}

	itsmeUser := itsme.ParseUserInfo(rawClaims)
	if itsmeUser.Sub == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "itsme did not return a valid identity")
	}

	orgID, _ := uuid.Parse(loginSess.OrgID)

	user, err := h.users.GetByExternalID(ctx, orgID, "itsme", itsmeUser.Sub)
	if err != nil {
		user, err = h.users.GetByEmail(ctx, orgID, itsmeUser.Email)
		if err != nil {
			if !provider.AllowJIT {
				return echo.NewHTTPError(http.StatusForbidden, "automatic provisioning not enabled for this organization")
			}
			fn := &itsmeUser.FirstName
			ln := &itsmeUser.LastName
			user, err = h.users.CreateWithExternalID(ctx, orgID, itsmeUser.Email, fn, ln, "itsme", itsmeUser.Sub)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "itsme JIT provisioning failed")
			}
			applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
			log.Info().Str("sub", itsmeUser.Sub).Str("org_id", orgID.String()).Msg("itsme: jit provisioned user")
		}
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "account disabled")
	}

	// OpenID Connect for Identity Assurance 1.0: store itsme verification evidence.
	itsmeLoA := provider.RoleClaimMappings["__acr_values__"]
	storeIDAMetadata(h.users, user.ID, itsmeIDAMetadata(itsmeLoA))

	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + stateData.OrgSlug + "/authorize/resume?login_session_id=" + stateData.LoginSessionID
	return c.Redirect(http.StatusFound, resumeURL)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func buildItsmeRedirectURI(c echo.Context, orgSlug, idpID string) string {
	scheme := "http"
	if c.Request().TLS != nil || c.Request().Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/%s/itsme/%s/callback", scheme, c.Request().Host, orgSlug, idpID)
}

func fetchItsmeUserInfo(ctx context.Context, userinfoURL, accessToken string) (map[string]interface{}, error) {
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
		return nil, fmt.Errorf("itsme userinfo: status %d", resp.StatusCode)
	}
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// exchangeItsmeProduction exchanges an authorization code at the itsme production
// token endpoint using a private_key_jwt client assertion (RFC 7523 §2.2).
//
// itsme production requires:
//   client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//   client_assertion      = RS256-signed JWT with iss=sub=client_id, aud=token_endpoint
//
// The JWT is signed with Clavex's own RS256 private key (same key used for ID tokens).
// The public key must be registered with itsme during onboarding.
func exchangeItsmeProduction(
	ctx context.Context,
	tokenURL, clientID, code, redirectURI string,
	keys oidc.Signer,
) (map[string]interface{}, error) {
	if keys == nil {
		return nil, fmt.Errorf("itsme production: no signing keys configured")
	}

	now := time.Now().UTC()
	jti := fmt.Sprintf("%d-%s", now.UnixNano(), clientID)

	// Build the client assertion JWT (RFC 7523 §3).
	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{tokenURL}).
		IssuedAt(now).
		Expiration(now.Add(2 * time.Minute)).
		JwtID(jti).
		Build()
	if err != nil {
		return nil, fmt.Errorf("itsme production: failed to build assertion JWT: %w", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.AlgorithmKey, jwa.RS256)
	_ = hdrs.Set(jws.KeyIDKey, keys.KID())
	_ = hdrs.Set("typ", "JWT")

	assertionBytes, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, keys.CryptoSigner(), jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return nil, fmt.Errorf("itsme production: sign assertion: %w", err)
	}

	form := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {redirectURI},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {string(assertionBytes)},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("itsme production: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("itsme production: token request: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("itsme production: decode response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("itsme production: token endpoint returned %d: %v", resp.StatusCode, result)
	}
	return result, nil
}
