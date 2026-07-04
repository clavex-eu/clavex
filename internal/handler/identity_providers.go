package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/connectorregistry"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// IDPHandler manages identity provider CRUD and handles the OAuth2 SSO flow.
type IDPHandler struct {
	repo  *repository.IDPRepository
	users *repository.UserRepository
	orgs  *repository.OrgRepository
	store *session.Store
}

func NewIDPHandler(pool *pgxpool.Pool, store *session.Store) *IDPHandler {
	return &IDPHandler{
		repo:  repository.NewIDPRepository(pool),
		users: repository.NewUserRepository(pool),
		orgs:  repository.NewOrgRepository(pool),
		store: store,
	}
}

// ── Social provider presets ───────────────────────────────────────────────────

// applyPreset fills in missing endpoint fields from the connector registry for
// the given provider_type. Fields already set by the caller take precedence.
func applyPreset(req *createIDPRequest) {
	def := connectorregistry.GetSocial(req.ProviderType)
	if def == nil {
		return
	}
	if req.AuthorizationURL == "" {
		req.AuthorizationURL = def.AuthorizationURL
	}
	if req.TokenURL == "" {
		req.TokenURL = def.TokenURL
	}
	if req.UserinfoURL == nil && def.UserinfoURL != nil {
		req.UserinfoURL = def.UserinfoURL
	}
	if req.Scopes == "" {
		req.Scopes = def.Scopes
	}
	if req.EmailClaim == "" {
		req.EmailClaim = def.EmailClaim
	}
	if req.FirstNameClaim == "" {
		req.FirstNameClaim = def.FirstNameClaim
	}
	if req.LastNameClaim == "" {
		req.LastNameClaim = def.LastNameClaim
	}
}

// Presets returns the canonical endpoint configuration for all registered
// social login providers from the connector registry catalog.
// GET /api/v1/social-providers/presets
func (h *IDPHandler) Presets(c echo.Context) error {
	defs := connectorregistry.ListSocial()
	// Convert to a keyed map to preserve the existing API response shape.
	out := make(map[string]any, len(defs))
	for _, d := range defs {
		out[d.ID] = d
	}
	return c.JSON(http.StatusOK, out)
}

// ── Admin CRUD ────────────────────────────────────────────────────────────────────────────

type createIDPRequest struct {
	Name              string            `json:"name"               validate:"required,min=1,max=128"`
	ProviderType      string            `json:"provider_type"      validate:"required"`
	ClientID          string            `json:"client_id"          validate:"required"`
	ClientSecret      string            `json:"client_secret"`
	AuthorizationURL  string            `json:"authorization_url"  validate:"omitempty,url"`
	TokenURL          string            `json:"token_url"          validate:"omitempty,url"`
	UserinfoURL       *string           `json:"userinfo_url"       validate:"omitempty,url"`
	Scopes            string            `json:"scopes"`
	EmailClaim        string            `json:"email_claim"`
	FirstNameClaim    string            `json:"first_name_claim"`
	LastNameClaim     string            `json:"last_name_claim"`
	IsActive          bool              `json:"is_active"`
	AllowJIT          bool              `json:"allow_jit"`
	RolesClaim        *string           `json:"roles_claim"`
	RoleClaimMappings map[string]string `json:"role_claim_mappings"`
	// Apple Sign In With Apple JWT credentials (only required when provider_type == "apple")
	AppleTeamID     string `json:"apple_team_id"`
	AppleKeyID      string `json:"apple_key_id"`
	ApplePrivateKey string `json:"apple_private_key"` // PEM or raw .p8 content
}

// Create registers a new identity provider.
// POST /api/v1/organizations/:org_id/identity-providers
func (h *IDPHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createIDPRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if !connectorregistry.IsSocialRegistered(req.ProviderType) {
		return echo.NewHTTPError(http.StatusBadRequest, "unknown provider_type; see GET /connector-catalog/social for available providers")
	}
	// Auto-fill endpoints from the built-in preset so callers only need to
	// provide client_id + client_secret for well-known social providers.
	applyPreset(&req)

	// After applying presets, ensure required URL fields are populated.
	if req.AuthorizationURL == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "authorization_url is required")
	}
	if req.TokenURL == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "token_url is required")
	}
	if req.Scopes == "" {
		req.Scopes = "openid email profile"
	}
	if req.EmailClaim == "" {
		req.EmailClaim = "email"
	}
	if req.FirstNameClaim == "" {
		req.FirstNameClaim = "given_name"
	}
	if req.LastNameClaim == "" {
		req.LastNameClaim = "family_name"
	}
	if req.RoleClaimMappings == nil {
		req.RoleClaimMappings = map[string]string{}
	}
	p := &models.IdentityProvider{
		OrgID:             orgID,
		Name:              req.Name,
		ProviderType:      req.ProviderType,
		ClientID:          req.ClientID,
		AuthorizationURL:  req.AuthorizationURL,
		TokenURL:          req.TokenURL,
		UserinfoURL:       req.UserinfoURL,
		Scopes:            req.Scopes,
		EmailClaim:        req.EmailClaim,
		FirstNameClaim:    req.FirstNameClaim,
		LastNameClaim:     req.LastNameClaim,
		IsActive:          req.IsActive,
		AllowJIT:          req.AllowJIT,
		RolesClaim:        req.RolesClaim,
		RoleClaimMappings: req.RoleClaimMappings,
	}
	if req.AppleTeamID != "" {
		p.AppleTeamID = &req.AppleTeamID
	}
	if req.AppleKeyID != "" {
		p.AppleKeyID = &req.AppleKeyID
	}
	if req.ApplePrivateKey != "" {
		p.ApplePrivateKey = &req.ApplePrivateKey
	}
	// For Apple, the client_secret field may be empty (we generate it on-the-fly);
	// for all other providers it remains required.
	if req.ProviderType != "apple" && req.ClientSecret == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "client_secret is required")
	}
	created, err := h.repo.Create(c.Request().Context(), p, req.ClientSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "provider name already exists for this organization")
	}
	return c.JSON(http.StatusCreated, created)
}

// List returns all identity providers for an org.
// GET /api/v1/organizations/:org_id/identity-providers
func (h *IDPHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	providers, err := h.repo.List(c.Request().Context(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, providers)
}

type updateIDPRequest struct {
	Name              string            `json:"name"               validate:"required,min=1,max=128"`
	ProviderType      string            `json:"provider_type"      validate:"required"`
	ClientID          string            `json:"client_id"          validate:"required"`
	ClientSecret      string            `json:"client_secret"`
	AuthorizationURL  string            `json:"authorization_url"  validate:"required,url"`
	TokenURL          string            `json:"token_url"          validate:"required,url"`
	UserinfoURL       *string           `json:"userinfo_url"       validate:"omitempty,url"`
	Scopes            string            `json:"scopes"`
	EmailClaim        string            `json:"email_claim"`
	FirstNameClaim    string            `json:"first_name_claim"`
	LastNameClaim     string            `json:"last_name_claim"`
	IsActive          bool              `json:"is_active"`
	AllowJIT          bool              `json:"allow_jit"`
	RolesClaim        *string           `json:"roles_claim"`
	RoleClaimMappings map[string]string `json:"role_claim_mappings"`
	// Apple-specific credentials (optional; set only when updating Apple JWT keys)
	AppleTeamID     string `json:"apple_team_id"`
	AppleKeyID      string `json:"apple_key_id"`
	ApplePrivateKey string `json:"apple_private_key"` // empty = keep existing
}

// Update patches a registered identity provider.
// PATCH /api/v1/organizations/:org_id/identity-providers/:id
func (h *IDPHandler) Update(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid provider id")
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	var req updateIDPRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.RoleClaimMappings == nil {
		req.RoleClaimMappings = map[string]string{}
	}
	p := repository.UpdateIDPParams{
		ID:                id,
		Name:              req.Name,
		ProviderType:      req.ProviderType,
		ClientID:          req.ClientID,
		ClientSecret:      req.ClientSecret,
		AuthURL:           req.AuthorizationURL,
		TokenURL:          req.TokenURL,
		UserinfoURL:       req.UserinfoURL,
		Scopes:            req.Scopes,
		EmailClaim:        req.EmailClaim,
		FirstNameClaim:    req.FirstNameClaim,
		LastNameClaim:     req.LastNameClaim,
		IsActive:          req.IsActive,
		AllowJIT:          req.AllowJIT,
		RolesClaim:        req.RolesClaim,
		RoleClaimMappings: req.RoleClaimMappings,
	}
	if req.AppleTeamID != "" {
		p.AppleTeamID = &req.AppleTeamID
	}
	if req.AppleKeyID != "" {
		p.AppleKeyID = &req.AppleKeyID
	}
	if req.ApplePrivateKey != "" {
		p.ApplePrivateKey = &req.ApplePrivateKey
	}
	updated, err := h.repo.Update(c.Request().Context(), p)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, updated)
}

// Delete removes a registered identity provider.
// DELETE /api/v1/organizations/:org_id/identity-providers/:id
func (h *IDPHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid provider id")
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	if err := h.repo.Delete(c.Request().Context(), id); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ── OAuth2 SSO flow ─────────────────────────────────────────────────────────────────────────

// StartSSO initiates the upstream OAuth2/OIDC login.
// GET /:org_slug/idp/:id?login_session_id=...
func (h *IDPHandler) StartSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idStr := c.Param("id")
	providerID, err := uuid.Parse(idStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid provider id")
	}
	loginSessionID := c.QueryParam("login_session_id")
	if loginSessionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}
	orgSlug := c.Param("org_slug")

	// Bind the provider to the login session's org: an IdP registered in a
	// different tenant must never be usable to authenticate into this org
	// (cross-tenant account takeover). The provider's org must equal the org
	// the user is ultimately provisioned/looked-up in (loginSess.OrgID).
	loginSess, err := h.store.GetLoginSession(ctx, loginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please start over")
	}
	orgID, err := uuid.Parse(loginSess.OrgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	provider, err := h.repo.GetForOrg(ctx, providerID, orgID)
	if err != nil || !provider.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "identity provider not found or inactive")
	}

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return echo.ErrInternalServerError
	}
	state := base64.RawURLEncoding.EncodeToString(b)

	if err := h.store.SaveIDPState(ctx, state, &session.IDPState{
		ProviderID:     providerID.String(),
		LoginSessionID: loginSessionID,
		OrgSlug:        orgSlug,
	}); err != nil {
		return echo.ErrInternalServerError
	}

	redirectURI := buildRedirectURI(c, orgSlug, idStr)

	authURL, _ := url.Parse(provider.AuthorizationURL)
	q := authURL.Query()
	q.Set("client_id", provider.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", provider.Scopes)
	q.Set("state", state)
	q.Set("redirect_uri", redirectURI)
	authURL.RawQuery = q.Encode()

	return c.Redirect(http.StatusFound, authURL.String())
}

// CallbackSSO handles the upstream OAuth2/OIDC callback.
// GET /:org_slug/idp/:id/callback?code=...&state=...
func (h *IDPHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()
	idStr := c.Param("id")
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	if state == "" || code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing state or code")
	}

	stateData, err := h.store.GetIDPState(ctx, state)
	if err != nil || stateData == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid or expired state \u2014 please try again")
	}
	if stateData.ProviderID != idStr {
		return echo.NewHTTPError(http.StatusBadRequest, "state mismatch")
	}

	loginSess, err := h.store.GetLoginSession(ctx, stateData.LoginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired \u2014 please start over")
	}

	orgID, err := uuid.Parse(loginSess.OrgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	providerID, _ := uuid.Parse(stateData.ProviderID)
	// Cross-tenant guard: the provider must belong to the login session's org,
	// otherwise an attacker-controlled IdP from another tenant could assert an
	// arbitrary identity into this org (account takeover).
	provider, err := h.repo.GetForOrg(ctx, providerID, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	clientSecret, appleTeamID, appleKeyID, applePrivKey, err := h.repo.GetClientSecret(ctx, provider.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Apple requires a dynamically-generated ES256 JWT as the client_secret
	// rather than a static string. Generate a fresh one for this request.
	if provider.ProviderType == "apple" {
		if appleTeamID == nil || appleKeyID == nil || applePrivKey == nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "apple jwt credentials not configured")
		}
		generated, jwtErr := generateAppleClientSecret(provider.ClientID, *appleTeamID, *appleKeyID, *applePrivKey)
		if jwtErr != nil {
			log.Error().Err(jwtErr).Msg("idp: failed to generate Apple client_secret JWT")
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate Apple client_secret")
		}
		clientSecret = generated
	}

	redirectURI := buildRedirectURI(c, stateData.OrgSlug, idStr)

	tokenResp, err := exchangeUpstreamCode(ctx, provider.TokenURL, provider.ClientID, clientSecret, code, redirectURI)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "failed to exchange code with identity provider")
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "identity provider did not return an access token")
	}

	email, firstName, lastName, userInfoRaw, err := fetchUpstreamUserInfo(ctx, provider, accessToken)
	if err != nil || email == "" {
		return echo.NewHTTPError(http.StatusBadGateway, "failed to retrieve user information from identity provider")
	}

	user, err := h.users.GetByEmail(ctx, orgID, email)
	if err != nil {
		// User does not exist — respect the allow_jit toggle.
		if !provider.AllowJIT {
			return echo.NewHTTPError(http.StatusForbidden, "your organization does not allow automatic account provisioning via this identity provider")
		}
		var fn, ln *string
		if firstName != "" {
			fn = &firstName
		}
		if lastName != "" {
			ln = &lastName
		}
		user, err = h.users.Create(ctx, orgID, email, fn, ln)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to provision user account")
		}
		applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "your account has been disabled")
	}

	// Apply role claim mappings if configured.
	if provider.RolesClaim != nil && *provider.RolesClaim != "" && len(provider.RoleClaimMappings) > 0 {
		if err := applyRoleClaimMappings(ctx, h.users, user.ID, orgID, provider, userInfoRaw); err != nil {
			// Non-fatal: log and continue.
			log.Warn().Err(err).Str("user_id", user.ID.String()).Msg("idp: role claim mapping failed")
		}
	}

	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + stateData.OrgSlug + "/authorize/resume?login_session_id=" + stateData.LoginSessionID
	return c.Redirect(http.StatusFound, resumeURL)
}

// generateAppleClientSecret produces the short-lived ES256 JWT that Apple
// requires as the client_secret in the authorization_code token exchange.
//
// Apple requirements (https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens):
//
//	Header:  alg=ES256, kid=<Key ID from Developer portal>
//	Claims:  iss=<Team ID>, iat=now, exp=now+180d (max 6 months), aud="https://appleid.apple.com", sub=<Client ID>
//	Signed with the .p8 EC private key from the Developer portal.
//
// The key is expected in PEM or raw PKCS#8 format (the content of the .p8 file
// Apple provides — which is a PEM block of type "PRIVATE KEY").
func generateAppleClientSecret(clientID, teamID, keyID, privateKeyPEM string) (string, error) {
	// Decode the PEM block.  Apple's .p8 files use the "PRIVATE KEY" type.
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("apple: private key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("apple: parse private key: %w", err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("apple: private key must be EC (got %T)", parsed)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(180 * 24 * time.Hour).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": clientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID

	signed, err := token.SignedString(ecKey)
	if err != nil {
		return "", fmt.Errorf("apple: sign jwt: %w", err)
	}
	return signed, nil
}

// buildRedirectURI constructs the absolute callback URL for the IdP.
func buildRedirectURI(c echo.Context, orgSlug, idStr string) string {
	scheme := "http"
	if c.Request().TLS != nil || c.Request().Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + c.Request().Host + "/" + orgSlug + "/idp/" + idStr + "/callback"
}

// upstreamHTTPClient is used for outbound calls to admin-configured upstream
// IdP endpoints (token / userinfo). It refuses to connect to private, loopback
// and link-local addresses so a malicious provider URL cannot be used to reach
// internal services (SSRF, e.g. cloud metadata endpoints).
var upstreamHTTPClient = safehttp.Client(30*time.Second, false)

// SetUpstreamHTTPClient overrides the client used for outbound calls to
// admin-configured upstream IdP token/userinfo endpoints. Called at startup
// when the operator opts into private outbound targets
// (http.allow_private_outbound_targets) so a federated IdP on an internal
// network is reachable. Default keeps the SSRF guard on.
func SetUpstreamHTTPClient(c *http.Client) { upstreamHTTPClient = c }

// exchangeUpstreamCode posts to the upstream token endpoint.
func exchangeUpstreamCode(ctx context.Context, tokenURL, clientID, clientSecret, code, redirectURI string) (map[string]interface{}, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := upstreamHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}
	var result map[string]interface{}
	return result, json.Unmarshal(body, &result)
}

// fetchUpstreamUserInfo calls the userinfo endpoint and extracts configured claims.
// It returns the raw claims map so role-mapping can inspect arbitrary claim names.
// GitHub special case: when the email claim is empty (private profile), this
// function transparently fetches the primary verified email from /user/emails.
func fetchUpstreamUserInfo(ctx context.Context, p *models.IdentityProvider, accessToken string) (email, firstName, lastName string, raw map[string]interface{}, err error) {
	if p.UserinfoURL == nil || *p.UserinfoURL == "" {
		err = fmt.Errorf("no userinfo URL configured for provider %s", p.ID)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *p.UserinfoURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := upstreamHTTPClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var claims map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return
	}
	raw = claims
	if v, ok := claims[p.EmailClaim].(string); ok {
		email = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := claims[p.FirstNameClaim].(string); ok {
		firstName = v
	}
	if v, ok := claims[p.LastNameClaim].(string); ok {
		lastName = v
	}

	// GitHub-specific: email may be absent on the /user endpoint when the user
	// has set their email to private. Fall back to the /user/emails API which
	// returns the primary verified email regardless of privacy settings.
	if email == "" && p.ProviderType == "github" {
		if primaryEmail := fetchGitHubPrimaryEmail(ctx, accessToken); primaryEmail != "" {
			email = primaryEmail
			// Expose in raw so role-mappers see the resolved address.
			raw["email"] = email
		}
	}
	return
}

// fetchGitHubPrimaryEmail calls the GitHub /user/emails API and returns the
// primary verified email address, or empty string on any error.
func fetchGitHubPrimaryEmail(ctx context.Context, accessToken string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return ""
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return strings.ToLower(strings.TrimSpace(e.Email))
		}
	}
	return ""
}

// applyRoleClaimMappings reads the roles/groups claim from the IdP's userinfo response
// and assigns any matching local roles to the user.
func applyRoleClaimMappings(
	ctx context.Context,
	users *repository.UserRepository,
	userID, orgID uuid.UUID,
	provider *models.IdentityProvider,
	raw map[string]interface{},
) error {
	if raw == nil || provider.RolesClaim == nil {
		return nil
	}
	claimVal, ok := raw[*provider.RolesClaim]
	if !ok {
		return nil
	}
	// Claim value can be a []interface{} (JSON array) or a single string.
	var claimValues []string
	switch v := claimVal.(type) {
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				claimValues = append(claimValues, s)
			}
		}
	case string:
		claimValues = strings.Split(v, " ")
	}

	for _, claimRole := range claimValues {
		localRoleName, mapped := provider.RoleClaimMappings[claimRole]
		if !mapped {
			continue
		}
		role, err := users.GetRoleByName(ctx, orgID, localRoleName)
		if err != nil {
			// Role doesn't exist in this org — skip.
			continue
		}
		// AssignRole is idempotent (INSERT … ON CONFLICT DO NOTHING).
		_ = users.AssignRole(ctx, userID, role.ID)
	}
	return nil
}
// SetPromoted handles PUT /organizations/:org_id/identity-providers/:id/promote.
// Body: {"is_promoted": true|false}
func (h *IDPHandler) SetPromoted(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	idpID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	var body struct {
		IsPromoted bool `json:"is_promoted"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}

	if err := h.repo.SetPromoted(c.Request().Context(), orgID, idpID, body.IsPromoted); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}