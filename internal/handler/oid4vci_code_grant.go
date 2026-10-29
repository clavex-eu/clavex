package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func authorizationCodeToken(ac *repository.AuthCode) (jwt.Token, error) {
	builder := jwt.NewBuilder().Claim("scope", ac.Scope)
	if len(ac.AuthorizationDetails) > 0 {
		builder = builder.Claim("authorization_details", ac.AuthorizationDetails)
	}
	return builder.Build()
}

// Intercept only codes with an actual deferred credential authorization.
// All ordinary OIDC codes keep the existing exchange implementation.
func (h *OID4VCIHandler) walletAuthorizationCodeRequest(c echo.Context) (bool, error) {
	ctx := c.Request().Context()
	ac, err := h.repo.WalletAuthorizationCode(ctx, oidc.HashToken(c.FormValue("code")))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, echo.ErrServiceUnavailable
	}
	org, err := h.resolveOrg(c)
	if err != nil {
		return false, err
	}
	if ac.OrgID != org.ID {
		return false, nil
	}
	configs, err := h.repo.ListCredentialConfigs(ctx, org.ID)
	if err != nil {
		return false, echo.ErrServiceUnavailable
	}
	tok, err := authorizationCodeToken(ac)
	if err != nil {
		return false, echo.ErrServiceUnavailable
	}
	issuer := h.cfg.BaseURL() + "/" + org.Slug
	for _, cfg := range configs {
		if cfg.IsActive && cfg.DeferredIssuance && credentialConfigurationAuthorized(tok, oid4w.CredentialConfigID(cfg.VCT), issuer) {
			return true, nil
		}
	}
	return false, nil
}
func (h *OID4VCIHandler) walletCodeConfig(ctx context.Context, org *models.Organization, ac *repository.AuthCode, c echo.Context) (*models.CredentialConfig, error) {
	configs, err := h.repo.ListCredentialConfigs(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	tok, err := authorizationCodeToken(ac)
	if err != nil {
		return nil, err
	}
	requested := ""
	if raw := c.FormValue("authorization_details"); raw != "" {
		var details []struct {
			Type      string   `json:"type"`
			ID        string   `json:"credential_configuration_id"`
			Locations []string `json:"locations"`
		}
		if len(raw) > 16*1024 || json.Unmarshal([]byte(raw), &details) != nil || len(details) != 1 || details[0].Type != "openid_credential" || details[0].ID == "" {
			return nil, pgx.ErrNoRows
		}
		for _, location := range details[0].Locations {
			if location != h.cfg.BaseURL()+"/"+org.Slug {
				return nil, pgx.ErrNoRows
			}
		}
		requested = details[0].ID
	}
	var selected *models.CredentialConfig
	for i := range configs {
		cfg := &configs[i]
		id := oid4w.CredentialConfigID(cfg.VCT)
		if !cfg.IsActive || requested != "" && id != requested || !credentialConfigurationAuthorized(tok, id, h.cfg.BaseURL()+"/"+org.Slug) {
			continue
		}
		if selected != nil {
			return nil, echo.NewHTTPError(http.StatusBadRequest, "select one authorized credential configuration using authorization_details")
		}
		selected = cfg
	}
	if selected == nil {
		return nil, pgx.ErrNoRows
	}
	return selected, nil
}
func (h *OID4VCIHandler) authorizationCodeWalletGrant(c echo.Context, org *models.Organization) error {
	if !org.IsActive {
		return walletTokenError(c, "invalid_grant")
	}
	if len(c.FormValue("code")) > 2048 || c.FormValue("code") == "" {
		return walletTokenError(c, "invalid_grant")
	}
	for _, name := range []string{"resource", "audience"} {
		if c.FormValue(name) != "" {
			return walletTokenError(c, "invalid_request")
		}
	}
	client, err := h.authenticateWalletClient(c, org)
	if err != nil {
		return walletClientError(c, err)
	}
	if client.ID == "" {
		return walletClientError(c, echo.ErrUnauthorized)
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()
	repo, tx, err := h.repo.BeginIssuance(ctx)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	defer tx.Rollback(ctx)
	ac, err := repo.ConsumeWalletAuthorizationCode(ctx, oidc.HashToken(c.FormValue("code")))
	if err != nil {
		return walletGrantError(c, err)
	}
	if ac.OrgID != org.ID || ac.ClientID != client.ID || ac.RedirectURI != c.FormValue("redirect_uri") || !time.Now().Before(ac.ExpiresAt) {
		return walletTokenError(c, "invalid_grant")
	}
	// Wallet code exchange always uses S256 PKCE, including confidential clients.
	verifier := c.FormValue("code_verifier")
	if ac.PKCEMethod != "S256" || ac.PKCEChallenge == "" || len(verifier) < 43 || len(verifier) > 128 || oidc.VerifyPKCE(ac.PKCEChallenge, verifier) != nil {
		return walletTokenError(c, "invalid_grant")
	}
	if c.FormValue("scope") != "" && c.FormValue("scope") != ac.Scope {
		return walletTokenError(c, "invalid_scope")
	}
	cfg, err := h.walletCodeConfig(ctx, org, ac, c)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return walletTokenError(c, "invalid_scope")
		}
		var he *echo.HTTPError
		if errors.As(err, &he) {
			return walletTokenError(c, "invalid_request")
		}
		return echo.ErrServiceUnavailable
	}
	// Bind a single authorized configuration to an internal offer. Its random
	// pre-authorized code is never exposed; authentication remains the code grant.
	deadline := time.Now().Add(walletGrantLifetime)
	if !cfg.DeferredIssuance {
		deadline = time.Now().Add(walletAccessLifetime)
	}
	internalCode, _, err := walletToken("internal_code_")
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	offer, err := repo.CreateCredentialOffer(ctx, org.ID, &ac.UserID, cfg.VCT, internalCode, nil, nil, deadline)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	details, err := json.Marshal(ac.AuthorizationDetails)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	if len(ac.AuthorizationDetails) == 0 {
		details = []byte(`[]`)
	}
	g := repository.WalletIssuanceGrant{OrgID: org.ID, OfferID: offer.ID, UserID: &ac.UserID, ConfigurationID: cfg.ID, VCT: cfg.VCT, ClientID: client.ID, ClientAuthMethod: client.Method, AttestationJKT: client.AttestationJKT, StatusParents: marshalStatusParents(client.Parents), DeferredAllowed: cfg.DeferredIssuance, ExpiresAt: deadline, AuthorizationCodeID: &ac.ID, AuthorizationScope: ac.Scope, AuthorizationDetails: details}
	if err := h.walletSender(c, &g, "", true); err != nil {
		if errors.Is(err, echo.ErrServiceUnavailable) {
			return err
		}
		return walletTokenError(c, "invalid_dpop_proof")
	}
	if ac.DpopJKT != "" && g.DPoPJKT != ac.DpopJKT {
		return walletTokenError(c, "invalid_dpop_proof")
	}
	if err := repo.CheckWalletEligibility(ctx, &g, offer); err != nil {
		return walletGrantError(c, err)
	}
	created, err := repo.CreateWalletGrant(ctx, g)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	response, err := h.walletTokenResponse(ctx, repo, created, "", "")
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	response["scope"] = g.AuthorizationScope
	if len(ac.AuthorizationDetails) > 0 {
		response["authorization_details"] = ac.AuthorizationDetails
	}
	// Mixed OpenID + credential scopes retain a signed JWT access token (usable
	// at UserInfo) and an ID token bound to that exact access token.
	if containsScope(ac.Scope, "openid") {
		user, err := h.users.GetForOrg(ctx, ac.UserID, org.ID)
		if err != nil {
			return walletGrantError(c, err)
		}
		uc := oidc.UserClaimsFromModel(user)
		uc.AuthTime = ac.AuthTime
		uc.Acr = ac.Acr
		uc.AtHash = oidc.ComputeAtHash(response["access_token"].(string))
		methodClient, err := h.oidcHandler.clients.GetByClientID(ctx, client.ID)
		if err != nil {
			return echo.ErrServiceUnavailable
		}
		idToken, err := h.oidcHandler.newTC(h.cfg.BaseURL()+"/"+org.Slug).IssueIDToken(client.ID, ac.Nonce, uc, oidc.ResolveIDTokenAlg(methodClient.IDTokenSignedResponseAlg))
		if err != nil {
			return echo.ErrServiceUnavailable
		}
		response["id_token"] = idToken
	}
	nonce, err := h.issueCredentialNonce(ctx, org.Slug)
	if err != nil {
		return writeCredentialProofError(c, err)
	}
	response["c_nonce"], response["c_nonce_expires_in"] = nonce, int(vciNonceTTL.Seconds())
	if err := tx.Commit(ctx); err != nil {
		return echo.ErrServiceUnavailable
	}
	return c.JSON(http.StatusOK, response)
}
func containsScope(scope, wanted string) bool {
	for _, s := range strings.Fields(scope) {
		if s == wanted {
			return true
		}
	}
	return false
}

func (h *OID4VCIHandler) walletAuthorizationJWT(ctx context.Context, g *repository.WalletIssuanceGrant) (string, error) {
	if h.oidcHandler == nil || g.UserID == nil {
		return "", echo.ErrServiceUnavailable
	}
	user, err := h.users.GetForOrg(ctx, *g.UserID, g.OrgID)
	if err != nil {
		return "", err
	}
	org, err := h.orgs.GetByID(ctx, g.OrgID)
	if err != nil {
		return "", err
	}
	uc := oidc.UserClaimsFromModel(user)
	uc.ExtraClaims = map[string]any{"clavex_wallet_grant": g.ID.String()}
	if json.Unmarshal(g.AuthorizationDetails, &uc.AuthorizationDetails) != nil {
		return "", echo.ErrServiceUnavailable
	}
	tc := h.oidcHandler.newTC(h.cfg.BaseURL() + "/" + org.Slug)
	tc.AccessTokenTTL = walletAccessLifetime
	if remaining := time.Until(g.ExpiresAt); remaining < tc.AccessTokenTTL {
		tc.AccessTokenTTL = remaining
	}
	var dpop *oidc.DPoPKey
	if g.DPoPJKT != "" {
		dpop = &oidc.DPoPKey{JKT: g.DPoPJKT}
	}
	var mtls *oidc.MTLSCert
	if g.MTLSX5TS256 != "" {
		mtls = &oidc.MTLSCert{X5TS256: g.MTLSX5TS256}
	}
	raw, _, err := tc.IssueAccessToken(g.ClientID, g.AuthorizationScope, &uc, dpop, mtls)
	return raw, err
}
