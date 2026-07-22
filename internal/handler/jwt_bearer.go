package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/metrics"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	jwkPkg "github.com/lestrrat-go/jwx/v2/jwk"
	jwtPkg "github.com/lestrrat-go/jwx/v2/jwt"
)

// jwtBearerGrant handles grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
// (RFC 7523 §2.1/§4 — the generic JWT Bearer authorization grant).
//
// This is distinct from client_assertion_type=urn:ietf:params:oauth:client-
// assertion-type:jwt-bearer (RFC 7523 §2.2, handled by
// authenticateClientByAssertion), which authenticates the CLIENT itself.
// Here the assertion authorizes the token request on behalf of a subject
// asserted by a trusted external issuer — iss (the issuer) and sub (the
// subject) are independent, unlike a client assertion.
//
// This implements only the generic, stable RFC 7523 profile. It is the
// building block ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant)
// will be layered on top of once that draft stabilises — no ID-JAG-specific
// claims or semantics are interpreted here. See docs/ID-JAG-ROADMAP.md.
func (h *OIDCHandler) jwtBearerGrant(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	assertion := c.FormValue("assertion")
	if assertion == "" {
		return tokenError(c, "invalid_request", "assertion is required")
	}

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return tokenError(c, "invalid_request", "organization not found")
	}

	// Parse unverified to extract iss so the trusted-issuer config can be
	// looked up; full cryptographic validation happens in
	// oidc.ValidateJWTBearerGrant once the issuer's key set is resolved.
	unverified, err := jwtPkg.Parse([]byte(assertion), jwtPkg.WithVerify(false), jwtPkg.WithValidate(false))
	if err != nil {
		return tokenError(c, "invalid_grant", "invalid assertion")
	}
	iss := unverified.Issuer()
	if iss == "" {
		return tokenError(c, "invalid_grant", "assertion missing iss (RFC 7523 sec. 3)")
	}

	trusted, err := h.jwtBearerIssuers.GetActiveByIssuer(ctx, org.ID, iss)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return tokenError(c, "invalid_grant", "issuer is not trusted for this organization")
		}
		return echo.ErrInternalServerError
	}

	keySet, ferr := resolveTrustedIssuerJWKS(ctx, trusted)
	if ferr != nil {
		return tokenError(c, "invalid_grant", ferr.Error())
	}

	issuer := h.issuerFromRequest(c, orgSlug)
	jtiCache := &redisJTICache{rdb: h.rdb}
	tok, verr := oidc.ValidateJWTBearerGrant(ctx, assertion, keySet, issuer+"/token", jtiCache)
	if verr != nil {
		var te *oidc.TokenError
		if errors.As(verr, &te) {
			return tokenError(c, te.Code, te.Description)
		}
		return tokenError(c, "invalid_grant", "assertion validation failed")
	}

	scope := oidc.FilterScope(c.FormValue("scope"), trusted.AllowedScopes)

	uc := oidc.UserClaims{
		UserID: tok.Subject(),
		OrgID:  org.ID.String(),
	}
	if len(trusted.ClaimMappings) > 0 {
		extra := make(map[string]any, len(trusted.ClaimMappings))
		for extClaim, clavexClaim := range trusted.ClaimMappings {
			if v, ok := tok.Get(extClaim); ok {
				extra[clavexClaim] = v
			}
		}
		if len(extra) > 0 {
			uc.ExtraClaims = extra
		}
	}

	tc := h.newTC(issuer)
	h.applyOrgOverrides(ctx, tc, org, nil)

	// The audience of the issued access token is the requesting client, if
	// identified; otherwise the external issuer identifies the caller.
	clientID := c.FormValue("client_id")
	if clientID == "" {
		clientID = iss
	}

	accessToken, _, err := tc.IssueAccessToken(clientID, scope, &uc, nil, nil)
	if err != nil {
		return echo.ErrInternalServerError
	}

	metrics.TokensIssuedTotal.WithLabelValues(orgSlug, "jwt-bearer").Inc()
	return c.JSON(http.StatusOK, &oidc.TokenSet{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(tc.AccessTokenTTL.Seconds()),
		Scope:       scope,
	})
}

// resolveTrustedIssuerJWKS returns the key set for a trusted-issuer record:
// inline JWKS takes precedence over jwks_uri (mirrors resolveClientJWKS).
func resolveTrustedIssuerJWKS(ctx context.Context, t *models.JWTBearerTrustedIssuer) (jwkPkg.Set, error) {
	switch {
	case t.JWKS != nil && len(*t.JWKS) > 2: // "{}" is len 2
		keySet, err := jwkPkg.Parse(*t.JWKS)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted issuer JWKS")
		}
		return keySet, nil
	case t.JWKSURI != nil && *t.JWKSURI != "":
		fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		keySet, err := jwkPkg.Fetch(fetchCtx, *t.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch trusted issuer jwks_uri")
		}
		return keySet, nil
	default:
		return nil, fmt.Errorf("trusted issuer has no JWKS configured")
	}
}
