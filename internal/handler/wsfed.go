package handler

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	eursaml "github.com/clavex-eu/clavex/internal/saml"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/wsfed"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

// WSFedHandler handles WS-Federation Passive Requestor Protocol endpoints
// and admin CRUD for relying party (RP) registrations.
type WSFedHandler struct {
	cfg      *config.Config
	wsfedR   *repository.WSFedRepository
	samlR    *repository.SAMLRepository
	orgR     *repository.OrgRepository
	userR    *repository.UserRepository
	store    *session.Store
}

func NewWSFedHandler(cfg *config.Config, pool *pgxpool.Pool, rdb redis.UniversalClient) *WSFedHandler {
	return &WSFedHandler{
		cfg:    cfg,
		wsfedR: repository.NewWSFedRepository(pool),
		samlR:  repository.NewSAMLRepository(pool),
		orgR:   repository.NewOrgRepository(pool),
		userR:  repository.NewUserRepository(pool),
		store:  session.NewStore(rdb),
	}
}

// ── Public endpoints ─────────────────────────────────────────────────────────

// Endpoint handles the WS-Federation passive requestor protocol.
// GET|POST /:org_slug/wsfed
//
// Query params (GET) or form (POST):
//
//	wa        — "wsignin1.0" (sign-in) or "wsignout1.0" (sign-out)
//	wtrealm   — relying party realm identifier (registered in DB)
//	wreply    — URL to POST the token to (must be in registered wreply_uris)
//	wctx      — optional context string echoed back in response
func (h *WSFedHandler) Endpoint(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	org, err := h.orgR.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	param := func(k string) string {
		if v := c.QueryParam(k); v != "" {
			return v
		}
		return c.FormValue(k)
	}

	wa := param("wa")

	// ── Sign-out ─────────────────────────────────────────────────────────────
	if wa == "wsignout1.0" {
		if cookie, err := c.Cookie("clavex_sso"); err == nil && cookie.Value != "" {
			_ = h.store.DeleteSSOSession(ctx, cookie.Value)
			c.SetCookie(&http.Cookie{
				Name: "clavex_sso", Value: "", Path: "/", MaxAge: -1,
				HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
		}
		wreply := param("wreply")
		if wreply != "" {
			// Validate wreply against the org's registered RP reply URIs before
			// redirecting — otherwise sign-out is an open redirect (CWE-601).
			var allowed []string
			if rps, lerr := h.wsfedR.List(ctx, org.ID); lerr == nil {
				for _, rp := range rps {
					if rp.IsActive {
						allowed = append(allowed, rp.WreplyURIs...)
					}
				}
			}
			if !isAllowedWreply(wreply, allowed) {
				return echo.NewHTTPError(http.StatusForbidden, "wreply not registered")
			}
			return c.Redirect(http.StatusFound, wreply)
		}
		return c.String(http.StatusOK, "<html><body>Signed out.</body></html>")
	}

	// ── Sign-in ──────────────────────────────────────────────────────────────
	if wa != "wsignin1.0" {
		return echo.NewHTTPError(http.StatusBadRequest, "unsupported wa action")
	}

	wtrealm := param("wtrealm")
	wreply := param("wreply")
	if wtrealm == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "wtrealm is required")
	}

	// Look up registered relying party.
	rp, err := h.wsfedR.GetByRealm(ctx, org.ID, wtrealm)
	if err != nil || !rp.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "unregistered relying party")
	}

	// Validate wreply URI is registered.
	if wreply == "" && len(rp.WreplyURIs) > 0 {
		wreply = rp.WreplyURIs[0]
	}
	if !isAllowedWreply(wreply, rp.WreplyURIs) {
		return echo.NewHTTPError(http.StatusForbidden, "wreply not registered for this realm")
	}

	// Check existing SSO session.
	cookie, cookieErr := c.Cookie("clavex_sso")
	if cookieErr != nil || cookie.Value == "" {
		// No session — redirect to OIDC login, then back to this WS-Fed endpoint.
		issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug)
		loginURL := issuer + "/auth?response_type=code&client_id=wsfed-internal" +
			"&redirect_uri=" + c.Request().URL.String()
		return c.Redirect(http.StatusFound, loginURL)
	}

	ssoSess, err := h.store.GetSSOSession(ctx, cookie.Value)
	if err != nil || ssoSess == nil {
		return c.Redirect(http.StatusFound, c.Request().URL.String())
	}

	userID, err := uuid.Parse(ssoSess.UserID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	user, err := h.userR.GetByID(ctx, userID)
	if err != nil || !user.IsActive {
		return echo.NewHTTPError(http.StatusUnauthorized, "user not found or inactive")
	}

	// Load org's SAML signing key (reused for WS-Fed).
	cert, key, err := loadSAMLCert(ctx, h.samlR, h.orgR, h.cfg, orgSlug, org.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	firstName, lastName := "", ""
	if user.FirstName != nil {
		firstName = *user.FirstName
	}
	if user.LastName != nil {
		lastName = *user.LastName
	}

	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug)
	ar, err := wsfed.IssueAssertion(&wsfed.KeyStore{PrivateKey: key, Certificate: cert},
		wsfed.TokenParams{
			Issuer:               issuer,
			Realm:                wtrealm,
			UserEmail:            user.Email,
			UserID:               user.ID.String(),
			FirstName:            firstName,
			LastName:             lastName,
			TokenLifetimeSeconds: rp.TokenLifetimeSeconds,
		})
	if err != nil {
		c.Logger().Errorf("wsfed: issue assertion: %v", err)
		return echo.ErrInternalServerError
	}

	rstr := wsfed.BuildRSTR(ar.SignedXML, wtrealm)
	page, err := wsfed.WsFedResponsePage(wreply, template.HTMLEscapeString(rstr))
	if err != nil {
		return echo.ErrInternalServerError
	}

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().Header().Set("Cache-Control", "no-store, no-cache")
	return c.HTML(http.StatusOK, page)
}

// FederationMetadata serves the WS-Federation metadata document.
// GET /:org_slug/wsfed/metadata
func (h *WSFedHandler) FederationMetadata(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	org, err := h.orgR.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	cert, _, err := loadSAMLCert(ctx, h.samlR, h.orgR, h.cfg, orgSlug, org.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}

	issuer := h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug)
	passiveURL := issuer + "/wsfed"

	import_enc := "http://www.w3.org/2001/04/xmlenc#"
	_ = import_enc

	certB64 := b64cert(cert.Raw)
	meta := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<fed:FederationMetadata xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"` +
		` xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706"` +
		` xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"` +
		` Version="1.0">` + "\n" +
		`  <RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"` +
		` xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"` +
		` xsi:type="fed:SecurityTokenServiceType"` +
		` protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">` + "\n" +
		`    <KeyDescriptor use="signing">` + "\n" +
		`      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` + "\n" +
		`        <X509Data><X509Certificate>` + certB64 + `</X509Certificate></X509Data>` + "\n" +
		`      </KeyInfo>` + "\n" +
		`    </KeyDescriptor>` + "\n" +
		`    <fed:PassiveRequestorEndpoint>` + "\n" +
		`      <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">` + "\n" +
		`        <wsa:Address>` + passiveURL + `</wsa:Address>` + "\n" +
		`      </wsa:EndpointReference>` + "\n" +
		`    </fed:PassiveRequestorEndpoint>` + "\n" +
		`  </RoleDescriptor>` + "\n" +
		`</fed:FederationMetadata>`

	c.Response().Header().Set("Content-Type", "application/xml; charset=utf-8")
	return c.String(http.StatusOK, meta)
}

// ── Admin CRUD ────────────────────────────────────────────────────────────────

type createWSFedRPRequest struct {
	Name                 string            `json:"name"                   validate:"required"`
	Realm                string            `json:"realm"                  validate:"required"`
	WreplyURIs           []string          `json:"wreply_uris"`
	TokenLifetimeSeconds int               `json:"token_lifetime_seconds"`
	ClaimsMapping        map[string]string `json:"claims_mapping"`
}

func (h *WSFedHandler) ListRPs(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	rps, err := h.wsfedR.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if rps == nil {
		rps = []*models.WSFedRelyingParty{}
	}
	return c.JSON(http.StatusOK, rps)
}

func (h *WSFedHandler) CreateRP(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createWSFedRPRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	rp, err := h.wsfedR.Create(c.Request().Context(), repository.CreateWSFedRPParams{
		OrgID:                orgID,
		Name:                 req.Name,
		Realm:                req.Realm,
		WreplyURIs:           req.WreplyURIs,
		TokenLifetimeSeconds: req.TokenLifetimeSeconds,
		ClaimsMapping:        req.ClaimsMapping,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "realm already registered")
	}
	return c.JSON(http.StatusCreated, rp)
}

func (h *WSFedHandler) GetRP(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "rp_id")
	if err != nil {
		return err
	}
	rp, err := h.wsfedR.GetByID(c.Request().Context(), orgID, id)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, rp)
}

func (h *WSFedHandler) UpdateRP(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "rp_id")
	if err != nil {
		return err
	}
	var req createWSFedRPRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	rp, err := h.wsfedR.Update(c.Request().Context(), orgID, id, repository.CreateWSFedRPParams{
		OrgID:                orgID,
		Name:                 req.Name,
		WreplyURIs:           req.WreplyURIs,
		TokenLifetimeSeconds: req.TokenLifetimeSeconds,
		ClaimsMapping:        req.ClaimsMapping,
	})
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, rp)
}

func (h *WSFedHandler) DeleteRP(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "rp_id")
	if err != nil {
		return err
	}
	if err := h.wsfedR.Delete(c.Request().Context(), orgID, id); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isAllowedWreply(wreply string, allowed []string) bool {
	if wreply == "" {
		return len(allowed) > 0
	}
	for _, u := range allowed {
		if strings.EqualFold(u, wreply) || strings.HasPrefix(wreply, u) {
			return true
		}
	}
	return len(allowed) == 0 // if no restrictions set, allow any
}

func loadSAMLCert(ctx context.Context, samlR *repository.SAMLRepository, orgR *repository.OrgRepository,
	cfg *config.Config, orgSlug string, orgID uuid.UUID,
) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Reuse the SAML IdP cert/key (auto-generates if not present).
	idpCfg := eursaml.IDPConfig{
		OrgSlug:   orgSlug,
		OrgID:     orgID,
		IssuerURL: cfg.HTTP.IssuerURLFromBase(cfg.Auth.IssuerBase, orgSlug),
	}
	idp, err := eursaml.NewIDP(ctx, cfg, samlR, orgR, idpCfg)
	if err != nil {
		return nil, nil, err
	}
	key, ok := idp.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("wsfed: IdP key is not RSA")
	}
	return idp.Certificate, key, nil
}

func b64cert(der []byte) string {
	return base64.StdEncoding.EncodeToString(der)
}
