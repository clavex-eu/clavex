package handler

import (
	"embed"
	"encoding/xml"
	"html/template"
	"net/http"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	eursaml "github.com/clavex-eu/clavex/internal/saml"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

//go:embed templates/saml_login.html
var samlTemplateFS embed.FS

var samlLoginTmpl = template.Must(
	template.ParseFS(samlTemplateFS, "templates/saml_login.html"),
)

// SAMLHandler handles SAML 2.0 IdP endpoints.
type SAMLHandler struct {
	cfg      *config.Config
	samlRepo *repository.SAMLRepository
	orgRepo  *repository.OrgRepository
	userRepo *repository.UserRepository
	store    *session.Store
}

func NewSAMLHandler(cfg *config.Config, pool *pgxpool.Pool, rdb redis.UniversalClient) *SAMLHandler {
	return &SAMLHandler{
		cfg:      cfg,
		samlRepo: repository.NewSAMLRepository(pool),
		orgRepo:  repository.NewOrgRepository(pool),
		userRepo: repository.NewUserRepository(pool),
		store:    session.NewStore(rdb),
	}
}

// Metadata returns the SAML IdP metadata XML for the given org.
// GET /:org_slug/saml/metadata
func (h *SAMLHandler) Metadata(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	org, err := h.orgRepo.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	idp, err := eursaml.NewIDP(ctx, h.cfg, h.samlRepo, h.orgRepo, eursaml.IDPConfig{
		OrgSlug:   orgSlug,
		OrgID:     org.ID,
		IssuerURL: h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug),
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "saml idp unavailable")
	}

	meta := idp.Metadata()
	metaXML, err := xml.Marshal(meta)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "saml metadata marshal error")
	}

	c.Response().Header().Set("Content-Type", "application/samlmetadata+xml")
	return c.Blob(http.StatusOK, "application/samlmetadata+xml", metaXML)
}

// SSO handles SP-initiated SSO (HTTP-Redirect and HTTP-POST bindings).
// GET|POST /:org_slug/saml/sso
func (h *SAMLHandler) SSO(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	org, err := h.orgRepo.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	idp, err := eursaml.NewIDP(ctx, h.cfg, h.samlRepo, h.orgRepo, eursaml.IDPConfig{
		OrgSlug:   orgSlug,
		OrgID:     org.ID,
		IssuerURL: h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug),
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "saml idp unavailable")
	}

	idp.SessionProvider = &eursaml.LoginSessionProvider{
		OrgSlug:   orgSlug,
		OrgID:     org.ID,
		OrgName:   org.Name,
		LogoURL:   org.LogoURL,
		Store:     h.store,
		Users:     h.userRepo,
		LoginTmpl: samlLoginTmpl,
		Nonce:     middleware.GetCSPNonce(c),
	}

	// Delegate entirely to crewjam/saml — it handles redirect/POST binding,
	// parses AuthnRequest, calls SessionProvider.GetSession, and writes the
	// SAMLResponse back to the SP.
	idp.ServeSSO(c.Response(), c.Request())
	return nil
}

// SLO handles Single Logout requests (HTTP-POST binding).
// POST /:org_slug/saml/slo
func (h *SAMLHandler) SLO(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	org, err := h.orgRepo.GetBySlug(ctx, orgSlug)
	if err != nil || !org.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}

	idp, err := eursaml.NewIDP(ctx, h.cfg, h.samlRepo, h.orgRepo, eursaml.IDPConfig{
		OrgSlug:   orgSlug,
		OrgID:     org.ID,
		IssuerURL: h.cfg.HTTP.IssuerURLFromBase(h.cfg.Auth.IssuerBase, orgSlug),
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "saml idp unavailable")
	}

	// crewjam/saml does not expose a dedicated SLO handler on IdentityProvider;
	// respond with a success LogoutResponse so the SP completes the flow.
	_ = idp
	return c.NoContent(http.StatusOK)
}

// ── Admin CRUD for SAML service providers ────────────────────────────────────

// CreateSP registers a new service provider for an org.
// POST /api/v1/organizations/:org_id/saml/sps
func (h *SAMLHandler) CreateSP(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	var req struct {
		EntityID     string  `json:"entity_id"     validate:"required"`
		Name         string  `json:"name"          validate:"required"`
		ACSURL       string  `json:"acs_url"       validate:"required,url"`
		SLOURL       *string `json:"slo_url"`
		MetadataXML  *string `json:"metadata_xml"`
		NameIDFormat string  `json:"name_id_format"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.NameIDFormat == "" {
		req.NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"
	}

	sp, err := h.samlRepo.CreateSP(c.Request().Context(), repository.CreateSAMLSPParams{
		OrgID:        orgID,
		EntityID:     req.EntityID,
		Name:         req.Name,
		ACSURL:       req.ACSURL,
		SLOURL:       req.SLOURL,
		MetadataXML:  req.MetadataXML,
		NameIDFormat: req.NameIDFormat,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, sp)
}

// ListSPs returns all SPs registered for an org.
// GET /api/v1/organizations/:org_id/saml/sps
func (h *SAMLHandler) ListSPs(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	sps, err := h.samlRepo.ListSPsByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, sps)
}

// DeleteSP removes a service provider.
// DELETE /api/v1/organizations/:org_id/saml/sps/:sp_id
func (h *SAMLHandler) DeleteSP(c echo.Context) error {
	spID, err := uuid.Parse(c.Param("sp_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid sp_id")
	}
	if err := h.samlRepo.DeleteSP(c.Request().Context(), spID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.NoContent(http.StatusNoContent)
}
