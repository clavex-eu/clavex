package handler

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/bundidsaml"
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

// BundIDSAMLHandler manages BundID SAML SP configuration and the SSO flow.
//
// BundID is the German federal digital identity portal operated by FITKO.
// It uses SAML 2.0 with HTTP-POST binding and eIDAS attribute names.
//
// Registration workflow:
//  1. Admin calls PUT /api/v1/organizations/:id/bundid-saml/config to save SP settings.
//     A self-signed SP certificate is auto-generated and stored.
//  2. Admin downloads SP metadata XML via GET /api/v1/organizations/:id/bundid-saml/metadata
//     and submits it to FITKO at https://id.bund.de/de/fuer-dienstleister/registrierung
//     (integration environment is self-service; production takes 3-5 business days).
//  3. After FITKO approval, admin sets is_active = true.
//  4. Users reach SSO via GET /:org_slug/bundidsaml/sso?login_session_id=...
type BundIDSAMLHandler struct {
	repo  *repository.BundIDSAMLRepository
	users *repository.UserRepository
	orgs  *repository.OrgRepository
	store *session.Store
}

func NewBundIDSAMLHandler(pool *pgxpool.Pool, store *session.Store) *BundIDSAMLHandler {
	return &BundIDSAMLHandler{
		repo:  repository.NewBundIDSAMLRepository(pool),
		users: repository.NewUserRepository(pool),
		orgs:  repository.NewOrgRepository(pool),
		store: store,
	}
}

// ── Admin CRUD ─────────────────────────────────────────────────────────────────

// GetConfig returns the BundID SAML SP config for an org.
// GET /api/v1/organizations/:org_id/bundid-saml/config
func (h *BundIDSAMLHandler) GetConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	cfg, err := h.repo.GetConfig(c.Request().Context(), orgID)
	if err != nil || cfg == nil {
		return echo.NewHTTPError(http.StatusNotFound, "BundID SAML not configured for this organization")
	}
	return c.JSON(http.StatusOK, cfg)
}

type upsertBundIDSAMLConfigRequest struct {
	EntityID       string  `json:"entity_id"        validate:"required,url"`
	OrgName        string  `json:"org_name"         validate:"required"`
	OrgDisplayName string  `json:"org_display_name" validate:"required"`
	OrgURL         string  `json:"org_url"          validate:"required,url"`
	ContactEmail   string  `json:"contact_email"    validate:"required,email"`
	ContactPhone   *string `json:"contact_phone"`
	// Environment: "production" or "integration"
	Environment string `json:"environment" validate:"required,oneof=production integration"`
	// MinLoA: "low" | "substantial" | "high"
	// Determines the SAML AuthnContextClassRef sent in AuthnRequest.
	// Use "substantial" for most citizen services; "high" for nPA (Online-Ausweis).
	MinLoA       string   `json:"min_loa"       validate:"required,oneof=low substantial high"`
	AttributeSet []string `json:"attribute_set"`
	IsActive     bool     `json:"is_active"`
}

// UpsertConfig creates or updates the BundID SAML SP config for an org.
// If no cert/key exists yet, a fresh self-signed RSA-2048 certificate is auto-generated.
// The certificate must be included in the SP metadata submitted to FITKO.
// PUT /api/v1/organizations/:org_id/bundid-saml/config
func (h *BundIDSAMLHandler) UpsertConfig(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req upsertBundIDSAMLConfigRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if len(req.AttributeSet) == 0 {
		req.AttributeSet = bundidsaml.AttributeSetBase
	}

	existing, _ := h.repo.GetConfig(ctx, orgID)

	m := &models.BundIDSAMLConfig{
		OrgID:          orgID,
		EntityID:       req.EntityID,
		OrgName:        req.OrgName,
		OrgDisplayName: req.OrgDisplayName,
		OrgURL:         req.OrgURL,
		ContactEmail:   req.ContactEmail,
		ContactPhone:   req.ContactPhone,
		Environment:    req.Environment,
		MinLoA:         req.MinLoA,
		AttributeSet:   req.AttributeSet,
		IsActive:       req.IsActive,
	}

	// Auto-generate cert/key if not yet present. The cert PEM must be
	// sent to FITKO as part of SP registration.
	if existing == nil || existing.SpCertPem == nil {
		_, _, certPEM, keyPEM, gErr := bundidsaml.GenerateCert()
		if gErr != nil {
			return echo.ErrInternalServerError
		}
		m.SpCertPem = &certPEM
		m.SpKeyPem = &keyPEM
		log.Info().Str("org_id", orgID.String()).Msg("bundidsaml: auto-generated SP signing certificate")
	}

	saved, err := h.repo.UpsertConfig(ctx, m)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, saved)
}

// GetMetadataAdmin returns the BundID SP metadata XML for an org (admin endpoint).
// The XML must be submitted to FITKO during SP registration.
// GET /api/v1/organizations/:org_id/bundid-saml/metadata
func (h *BundIDSAMLHandler) GetMetadataAdmin(c echo.Context) error {
	return h.serveMetadata(c, "org_id")
}

// ── Public SP Metadata ─────────────────────────────────────────────────────────

// Metadata serves the SP metadata XML publicly (referenced as metadataURL to FITKO).
// GET /:org_slug/bundidsaml/metadata
func (h *BundIDSAMLHandler) Metadata(c echo.Context) error {
	return h.serveMetadata(c, "org_slug_lookup")
}

func (h *BundIDSAMLHandler) serveMetadata(c echo.Context, mode string) error {
	ctx := c.Request().Context()
	orgID, err := h.resolveOrgID(c, mode)
	if err != nil {
		return echo.ErrNotFound
	}

	cfg, err := h.repo.GetConfig(ctx, orgID)
	if err != nil || cfg == nil || !cfg.IsActive {
		return echo.ErrNotFound
	}
	sp, err := h.buildSP(c, cfg)
	if err != nil {
		return echo.ErrInternalServerError
	}
	xmlBytes, err := sp.MetadataXML()
	if err != nil {
		log.Error().Err(err).Msg("bundidsaml: generate metadata xml")
		return echo.ErrInternalServerError
	}
	return c.Blob(http.StatusOK, "application/samlmetadata+xml", xmlBytes)
}

// ── SSO flow ───────────────────────────────────────────────────────────────────

// StartSSO initiates the BundID SAML authentication flow.
// The browser is POSTed a self-submitting HTML form (HTTP-POST binding) to BundID.
// GET /:org_slug/bundidsaml/sso?login_session_id=...
func (h *BundIDSAMLHandler) StartSSO(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	loginSessionID := c.QueryParam("login_session_id")
	if loginSessionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}

	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.bundidsaml.start_sso")
	defer span.End()
	span.SetAttributes(attribute.String("org_slug", orgSlug))

	orgRepo := repository.NewOrgRepository(h.repo.Pool())
	org, err := orgRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.ErrNotFound
	}

	cfg, err := h.repo.GetConfig(ctx, org.ID)
	if err != nil || cfg == nil || !cfg.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "BundID nicht konfiguriert für diese Organisation")
	}

	sp, err := h.buildSP(c, cfg)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Fetch BundID IdP SSO URL from metadata (cached per environment for 24 h).
	eps := bundidsaml.GetEndpoints(cfg.Environment)
	idpMeta, _, fetchErr := bundidsaml.ParseIDPMetadataURL(ctx, eps.MetadataURL)
	if fetchErr != nil || idpMeta == nil {
		log.Warn().Err(fetchErr).Str("env", cfg.Environment).Msg("bundidsaml: IdP metadata fetch failed")
		return echo.NewHTTPError(http.StatusServiceUnavailable, "BundID IdP nicht erreichbar — bitte später erneut versuchen")
	}
	ssoURL, err := bundidsaml.ExtractIDPSSOURL(idpMeta)
	if err != nil {
		log.Error().Err(err).Msg("bundidsaml: no SSO URL in IdP metadata")
		return echo.ErrInternalServerError
	}

	relayState := newRandomToken()
	requestID, htmlForm, err := sp.MakeAuthnRequest(ctx, ssoURL, relayState)
	if err != nil {
		log.Error().Err(err).Msg("bundidsaml: make authn request")
		return echo.ErrInternalServerError
	}

	if err := h.store.SaveBundIDSAMLState(ctx, relayState, &session.BundIDSAMLState{
		RequestID:      requestID,
		LoginSessionID: loginSessionID,
		OrgSlug:        orgSlug,
		OrgID:          org.ID.String(),
	}); err != nil {
		return echo.ErrInternalServerError
	}

	return c.HTMLBlob(http.StatusOK, htmlForm)
}

// CallbackSSO processes the SAMLResponse POSTed back by BundID.
// POST /:org_slug/bundidsaml/callback
func (h *BundIDSAMLHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()

	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.bundidsaml.callback_sso")
	defer span.End()

	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")
	if samlResponse == "" || relayState == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "SAMLResponse und RelayState sind erforderlich")
	}

	state, err := h.store.GetBundIDSAMLState(ctx, relayState)
	if err != nil || state == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "BundID-Sitzung abgelaufen — bitte erneut anmelden")
	}

	loginSess, err := h.store.GetLoginSession(ctx, state.LoginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Anmeldesitzung abgelaufen — bitte von vorne beginnen")
	}

	orgID, _ := uuid.Parse(state.OrgID)
	cfg, err := h.repo.GetConfig(ctx, orgID)
	if err != nil || cfg == nil {
		return echo.ErrInternalServerError
	}

	sp, err := h.buildSP(c, cfg)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Fetch IdP signing cert for assertion validation. Reject explicitly when it
	// cannot be resolved rather than parsing against empty metadata.
	idpCert := h.fetchIDPSigningCert(ctx, cfg.Environment)
	if idpCert == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "BundID IdP signing certificate unavailable")
	}

	identity, err := sp.ParseResponse(samlResponse, state.RequestID, idpCert)
	if err != nil {
		log.Warn().Err(err).Str("org_id", state.OrgID).Msg("bundidsaml: assertion validation failed")
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "assertion validation failed")
		return echo.NewHTTPError(http.StatusUnauthorized, "BundID-Authentifizierung ungültig")
	}
	if identity.Sub == "" {
		span.SetStatus(otelcodes.Error, "empty sub")
		return echo.NewHTTPError(http.StatusUnauthorized, "BundID hat keine Identität zurückgegeben")
	}

	// Derive a stable email address from the BundID pseudonymous identifier.
	// BundID only releases email when the user has a verified BundID account AND
	// the service has requested the EmailAddress attribute AND the user consented.
	email := identity.EmailOrSynth()

	user, err := h.users.GetByEmail(ctx, orgID, email)
	if err != nil {
		// JIT provisioning — create a new local user mapped to the BundID-ID.
		fn := &identity.GivenName
		ln := &identity.FamilyName
		user, err = h.users.Create(ctx, orgID, email, fn, ln)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Benutzeranlage fehlgeschlagen")
		}
		applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
		log.Info().
			Str("sub", identity.Sub).
			Str("loa", identity.LoA).
			Bool("synthetic_email", identity.EmailSynthetic).
			Str("org_id", state.OrgID).
			Msg("bundidsaml: jit provisioned user")
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "Konto deaktiviert")
	}

	// OpenID Connect for Identity Assurance 1.0: store BundID SAML verification evidence.
	storeIDAMetadata(h.users, user.ID, bundIDSAMLIDAMetadata(identity.LoA))

	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + state.OrgSlug + "/authorize/resume?login_session_id=" + state.LoginSessionID
	span.SetAttributes(
		attribute.String("org_slug", state.OrgSlug),
		attribute.String("bundid_loa", identity.LoA),
	)
	return c.Redirect(http.StatusFound, resumeURL)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

// buildSP constructs a bundidsaml.ServiceProvider from the stored org config.
func (h *BundIDSAMLHandler) buildSP(c echo.Context, cfg *models.BundIDSAMLConfig) (*bundidsaml.ServiceProvider, error) {
	if cfg.SpCertPem == nil || cfg.SpKeyPem == nil {
		return nil, echo.NewHTTPError(http.StatusPreconditionFailed, "SP-Zertifikat nicht konfiguriert")
	}
	cert, key, err := bundidsaml.ParseCertAndKey(*cfg.SpCertPem, *cfg.SpKeyPem)
	if err != nil {
		return nil, err
	}
	acsURL := buildBundIDSAMLACSURL(c, c.Param("org_slug"))
	sp, err := bundidsaml.New(&bundidsaml.SPConfig{
		EntityID:       cfg.EntityID,
		OrgName:        cfg.OrgName,
		OrgDisplayName: cfg.OrgDisplayName,
		OrgURL:         cfg.OrgURL,
		ContactEmail:   cfg.ContactEmail,
		ContactPhone:   derefStr(cfg.ContactPhone),
		MinLoA:         cfg.MinLoA,
		AttributeSet:   cfg.AttributeSet,
		ACSURL:         acsURL,
		Certificate:    cert,
		PrivateKey:     key,
	})
	return sp, err
}

func buildBundIDSAMLACSURL(c echo.Context, orgSlug string) string {
	scheme := "http"
	if c.Request().TLS != nil || c.Request().Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + c.Request().Host + "/" + orgSlug + "/bundidsaml/callback"
}

func (h *BundIDSAMLHandler) resolveOrgID(c echo.Context, mode string) (uuid.UUID, error) {
	if mode == "org_id" {
		return uuidParam(c, "org_id")
	}
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	orgRepo := repository.NewOrgRepository(h.repo.Pool())
	org, err := orgRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		return uuid.Nil, err
	}
	return org.ID, nil
}

// fetchIDPSigningCert fetches the BundID IdP signing certificate from the live
// metadata URL for assertion signature validation. Returns nil on failure (development
// mode: signature verification is skipped). In production, log a warning and fail safely.
func (h *BundIDSAMLHandler) fetchIDPSigningCert(ctx context.Context, environment string) *x509.Certificate {
	eps := bundidsaml.GetEndpoints(environment)
	meta, _, err := bundidsaml.ParseIDPMetadataURL(ctx, eps.MetadataURL)
	if err != nil || meta == nil {
		log.Warn().Err(err).Str("env", environment).Msg("bundidsaml: could not fetch IdP cert for signature validation")
		return nil
	}
	cert, err := bundidsaml.ExtractIDPSigningCert(meta)
	if err != nil {
		log.Warn().Err(err).Msg("bundidsaml: no signing cert in IdP metadata")
		return nil
	}
	return cert
}
