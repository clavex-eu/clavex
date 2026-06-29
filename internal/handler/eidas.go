package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/eidas"
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

// EidasHandler manages the eIDAS node integration — SP config and SSO flow.
type EidasHandler struct {
	repo  *repository.EidasRepository
	users *repository.UserRepository
	orgs  *repository.OrgRepository
	store *session.Store
}

func NewEidasHandler(pool *pgxpool.Pool, store *session.Store) *EidasHandler {
	return &EidasHandler{
		repo:  repository.NewEidasRepository(pool),
		users: repository.NewUserRepository(pool),
		orgs:  repository.NewOrgRepository(pool),
		store: store,
	}
}

// ── Admin CRUD ─────────────────────────────────────────────────────────────────

type upsertEidasConfigRequest struct {
	EntityID       string `json:"entity_id"        validate:"required"`
	EidasNodeURL   string `json:"eidas_node_url"   validate:"required,url"`
	ACSURL         string `json:"acs_url"          validate:"required,url"`
	IdpCertPem     string `json:"idp_cert_pem"     validate:"required"` // eIDAS Node certificate (PEM)
	SpCertPem      string `json:"sp_cert_pem"`                          // leave empty to auto-generate
	SpKeyPem       string `json:"sp_key_pem"`                           // leave empty to auto-generate
	RequestedLoA   string `json:"requested_loa"`
	OrgName        string `json:"org_name"         validate:"required"`
	OrgDisplayName string `json:"org_display_name" validate:"required"`
	OrgURL         string `json:"org_url"          validate:"required,url"`
	ContactEmail   string `json:"contact_email"    validate:"required,email"`
	IsActive       bool   `json:"is_active"`
}

// GetConfig returns the eIDAS config for the org (key material is omitted).
// GET /api/v1/organizations/:org_id/eidas
func (h *EidasHandler) GetConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	cfg, err := h.repo.GetConfig(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if cfg == nil {
		return echo.NewHTTPError(http.StatusNotFound, "eIDAS not configured for this organization")
	}
	return c.JSON(http.StatusOK, cfg)
}

// UpsertConfig creates or updates the eIDAS SP config.
// If sp_cert_pem / sp_key_pem are empty, a fresh self-signed certificate is generated.
// PUT /api/v1/organizations/:org_id/eidas
func (h *EidasHandler) UpsertConfig(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req upsertEidasConfigRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if req.RequestedLoA == "" {
		req.RequestedLoA = eidas.LoASubstantial
	}

	certPEM := req.SpCertPem
	keyPEM := req.SpKeyPem
	if certPEM == "" || keyPEM == "" {
		// Auto-generate a self-signed SP certificate.
		newCert, newKey, genErr := eidas.GenerateSelfSignedCert(req.OrgName)
		if genErr != nil {
			log.Error().Err(genErr).Msg("eidas: cert generation failed")
			return echo.ErrInternalServerError
		}
		certPEM = string(newCert)
		keyPEM = string(newKey)
		log.Info().Str("org_id", orgID.String()).Msg("eidas: auto-generated SP signing certificate")
	}

	saved, err := h.repo.Upsert(ctx, &models.EidasConfig{
		OrgID:          orgID,
		EntityID:       req.EntityID,
		EidasNodeURL:   req.EidasNodeURL,
		ACSURL:         req.ACSURL,
		IdpCertPem:     req.IdpCertPem,
		SpCertPem:      certPEM,
		SpKeyPem:       keyPEM,
		RequestedLoA:   req.RequestedLoA,
		OrgName:        req.OrgName,
		OrgDisplayName: req.OrgDisplayName,
		OrgURL:         req.OrgURL,
		ContactEmail:   req.ContactEmail,
		IsActive:       req.IsActive,
	})
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("eidas: upsert config failed")
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, saved)
}

// Metadata serves SAML 2.0 SP metadata XML for submission to the eIDAS node operator.
// GET /api/v1/organizations/:org_id/eidas/metadata
func (h *EidasHandler) Metadata(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	cfg, err := h.repo.GetConfig(ctx, orgID)
	if err != nil || cfg == nil {
		return echo.NewHTTPError(http.StatusNotFound, "eIDAS not configured")
	}
	sp, buildErr := buildSP(cfg)
	if buildErr != nil {
		return buildErr
	}
	xmlBytes, err := sp.MetadataXML()
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.Blob(http.StatusOK, "application/xml; charset=utf-8", xmlBytes)
}

// ── SSO flow ───────────────────────────────────────────────────────────────────

// StartSSO initiates the eIDAS authentication flow by redirecting the browser
// to the national eIDAS Connector/Node with a signed AuthnRequest.
// GET /:org_slug/eidas/sso
func (h *EidasHandler) StartSSO(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.eidas.start_sso")
	defer span.End()
	span.SetAttributes(attribute.String("org_slug", orgSlug))

	loginSessionID := c.QueryParam("login_session_id")
	if loginSessionID == "" {
		span.SetStatus(otelcodes.Error, "login_session_id required")
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}

	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil || org == nil {
		return echo.NewHTTPError(http.StatusNotFound, "organization not found")
	}
	cfg, err := h.repo.GetConfig(ctx, org.ID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if cfg == nil || !cfg.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "eIDAS not configured for this organization")
	}

	sp, buildErr := buildSP(cfg)
	if buildErr != nil {
		return buildErr
	}

	// Generate a cryptographically random relay-state token used to look up the
	// login session when the eIDAS node POSTs back the SAMLResponse.
	relayState, err := randomHex(16)
	if err != nil {
		return echo.ErrInternalServerError
	}

	redirectURL, requestID, err := sp.BuildAuthnRequestURL(relayState)
	if err != nil {
		log.Error().Err(err).Str("org_id", org.ID.String()).Msg("eidas: build authn request failed")
		return echo.ErrInternalServerError
	}

	if err := h.store.SaveEidasState(ctx, relayState, &session.EidasState{
		LoginSessionID: loginSessionID,
		OrgSlug:        orgSlug,
		OrgID:          org.ID.String(),
		RequestID:      requestID,
	}); err != nil {
		return echo.ErrInternalServerError
	}

	return c.Redirect(http.StatusFound, redirectURL)
}

// CallbackSSO handles the HTTP-POST from the eIDAS node with the signed SAMLResponse.
// POST /:org_slug/eidas/callback
func (h *EidasHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()
	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.eidas.callback_sso")
	defer span.End()

	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")
	if samlResponse == "" || relayState == "" {
		span.SetStatus(otelcodes.Error, "missing SAMLResponse or RelayState")
		return echo.NewHTTPError(http.StatusBadRequest, "SAMLResponse and RelayState are required")
	}

	state, err := h.store.GetEidasState(ctx, relayState)
	if err != nil || state == nil {
		span.SetStatus(otelcodes.Error, "eIDAS session expired or invalid")
		return echo.NewHTTPError(http.StatusBadRequest, "eIDAS session expired or invalid — please try again")
	}

	loginSess, err := h.store.GetLoginSession(ctx, state.LoginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please restart the login flow")
	}

	orgID, _ := uuid.Parse(state.OrgID)
	cfg, err := h.repo.GetConfig(ctx, orgID)
	if err != nil || cfg == nil {
		return echo.ErrInternalServerError
	}

	sp, buildErr := buildSP(cfg)
	if buildErr != nil {
		return buildErr
	}

	identity, err := sp.ParseAssertion(samlResponse, state.RequestID, []byte(cfg.IdpCertPem))
	if err != nil {
		log.Warn().Err(err).Str("org_id", state.OrgID).Msg("eidas: assertion validation failed")
		return echo.NewHTTPError(http.StatusUnauthorized, "eIDAS authentication failed")
	}

	// Determine the email to use.
	// eIDAS does not mandate email — we synthesise a stable address from PersonIdentifier.
	org, err := h.orgs.GetBySlug(ctx, state.OrgSlug)
	if err != nil || org == nil {
		return echo.ErrInternalServerError
	}
	email := identity.SynthesiseEmail(org.Slug + ".eidas")

	// JIT provision: find or create the user.
	user, err := h.users.GetByEmail(ctx, orgID, email)
	if err != nil {
		fn := identity.FirstName
		ln := identity.FamilyName
		user, err = h.users.Create(ctx, orgID, email, &fn, &ln)
		if err != nil {
			log.Error().Err(err).Str("email", email).Msg("eidas: JIT user provision failed")
			return echo.NewHTTPError(http.StatusInternalServerError, "user provisioning failed")
		}
		applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "account disabled")
	}

	// OpenID Connect for Identity Assurance 1.0: store eIDAS verification evidence.
	storeIDAMetadata(h.users, user.ID, eidasIDAMetadata(identity.LevelOfAssurance, identity.CitizenCountry))

	// Update the login session and resume the OIDC authorize flow.
	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + state.OrgSlug + "/authorize/resume?login_session_id=" + state.LoginSessionID
	return c.Redirect(http.StatusFound, resumeURL)
}

// ── Private helpers ────────────────────────────────────────────────────────────

// buildSP constructs an eidas.ServiceProvider from a stored EidasConfig.
func buildSP(cfg *models.EidasConfig) (*eidas.ServiceProvider, error) {
	block, _ := pem.Decode([]byte(cfg.SpCertPem))
	if block == nil {
		return nil, echo.NewHTTPError(http.StatusPreconditionFailed, "SP certificate not configured")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, echo.ErrInternalServerError
	}
	key, err := parsePrivateKey([]byte(cfg.SpKeyPem))
	if err != nil {
		return nil, echo.ErrInternalServerError
	}
	sp := eidas.New(eidas.SPConfig{
		EntityID:                    cfg.EntityID,
		AssertionConsumerServiceURL: cfg.ACSURL,
		OrgName:                     cfg.OrgName,
		OrgDisplayName:              cfg.OrgDisplayName,
		OrgURL:                      cfg.OrgURL,
		ContactEmail:                cfg.ContactEmail,
		Certificate:                 cert,
		PrivateKey:                  key,
		EidasNodeURL:                cfg.EidasNodeURL,
		RequestedLoA:                cfg.RequestedLoA,
	})
	return sp, nil
}

// randomHex returns n cryptographically random bytes as a lower-case hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// parsePrivateKey parses a PKCS#1 RSA private key from PEM.
func parsePrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, echo.NewHTTPError(http.StatusPreconditionFailed, "SP private key not configured")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
