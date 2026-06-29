package handler

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/spid"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// SPIDHandler manages SPID SP configuration and the SSO flow.
type SPIDHandler struct {
	repo    *repository.SPIDRepository
	users   *repository.UserRepository
	orgs    *repository.OrgRepository
	store   *session.Store
	oid4w   *repository.OID4WRepository
	baseURL string
}

func NewSPIDHandler(pool *pgxpool.Pool, store *session.Store, baseURL string) *SPIDHandler {
	return &SPIDHandler{
		repo:    repository.NewSPIDRepository(pool),
		users:   repository.NewUserRepository(pool),
		orgs:    repository.NewOrgRepository(pool),
		store:   store,
		oid4w:   repository.NewOID4WRepository(pool),
		baseURL: baseURL,
	}
}

// ── Instance config (global admin) ────────────────────────────────────────────

// GetInstanceConfig returns the SPID instance-level SP config.
// GET /api/v1/admin/spid/instance-config
func (h *SPIDHandler) GetInstanceConfig(c echo.Context) error {
	cfg, err := h.repo.GetSPIDInstanceConfig(c.Request().Context())
	if err != nil || cfg == nil {
		return echo.NewHTTPError(http.StatusNotFound, "SPID instance not configured")
	}
	return c.JSON(http.StatusOK, cfg)
}

type upsertSPIDInstanceRequest struct {
	EntityID       string  `json:"entity_id"        validate:"required,url"`
	OrgName        string  `json:"org_name"         validate:"required"`
	OrgDisplayName string  `json:"org_display_name" validate:"required"`
	OrgLocality    string  `json:"org_locality"     validate:"required"`
	OrgURL         string  `json:"org_url"          validate:"required,url"`
	ContactEmail   string  `json:"contact_email"    validate:"required,email"`
	ContactPhone   *string `json:"contact_phone"`
	VATNumber      *string `json:"vat_number"`
	IPACode        *string `json:"ipa_code"`
	EntityType     string  `json:"entity_type"      validate:"required,oneof=private public"`
}

// UpsertInstanceConfig creates or updates the SPID instance config.
// Auto-generates the signing certificate on first save.
// PUT /api/v1/admin/spid/instance-config
func (h *SPIDHandler) UpsertInstanceConfig(c echo.Context) error {
	ctx := c.Request().Context()
	var req upsertSPIDInstanceRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}

	existing, _ := h.repo.GetSPIDInstanceConfig(ctx)

	m := &models.SPIDInstanceConfig{
		EntityID:       req.EntityID,
		OrgName:        req.OrgName,
		OrgDisplayName: req.OrgDisplayName,
		OrgLocality:    req.OrgLocality,
		OrgURL:         req.OrgURL,
		ContactEmail:   req.ContactEmail,
		ContactPhone:   req.ContactPhone,
		VATNumber:      req.VATNumber,
		IPACode:        req.IPACode,
		EntityType:     req.EntityType,
	}

	// Auto-generate cert/key on first save.
	if existing == nil || existing.SpCertPem == nil {
		var orgIdentifier string
		if req.EntityType == "public" && req.IPACode != nil && *req.IPACode != "" {
			orgIdentifier = "PA:IT-" + *req.IPACode
		} else if req.VATNumber != nil && *req.VATNumber != "" {
			orgIdentifier = "VATIT-" + *req.VATNumber
		}
		_, _, certPEM, keyPEM, err := spid.GenerateCert(spid.CertOptions{
			OrgName:         req.OrgName,
			OrgLocality:     req.OrgLocality,
			OrgIdentifier:   orgIdentifier,
			EIDASIdentifier: orgIdentifier,
		})
		if err != nil {
			return echo.ErrInternalServerError
		}
		m.SpCertPem = &certPEM
		m.SpKeyPem = &keyPEM
		log.Info().Msg("spid: auto-generated instance signing certificate")
	}

	saved, err := h.repo.UpsertSPIDInstanceConfig(ctx, m)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, saved)
}

// ── Per-org config ─────────────────────────────────────────────────────────────

// GetConfig returns the per-org SPID authentication preferences.
// GET /api/v1/organizations/:org_id/spid/config
func (h *SPIDHandler) GetConfig(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	cfg, err := h.repo.GetSPIDConfig(c.Request().Context(), orgID)
	if err != nil || cfg == nil {
		return echo.NewHTTPError(http.StatusNotFound, "SPID not configured for this organization")
	}
	return c.JSON(http.StatusOK, cfg)
}

type upsertSPIDConfigRequest struct {
	AuthnLevel   int      `json:"authn_level"  validate:"min=1,max=3"`
	AttributeSet []string `json:"attribute_set"`
	IsActive     bool     `json:"is_active"`
}

// UpsertConfig creates or updates the per-org SPID authentication preferences.
// PUT /api/v1/organizations/:org_id/spid/config
func (h *SPIDHandler) UpsertConfig(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req upsertSPIDConfigRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	if len(req.AttributeSet) == 0 {
		req.AttributeSet = spid.AttributeSetMinimo
	}
	if req.AuthnLevel == 0 {
		req.AuthnLevel = 2
	}

	saved, err := h.repo.UpsertSPIDConfig(ctx, &models.SPIDConfig{
		OrgID:        orgID,
		AuthnLevel:   req.AuthnLevel,
		AttributeSet: req.AttributeSet,
		IsActive:     req.IsActive,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, saved)
}

// ── SP Metadata ────────────────────────────────────────────────────────────────

// GetMetadataAdmin returns the signed SP metadata XML (admin preview).
// GET /api/v1/admin/spid/metadata
func (h *SPIDHandler) GetMetadataAdmin(c echo.Context) error {
	return h.serveMetadata(c)
}

// Metadata returns the signed SP metadata XML (public endpoint for AgID).
// GET /spid/metadata
func (h *SPIDHandler) Metadata(c echo.Context) error {
	return h.serveMetadata(c)
}

func (h *SPIDHandler) serveMetadata(c echo.Context) error {
	ctx := c.Request().Context()
	instCfg, err := h.repo.GetSPIDInstanceConfig(ctx)
	if err != nil || instCfg == nil {
		return echo.ErrNotFound
	}
	sp, err := h.buildSPFromInstance(instCfg, 2, spid.AttributeSetMinimo)
	if err != nil {
		return echo.ErrInternalServerError
	}
	xmlBytes, err := sp.MetadataXMLSigned()
	if err != nil {
		log.Error().Err(err).Msg("spid: generate metadata xml")
		return echo.ErrInternalServerError
	}
	return c.Blob(http.StatusOK, "application/samlmetadata+xml", xmlBytes)
}

// ── IdP registry ───────────────────────────────────────────────────────────────

// ListIdPs returns the list of active SPID identity providers (for the IdP picker UI).
// GET /:org_slug/spid/idps
func (h *SPIDHandler) ListIdPs(c echo.Context) error {
	ctx := c.Request().Context()
	includeTest := c.QueryParam("include_test") == "true"
	idps, err := h.repo.ListIdPs(ctx, includeTest)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, idps)
}

// ── SSO flow ───────────────────────────────────────────────────────────────────

// StartSSO initiates the SPID authentication flow.
// GET /:org_slug/spid/sso/:idp_id?login_session_id=...
func (h *SPIDHandler) StartSSO(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	idpIDStr := c.Param("idp_id")
	loginSessionID := c.QueryParam("login_session_id")
	if loginSessionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}

	idpID, err := uuid.Parse(idpIDStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid idp_id")
	}

	orgRepo := repository.NewOrgRepository(h.repo.Pool())
	org, err := orgRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.ErrNotFound
	}

	cfg, err := h.repo.GetSPIDConfig(ctx, org.ID)
	if err != nil || cfg == nil || !cfg.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "SPID non configurato per questa organizzazione")
	}

	instCfg, err := h.repo.GetSPIDInstanceConfig(ctx)
	if err != nil || instCfg == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "SPID instance non configurata — contattare l'amministratore")
	}

	idpEntry, err := h.repo.GetIdPByID(ctx, idpID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "IdP non trovato")
	}

	if idpEntry.MetadataXML == nil || needsRefresh(idpEntry.MetadataFetchedAt) {
		if err := h.refreshIdPMetadata(ctx, idpEntry); err != nil {
			log.Warn().Err(err).Str("entity_id", idpEntry.EntityID).Msg("spid: metadata refresh failed, using cached")
			if idpEntry.MetadataXML == nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, "impossibile contattare l'IdP SPID selezionato")
			}
		}
	}

	sp, err := h.buildSPFromInstance(instCfg, cfg.AuthnLevel, cfg.AttributeSet)
	if err != nil {
		return echo.ErrInternalServerError
	}

	meta, _, err := spid.ParseIDPMetadataURL(ctx, idpEntry.MetadataURL)
	if err != nil || meta == nil {
		if idpEntry.MetadataXML != nil {
			log.Warn().Str("entity_id", idpEntry.EntityID).Msg("spid: using raw metadata URL as SSO URL fallback")
		}
	}

	ssoURL := idpEntry.MetadataURL
	if meta != nil {
		if u, e := spid.ExtractIDPSSOURL(meta); e == nil {
			ssoURL = u
		}
	}

	relayState := newRandomToken()
	requestID, htmlForm, err := sp.MakeAuthnRequest(ctx, ssoURL, relayState, middleware.GetCSPNonce(c))
	if err != nil {
		log.Error().Err(err).Msg("spid: make authn request")
		return echo.ErrInternalServerError
	}

	if err := h.store.SaveSPIDState(ctx, relayState, &session.SPIDState{
		RequestID:      requestID,
		LoginSessionID: loginSessionID,
		OrgSlug:        orgSlug,
		OrgID:          org.ID.String(),
		IdPEntityID:    idpEntry.EntityID,
	}); err != nil {
		return echo.ErrInternalServerError
	}

	return c.HTMLBlob(http.StatusOK, htmlForm)
}

// UpgradeSSO initiates a SPID level upgrade for an existing login session.
// GET /:org_slug/spid/upgrade?login_session_id=...
func (h *SPIDHandler) UpgradeSSO(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	loginSessionID := c.QueryParam("login_session_id")
	if loginSessionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "login_session_id required")
	}

	loginSess, err := h.store.GetLoginSession(ctx, loginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "login session expired — please start over")
	}
	if loginSess.RequiredSPIDLevel == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no SPID level upgrade pending for this session")
	}

	orgRepo := repository.NewOrgRepository(h.repo.Pool())
	org, err := orgRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		return echo.ErrNotFound
	}

	cfg, err := h.repo.GetSPIDConfig(ctx, org.ID)
	if err != nil || cfg == nil || !cfg.IsActive {
		return echo.NewHTTPError(http.StatusNotFound, "SPID non configurato per questa organizzazione")
	}

	instCfg, err := h.repo.GetSPIDInstanceConfig(ctx)
	if err != nil || instCfg == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "SPID instance non configurata")
	}

	var idpEntry *models.SPIDIdP
	if loginSess.LastSPIDIdPEntityID != "" {
		idpEntry, _ = h.repo.GetIdPByEntityID(ctx, loginSess.LastSPIDIdPEntityID)
	}
	if idpEntry == nil {
		pickerURL := "/" + orgSlug + "/spid?login_session_id=" + loginSessionID +
			"&level=" + strconv.Itoa(loginSess.RequiredSPIDLevel)
		return c.Redirect(http.StatusFound, pickerURL)
	}

	if idpEntry.MetadataXML == nil || needsRefresh(idpEntry.MetadataFetchedAt) {
		if err := h.refreshIdPMetadata(ctx, idpEntry); err != nil {
			log.Warn().Err(err).Str("entity_id", idpEntry.EntityID).Msg("spid: upgrade metadata refresh failed, using cached")
			if idpEntry.MetadataXML == nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, "impossibile contattare l'IdP SPID selezionato")
			}
		}
	}

	sp, err := h.buildSPFromInstance(instCfg, loginSess.RequiredSPIDLevel, cfg.AttributeSet)
	if err != nil {
		return echo.ErrInternalServerError
	}

	ssoURL := idpEntry.MetadataURL
	meta, _, err := spid.ParseIDPMetadataURL(ctx, idpEntry.MetadataURL)
	if err == nil && meta != nil {
		if u, e := spid.ExtractIDPSSOURL(meta); e == nil {
			ssoURL = u
		}
	}

	relayState := newRandomToken()
	requestID, htmlForm, err := sp.MakeAuthnRequestWithLevel(ctx, ssoURL, relayState, middleware.GetCSPNonce(c), loginSess.RequiredSPIDLevel)
	if err != nil {
		log.Error().Err(err).Msg("spid: make upgrade authn request")
		return echo.ErrInternalServerError
	}

	if err := h.store.SaveSPIDState(ctx, relayState, &session.SPIDState{
		RequestID:      requestID,
		LoginSessionID: loginSessionID,
		OrgSlug:        orgSlug,
		OrgID:          org.ID.String(),
		IdPEntityID:    idpEntry.EntityID,
	}); err != nil {
		return echo.ErrInternalServerError
	}

	return c.HTMLBlob(http.StatusOK, htmlForm)
}

// CallbackSSO processes the SAMLResponse POSTed back by the SPID IdP.
// POST /spid/callback  (global) or  POST /:org_slug/spid/callback  (legacy)
func (h *SPIDHandler) CallbackSSO(c echo.Context) error {
	ctx := c.Request().Context()

	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")
	if samlResponse == "" || relayState == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "SAMLResponse e RelayState obbligatori")
	}

	state, err := h.store.GetSPIDState(ctx, relayState)
	if err != nil || state == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "sessione SPID scaduta o non valida — riprovare")
	}

	loginSess, err := h.store.GetLoginSession(ctx, state.LoginSessionID)
	if err != nil || loginSess == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "sessione di login scaduta — riprovare dall'inizio")
	}

	orgID, _ := uuid.Parse(state.OrgID)
	cfg, err := h.repo.GetSPIDConfig(ctx, orgID)
	if err != nil || cfg == nil {
		return echo.ErrInternalServerError
	}

	instCfg, err := h.repo.GetSPIDInstanceConfig(ctx)
	if err != nil || instCfg == nil {
		return echo.ErrInternalServerError
	}

	sp, err := h.buildSPFromInstance(instCfg, cfg.AuthnLevel, cfg.AttributeSet)
	if err != nil {
		return echo.ErrInternalServerError
	}

	idpEntry, idpErr := h.repo.GetIdPByEntityID(ctx, state.IdPEntityID)
	if idpErr != nil || idpEntry == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "IdP SPID sconosciuto")
	}
	idpCert := spidCertFromEntry(idpEntry)
	if idpCert == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "certificato di firma IdP non disponibile") //nolint:misspell 
	}
	identity, err := sp.ParseResponse(samlResponse, state.RequestID, idpCert)
	if err != nil {
		log.Warn().Err(err).Str("org_id", state.OrgID).Msg("spid: assertion validation failed")
		return echo.NewHTTPError(http.StatusUnauthorized, "autenticazione SPID non valida")
	}

	email := identity.Email
	if email == "" && identity.FiscalNumber != "" {
		email = strings.ToLower(identity.FiscalNumber) + "@spid.internal"
	}
	user, err := h.users.GetByEmail(ctx, orgID, email)
	if err != nil {
		fn := &identity.Name
		ln := &identity.FamilyName
		user, err = h.users.Create(ctx, orgID, email, fn, ln)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "provisioning utente fallito")
		}
		applyAutoEnrollRole(ctx, h.orgs, h.users, orgID, user)
	}
	if !user.IsActive {
		return echo.NewHTTPError(http.StatusForbidden, "account disabilitato")
	}

	spidLoA := "low"
	if identity.Level >= 3 {
		spidLoA = "high"
	} else if identity.Level >= 2 {
		spidLoA = "substantial"
	}
	storeIDAMetadata(h.users, user.ID, spidIDAMetadata(identity.FiscalNumber, spidLoA))
	storeSPIDIdentityClaims(h.users, user.ID, identity)

	offerURIs := createIdpCredentialOffers(ctx, h.oid4w, h.baseURL, orgID, user, state.OrgSlug, "spid")

	loginSess.UserID = user.ID.String()
	loginSess.MFAPending = false
	loginSess.LastSPIDIdPEntityID = state.IdPEntityID
	if loginSess.RequiredSPIDLevel > 0 {
		if identity.Level < loginSess.RequiredSPIDLevel {
			return echo.NewHTTPError(http.StatusForbidden,
				"livello di autenticazione SPID insufficiente — riprovare con un IdP che supporti il livello richiesto")
		}
		loginSess.RequiredSPIDLevel = 0
	}
	if err := h.store.SaveLoginSession(ctx, loginSess, 5*time.Minute); err != nil {
		return echo.ErrInternalServerError
	}

	resumeURL := "/" + state.OrgSlug + "/authorize/resume?login_session_id=" + state.LoginSessionID
	if len(offerURIs) > 0 {
		resumeURL += "&credential_offer_uri=" + url.QueryEscape(offerURIs[0])
	}
	return c.Redirect(http.StatusFound, resumeURL)
}

// storeSPIDIdentityClaims persists the verified SPID identity claims in user metadata.
func storeSPIDIdentityClaims(users *repository.UserRepository, userID uuid.UUID, id *spid.SPIDIdentity) {
	patch := map[string]interface{}{
		"spid_fiscal_number": id.FiscalNumber,
		"spid_name":          id.Name,
		"spid_family_name":   id.FamilyName,
		"spid_level":         id.Level,
	}
	if id.DateOfBirth != "" {
		patch["spid_date_of_birth"] = id.DateOfBirth
	}
	if id.PlaceOfBirth != "" {
		patch["spid_place_of_birth"] = id.PlaceOfBirth
	}
	if id.Email != "" {
		patch["spid_email"] = id.Email
	}
	if id.MobilePhone != "" {
		patch["spid_mobile_phone"] = id.MobilePhone
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := users.MergeMetadata(bctx, userID, patch); err != nil {
			log.Warn().Err(err).Str("user_id", userID.String()).
				Msg("spid: failed to store identity claims in user metadata")
		}
	}()
}

// ── Helpers ────────────────────────────────────────────────────────────────────

// buildSPFromInstance constructs a spid.ServiceProvider from the instance config
// plus per-org authentication preferences.
func (h *SPIDHandler) buildSPFromInstance(inst *models.SPIDInstanceConfig, authnLevel int, attributeSet []string) (*spid.ServiceProvider, error) {
	if inst.SpCertPem == nil || inst.SpKeyPem == nil {
		return nil, echo.NewHTTPError(http.StatusPreconditionFailed, "SP certificate not configured — configure the SPID instance first")
	}
	cert, key, err := spid.ParseCertAndKey(*inst.SpCertPem, *inst.SpKeyPem)
	if err != nil {
		return nil, err
	}
	return spid.New(&spid.SPConfig{
		EntityID:       inst.EntityID,
		OrgName:        inst.OrgName,
		OrgDisplayName: inst.OrgDisplayName,
		OrgLocality:    inst.OrgLocality,
		OrgURL:         inst.OrgURL,
		ContactEmail:   inst.ContactEmail,
		ContactPhone:   derefStr(inst.ContactPhone),
		VATNumber:      derefStr(inst.VATNumber),
		IPACode:        derefStr(inst.IPACode),
		EntityType:     inst.EntityType,
		AuthnLevel:     authnLevel,
		AttributeSet:   attributeSet,
		ACSURL:         h.baseURL + "/spid/callback",
		Certificate:    cert,
		PrivateKey:     key,
	})
}

func (h *SPIDHandler) refreshIdPMetadata(ctx context.Context, idp *models.SPIDIdP) error {
	_, xmlStr, err := spid.ParseIDPMetadataURL(ctx, idp.MetadataURL)
	if err != nil {
		return err
	}
	idp.MetadataXML = &xmlStr
	return h.repo.SaveIdPMetadata(ctx, idp.EntityID, xmlStr)
}

func needsRefresh(t *time.Time) bool {
	return t == nil || time.Since(*t) > 24*time.Hour
}

func spidCertFromEntry(idp *models.SPIDIdP) *x509.Certificate {
	if idp == nil || idp.MetadataXML == nil || *idp.MetadataXML == "" {
		log.Warn().Str("entity_id", func() string {
			if idp != nil {
				return idp.EntityID
			}
			return ""
		}()).Msg("spid: IdP metadata not cached — SAML signature verification skipped")
		return nil
	}
	var ed crewsaml.EntityDescriptor
	if err := xml.Unmarshal([]byte(*idp.MetadataXML), &ed); err != nil {
		log.Error().Err(err).Str("entity_id", idp.EntityID).Msg("spid: failed to parse IdP metadata XML")
		return nil
	}
	cert, err := spid.ExtractIDPSigningCert(&ed)
	if err != nil {
		log.Error().Err(err).Str("entity_id", idp.EntityID).Msg("spid: no signing cert in IdP metadata")
		return nil
	}
	return cert
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func newRandomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
