package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// MdocProximityHandler implements the verifier side of the ISO 18013-5 / eIDAS 2.0
// proximity flow, adapted for OID4VP (ISO 18013-7 / OID4VP draft §B).
//
// Flow overview:
//
//  1. Operator opens POST /:org_slug/mdoc/proximity/start
//     → session created, QR code URI returned
//     → browser renders /mdoc/proximity/:req_id/qr (HTML with QR + polling)
//
//  2. Wallet scans QR code containing:
//       openid4vp://?request_uri=<base>/mdoc/request/<req_id>&client_id=<base>/<org_slug>&nonce=<nonce>
//
//  3. Wallet GETs GET /:org_slug/mdoc/request/:req_id
//     → returns OID4VP AuthorizationRequest (JSON); status → 'scanned'
//
//  4. Wallet selects attributes and POSTs DeviceResponse (CBOR) to:
//       POST /:org_slug/mdoc/response
//     with Content-Type: application/cbor or application/json (base64url-encoded)
//     → IssuerSigned verified, attributes extracted, status → 'completed'
//
//  5. Browser polls GET /:org_slug/mdoc/proximity/:req_id/status
//     → returns {"status":"completed","claims":{...}} when done
//     → browser redirects to redirect_uri or shows attributes inline
//
// Admin endpoints:
//   GET  /api/v1/organizations/:org_id/mdoc/sessions          → list sessions
//   GET  /api/v1/organizations/:org_id/mdoc/sessions/:session_id → get session

const mdocProximityTTL = 10 * time.Minute

type MdocProximityHandler struct {
	repo       *repository.MdocProximityRepository
	orgs       *repository.OrgRepository
	iacaRepo   *repository.IACARepository
	keys       oidc.Signer
	cfg        baseURLProvider
	walletRepo *repository.OID4WRepository
}

func NewMdocProximityHandler(pool *pgxpool.Pool, keys oidc.Signer, cfg baseURLProvider) *MdocProximityHandler {
	return &MdocProximityHandler{
		repo:       repository.NewMdocProximityRepository(pool),
		orgs:       repository.NewOrgRepository(pool),
		iacaRepo:   repository.NewIACARepository(pool),
		keys:       keys,
		cfg:        cfg,
		walletRepo: repository.NewOID4WRepository(pool),
	}
}

// ── Tenant-facing endpoints ───────────────────────────────────────────────────

// StartSession handles POST /:org_slug/mdoc/proximity/start
//
// Body (JSON):
//
//	{
//	  "requested_doc_types": ["eu.europa.ec.eudi.pid.1"],   // optional
//	  "presentation_definition": { ... },                    // optional PEX v2
//	  "redirect_uri": "https://counter.example.com/verified" // optional
//	}
//
// Response:
//
//	{
//	  "session_id":   "<uuid>",
//	  "request_id":  "<base64url>",
//	  "qr_uri":      "openid4vp://?request_uri=...&client_id=...&nonce=...",
//	  "qr_page_url": "/<org_slug>/mdoc/proximity/<req_id>/qr",
//	  "status_url":  "/<org_slug>/mdoc/proximity/<req_id>/status",
//	  "expires_at":  "<ISO8601>"
//	}
func (h *MdocProximityHandler) StartSession(c echo.Context) error {
	ctx := c.Request().Context()

	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}

	var req struct {
		RequestedDocTypes      []string               `json:"requested_doc_types"`
		PresentationDefinition map[string]interface{} `json:"presentation_definition"`
		RedirectURI            *string                `json:"redirect_uri"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.ErrBadRequest
	}

	// Defaults: if no docType specified, request eu.europa.ec.eudi.pid.1.
	if len(req.RequestedDocTypes) == 0 {
		req.RequestedDocTypes = []string{mdoc.DocTypeEuPid}
	}
	if req.PresentationDefinition == nil {
		req.PresentationDefinition = buildDefaultPresentationDef(req.RequestedDocTypes)
	}

	requestID, err := generateRequestID()
	if err != nil {
		return echo.ErrInternalServerError
	}
	nonce, err := generateNonce()
	if err != nil {
		return echo.ErrInternalServerError
	}

	baseURL := h.cfg.BaseURL()
	clientID := baseURL + "/" + org.Slug
	responseURI := baseURL + "/" + org.Slug + "/mdoc/response"
	requestURI := baseURL + "/" + org.Slug + "/mdoc/request/" + requestID
	expiresAt := time.Now().Add(mdocProximityTTL)

	session, err := h.repo.Create(
		ctx,
		org.ID,
		requestID,
		nonce,
		clientID,
		responseURI,
		req.RequestedDocTypes,
		req.PresentationDefinition,
		req.RedirectURI,
		expiresAt,
	)
	if err != nil {
		return echo.ErrInternalServerError
	}

	// Build the OID4VP engagement URI for the QR code.
	// Format follows ISO 18013-7 §8.3.3.1.2 and OID4VP §B.
	qrURI := "openid4vp://?request_uri=" + requestURI +
		"&client_id=" + clientID +
		"&nonce=" + nonce

	return c.JSON(http.StatusCreated, map[string]any{
		"session_id":  session.ID,
		"request_id":  requestID,
		"qr_uri":      qrURI,
		"qr_page_url": "/" + org.Slug + "/mdoc/proximity/" + requestID + "/qr",
		"status_url":  "/" + org.Slug + "/mdoc/proximity/" + requestID + "/status",
		"expires_at":  expiresAt,
	})
}

// QRPage handles GET /:org_slug/mdoc/proximity/:req_id/qr
// Renders an HTML page that displays the QR code and auto-polls the status endpoint.
func (h *MdocProximityHandler) QRPage(c echo.Context) error {
	reqID := c.Param("req_id")
	session, err := h.repo.GetByRequestID(c.Request().Context(), reqID)
	if err != nil || session == nil {
		return echo.ErrNotFound
	}
	if session.Status == "completed" || session.Status == "failed" {
		// Already done — redirect or show result inline.
		if session.RedirectURI != nil && session.Status == "completed" {
			return c.Redirect(http.StatusFound, *session.RedirectURI+"?session_id="+session.ID.String())
		}
	}

	org, err := h.resolveOrg(c)
	if err != nil {
		return err
	}

	baseURL := h.cfg.BaseURL()
	qrURI := "openid4vp://?request_uri=" + baseURL + "/" + org.Slug + "/mdoc/request/" + reqID +
		"&client_id=" + baseURL + "/" + org.Slug +
		"&nonce=" + session.Nonce

	return mdocProximityTmpl.Execute(c.Response().Writer, mdocProximityData{
		OrgName:   org.Name,
		RequestID: reqID,
		QRURI:     qrURI,
		StatusURL: "/" + org.Slug + "/mdoc/proximity/" + reqID + "/status",
		ExpiresAt: session.ExpiresAt,
		Nonce:     session.Nonce,
	})
}

// GetRequest handles GET /:org_slug/mdoc/request/:req_id
// The wallet calls this after scanning the QR code to fetch the OID4VP request.
func (h *MdocProximityHandler) GetRequest(c echo.Context) error {
	ctx := c.Request().Context()

	reqID := c.Param("req_id")
	session, err := h.repo.GetByRequestID(ctx, reqID)
	if err != nil {
		return echo.ErrNotFound
	}
	if session.Status != "pending" && session.Status != "scanned" {
		return c.JSON(http.StatusGone, map[string]string{"error": "session_expired_or_used"})
	}
	if time.Now().After(session.ExpiresAt) {
		return c.JSON(http.StatusGone, map[string]string{"error": "session_expired"})
	}

	// Advance status to 'scanned' so the QR page knows the wallet is active.
	_ = h.repo.MarkScanned(ctx, reqID)

	def := unmarshalPresentationDef(session.PresentationDefinition)

	// Build the OID4VP AuthorizationRequest with mdoc-specific format.
	authReq := mdocAuthorizationRequest{
		AuthorizationRequest: oid4w.AuthorizationRequest{
			ResponseType:           "vp_token",
			ClientID:               session.ClientID,
			ResponseMode:           "direct_post",
			ResponseURI:            session.ResponseURI,
			Nonce:                  session.Nonce,
			PresentationDefinition: &def,
		},
		// Format hints to the wallet that we expect mso_mdoc format.
		ClientMetadata: map[string]any{
			"vp_formats_supported": map[string]any{"mso_mdoc": defaultClientMetadata["vp_formats_supported"].(map[string]interface{})["mso_mdoc"]},
			"vp_formats": map[string]any{
				"mso_mdoc": map[string]any{
					"alg": []string{"ES256", "ES384", "ES512"},
				},
			},
		},
	}

	return c.JSON(http.StatusOK, authReq)
}

// Response handles POST /:org_slug/mdoc/response
// The wallet POSTs the DeviceResponse (CBOR bytes, or base64url JSON-wrapped).
//
// Accepts:
//   - Content-Type: application/cbor — raw CBOR DeviceResponse bytes
//   - Content-Type: application/json — JSON with {"vp_token": "<base64url>", "state": "..."}
//
// Verifies the IssuerSigned data and extracts attributes.
// DeviceSigned key binding verification is performed when the session transcript is available.
func (h *MdocProximityHandler) Response(c echo.Context) error {
	ctx := c.Request().Context()

	// Resolve the session via state or nonce in the request.
	state := c.FormValue("state")
	if state == "" {
		var body struct {
			State string `json:"state"`
		}
		if err := c.Bind(&body); err == nil {
			state = body.State
		}
	}
	if state == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "state parameter required to identify proximity session",
		})
	}

	session, err := h.repo.GetByRequestID(ctx, state)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "session_not_found",
		})
	}
	if session.Status != "pending" && session.Status != "scanned" {
		return c.JSON(http.StatusConflict, map[string]string{"error": "session_already_completed"})
	}
	if time.Now().After(session.ExpiresAt) {
		_ = h.repo.Fail(ctx, state, "session expired")
		return c.JSON(http.StatusGone, map[string]string{"error": "session_expired"})
	}

	// ── Parse DeviceResponse from request body ────────────────────────────
	deviceResponseBytes, err := extractDeviceResponseBytes(c)
	if err != nil {
		_ = h.repo.Fail(ctx, state, "failed to extract vp_token: "+err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
	}

	dr, err := mdoc.ParseDeviceResponse(deviceResponseBytes)
	if err != nil {
		_ = h.repo.Fail(ctx, state, "DeviceResponse parse error: "+err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_device_response",
			"error_description": err.Error(),
		})
	}
	if dr.Status != 0 {
		_ = h.repo.Fail(ctx, state, "DeviceResponse.status != 0")
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "wallet_reported_error",
		})
	}

	// ── Resolve org to get org_id for IACA pool lookup ────────────────────
	org, err := h.orgs.GetBySlug(ctx, c.Param("org_slug"))
	if err != nil {
		return echo.ErrNotFound
	}

	if session.OrgID != org.ID {
		return echo.ErrNotFound
	}
	transcript, err := mdoc.BuildSessionTranscript(session.ClientID, session.ResponseURI, session.Nonce)
	if err != nil {
		return echo.ErrInternalServerError
	}
	var verified []*mdoc.VerifiedDocument
	if len(dr.Documents) == 0 || len(dr.DocumentErrors) > 0 {
		return c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "verification_failed"})
	}
	for _, doc := range dr.Documents {
		requested := false
		for _, docType := range session.RequestedDocTypes {
			if doc.DocType == docType {
				requested = true
			}
		}
		if !requested {
			return c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "unexpected_document_type"})
		}
		roots, err := h.iacaRepo.GetCertPoolForDocType(ctx, org.ID, doc.DocType)
		if err != nil {
			return echo.ErrInternalServerError
		}
		vdocs, errs := mdoc.VerifyDeviceResponse(&mdoc.DeviceResponse{Version: dr.Version, Status: dr.Status, Documents: []mdoc.Document{doc}}, mdoc.VerificationOptions{TrustedRoots: roots, RequireTrustedIssuer: true, RequireDeviceAuth: true, SessionTranscript: transcript})
		if len(errs) > 0 || len(vdocs) != 1 {
			_ = h.repo.Fail(ctx, state, "mdoc issuer or device verification failed")
			return c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "verification_failed"})
		}
		verified = append(verified, vdocs[0])
	}

	walletRepo, tx, err := h.walletRepo.BeginIssuance(ctx)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	defer tx.Rollback(ctx)
	for _, vd := range verified {
		result := &oid4w.VerificationResult{Claims: map[string]interface{}{}, Identity: &oid4w.VerifiedCredentialIdentity{
			Format: "mso_mdoc", Issuer: oid4w.MDOCIssuerIdentity(vd.IssuerCert), CredentialType: vd.DocType,
			ExpiresAt: vd.ValidUntil, IssuerTrusted: true, HolderBound: true, Status: vd.Status,
			CertificateChains: vd.VerifiedChains, IssuerCOSEHash: vd.IssuerAuthHash,
		}}
		if err := checkWalletStatus(ctx, walletRepo, org.ID, h.cfg.BaseURL()+"/"+org.Slug, org.Settings, result, true); err != nil {
			return walletStatusError(c, err)
		}
	}

	// ── Merge attributes + device signature verification ──────────────────
	mergedClaims := make(map[string]any)
	var issuerCountry *string

	for i := range verified {
		vd := verified[i]
		mergedClaims["_device_binding"] = "verified"
		// Extract attributes.
		ns := primaryNamespace(vd.DocType)
		attrs := mdoc.ExtractAttributes(vd, ns)
		oidcClaims := mdoc.ToOIDCClaims(attrs, vd.DocType)
		for k, v := range oidcClaims {
			mergedClaims[k] = v
		}
		// Extract issuer country for audit.
		if ic, ok := attrs["issuing_country"].(string); ok {
			issuerCountry = &ic
		}
		// Record which documents were verified.
		mergedClaims["_verified_doc_types"] = append(
			toStringSlice(mergedClaims["_verified_doc_types"]),
			vd.DocType,
		)
	}
	mergedClaims["_iaca_validated"] = true

	if err := repository.NewMdocProximityRepository(tx).Complete(ctx, state, mergedClaims, issuerCountry); err != nil {
		return echo.ErrInternalServerError
	}
	if err := tx.Commit(ctx); err != nil {
		return echo.ErrServiceUnavailable
	}

	// OID4VP direct_post success response per spec.
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// StatusPoll handles GET /:org_slug/mdoc/proximity/:req_id/status
// The QR page polls this every 2 seconds to detect wallet completion.
//
// Response: {"status":"pending"|"scanned"|"completed"|"failed", "claims":{...}}
// The claims field is only populated when status="completed".
func (h *MdocProximityHandler) StatusPoll(c echo.Context) error {
	reqID := c.Param("req_id")
	session, err := h.repo.GetByRequestID(c.Request().Context(), reqID)
	if err != nil {
		return echo.ErrNotFound
	}

	resp := map[string]any{
		"status":     session.Status,
		"expires_at": session.ExpiresAt,
	}
	if session.Status == "completed" {
		resp["claims"] = session.VPClaims
		if session.RedirectURI != nil {
			resp["redirect_uri"] = *session.RedirectURI + "?session_id=" + session.ID.String()
		}
	}
	if session.Status == "failed" && session.ErrorMessage != nil {
		resp["error"] = *session.ErrorMessage
	}
	return c.JSON(http.StatusOK, resp)
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

// ListSessions handles GET /api/v1/organizations/:org_id/mdoc/sessions
func (h *MdocProximityHandler) ListSessions(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	sessions, err := h.repo.ListByOrg(c.Request().Context(), orgID, 100)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, sessions)
}

// GetSession handles GET /api/v1/organizations/:org_id/mdoc/sessions/:session_id
func (h *MdocProximityHandler) GetSession(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	sessionID, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	session, err := h.repo.GetByID(c.Request().Context(), sessionID, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, session)
}

// ── Template types ────────────────────────────────────────────────────────────

type mdocProximityData struct {
	OrgName   string
	RequestID string
	QRURI     string
	StatusURL string
	ExpiresAt time.Time
	Nonce     string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *MdocProximityHandler) resolveOrg(c echo.Context) (*models.Organization, error) {
	slug := c.Param("org_slug")
	if slug == "" {
		return nil, echo.ErrBadRequest
	}
	org, err := h.orgs.GetBySlug(c.Request().Context(), slug)
	if err != nil {
		return nil, echo.ErrNotFound
	}
	return org, nil
}

// extractDeviceResponseBytes reads the raw CBOR DeviceResponse from the request.
// Supports:
//   - Content-Type: application/cbor — body is raw CBOR
//   - Content-Type: application/json — body is {"vp_token":"<base64url>"}
//   - form field vp_token — base64url-encoded CBOR
func extractDeviceResponseBytes(c echo.Context) ([]byte, error) {
	ct := c.Request().Header.Get("Content-Type")
	if ct == "application/cbor" {
		return readLimitedBody(c, 1<<20) // 1 MiB
	}

	// Try JSON vp_token field.
	var body struct {
		VPToken string `json:"vp_token" form:"vp_token"`
	}
	// Read body for JSON.
	raw, err := readLimitedBody(c, 1<<20)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &body); err == nil && body.VPToken != "" {
		return base64.RawURLEncoding.DecodeString(body.VPToken)
	}
	// Try form field.
	if vpt := c.FormValue("vp_token"); vpt != "" {
		return base64.RawURLEncoding.DecodeString(vpt)
	}
	// If the raw body is already valid base64url, decode it directly.
	if decoded, err := base64.RawURLEncoding.DecodeString(string(raw)); err == nil && len(decoded) > 0 {
		return decoded, nil
	}
	// Return raw bytes as-is (might be CBOR without correct Content-Type).
	if len(raw) > 0 {
		return raw, nil
	}
	return nil, echo.ErrBadRequest
}

func readLimitedBody(c echo.Context, maxBytes int64) ([]byte, error) {
	r := http.MaxBytesReader(c.Response().Writer, c.Request().Body, maxBytes)
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

func primaryNamespace(docType string) string {
	switch docType {
	case mdoc.DocTypeMdl:
		return mdoc.NSMdl
	case mdoc.DocTypeEuPid:
		return mdoc.NSEuPid
	default:
		return ""
	}
}

func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	if s, ok := v.([]string); ok {
		return s
	}
	return nil
}

// buildDefaultPresentationDef creates a minimal PEX v2 presentation definition
// that requests the essential PID attributes for the given docTypes.
func buildDefaultPresentationDef(docTypes []string) map[string]any {
	inputDescriptors := make([]map[string]any, 0, len(docTypes))
	for _, dt := range docTypes {
		var fields []map[string]any
		switch dt {
		case mdoc.DocTypeEuPid:
			fields = []map[string]any{
				{"path": []string{"$['eu.europa.ec.eudi.pid.1']['family_name']"}},
				{"path": []string{"$['eu.europa.ec.eudi.pid.1']['given_name']"}},
				{"path": []string{"$['eu.europa.ec.eudi.pid.1']['birth_date']"}},
				{"path": []string{"$['eu.europa.ec.eudi.pid.1']['age_over_18']"}, "optional": true},
			}
		case mdoc.DocTypeMdl:
			fields = []map[string]any{
				{"path": []string{"$['org.iso.18013.5.1']['family_name']"}},
				{"path": []string{"$['org.iso.18013.5.1']['given_name']"}},
				{"path": []string{"$['org.iso.18013.5.1']['birth_date']"}},
				{"path": []string{"$['org.iso.18013.5.1']['document_number']"}},
			}
		}
		inputDescriptors = append(inputDescriptors, map[string]any{
			"id":   dt,
			"name": dt,
			"format": map[string]any{
				"mso_mdoc": map[string]any{"alg": []string{"ES256", "ES384", "ES512"}},
			},
			"constraints": map[string]any{
				"limit_disclosure": "required",
				"fields":           fields,
			},
		})
	}
	id, _ := generateRequestID()
	return map[string]any{
		"id":                id,
		"input_descriptors": inputDescriptors,
	}
}

// mdocAuthorizationRequest extends AuthorizationRequest with mdoc-specific fields.
type mdocAuthorizationRequest struct {
	oid4w.AuthorizationRequest
	ClientMetadata map[string]any `json:"client_metadata,omitempty"`
}
