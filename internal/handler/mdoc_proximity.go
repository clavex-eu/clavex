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
	repo     *repository.MdocProximityRepository
	orgs     *repository.OrgRepository
	iacaRepo *repository.IACARepository
	keys     oidc.Signer
	cfg      baseURLProvider
}

func NewMdocProximityHandler(pool *pgxpool.Pool, keys oidc.Signer, cfg baseURLProvider) *MdocProximityHandler {
	return &MdocProximityHandler{
		repo:     repository.NewMdocProximityRepository(pool),
		orgs:     repository.NewOrgRepository(pool),
		iacaRepo: repository.NewIACARepository(pool),
		keys:     keys,
		cfg:      cfg,
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

	// ── Load per-org IACA trust anchors ───────────────────────────────────
	// Returns nil if no roots are configured; VerifyDeviceResponse treats
	// nil TrustedRoots as "skip root chain check" (COSE_Sign1 sig + MSO
	// digest verification still enforced regardless).
	trustedRoots, _ := h.iacaRepo.GetCertPool(ctx, org.ID)

	// ── Verify IssuerSigned data ───────────────────────────────────────────
	verifyOpts := mdoc.VerificationOptions{
		ExpectedNonce: session.Nonce,
		TrustedRoots:  trustedRoots, // nil → root-trust advisory only
	}
	verified, verifyErrs := mdoc.VerifyDeviceResponse(dr, verifyOpts)
	if len(verified) == 0 {
		errMsg := "no documents verified"
		if len(verifyErrs) > 0 {
			errMsg = verifyErrs[0].Error()
		}
		_ = h.repo.Fail(ctx, state, errMsg)
		return c.JSON(http.StatusUnprocessableEntity, map[string]string{
			"error":             "verification_failed",
			"error_description": errMsg,
		})
	}

	// ── Build session transcript (ISO 18013-7 OpenID4VPHandover) ──────────
	baseURL := h.cfg.BaseURL()
	transcript, err := mdoc.BuildSessionTranscript(
		session.ClientID,
		baseURL+"/"+org.Slug+"/mdoc/response",
		session.Nonce,
	)
	if err != nil {
		// Transcript build failure is non-fatal; we log and skip key binding.
		transcript = nil
	}

	// ── Merge attributes + device signature verification ──────────────────
	mergedClaims := make(map[string]any)
	var issuerCountry *string
	var deviceBindingErrors []string

	for i := range verified {
		vd := verified[i]
		// Device key binding: verify the wallet signed the session transcript
		// with the device private key whose public key is bound in the MSO.
		// This proves possession of the device key and ties the response to
		// this specific session (replay protection).
		if transcript != nil {
			deviceKey, keyErr := mdoc.ExtractDeviceKey(vd)
			if keyErr == nil && deviceKey != nil {
				if sigErr := mdoc.VerifyDeviceSignature(
					dr.Documents[i], transcript, deviceKey,
				); sigErr != nil {
					// Hard failure: device sig present but invalid.
					errMsg := "device signature invalid: " + sigErr.Error()
					_ = h.repo.Fail(ctx, state, errMsg)
					return c.JSON(http.StatusUnprocessableEntity, map[string]string{
						"error":             "device_binding_failed",
						"error_description": sigErr.Error(),
					})
				}
				mergedClaims["_device_binding"] = "verified"
			} else {
				// MSO has no parseable device key (unusual but not fatal).
				deviceBindingErrors = append(deviceBindingErrors, vd.DocType+": "+keyErr.Error())
			}
		}

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
	if len(deviceBindingErrors) > 0 {
		mergedClaims["_device_binding_warnings"] = deviceBindingErrors
	}
	// Record whether IACA root validation was enforced.
	if trustedRoots != nil {
		mergedClaims["_iaca_validated"] = true
	}

	if err := h.repo.Complete(ctx, state, mergedClaims, issuerCountry); err != nil {
		return echo.ErrInternalServerError
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
