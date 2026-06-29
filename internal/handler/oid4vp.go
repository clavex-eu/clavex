package handler

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"
)

// OID4VPHandler handles OpenID for Verifiable Presentations (OID4VP) endpoints.
//
// ...
//
// cibaVPACR is the ACR value set in CIBA tokens when the user authenticated
// by presenting a verifiable credential (e.g. CIE mdoc) via OID4VP.
// This value satisfies PSD2 RTS Article 9 Level 2 Strong Customer Authentication
// requirements: it combines possession (wallet device) + inherence (biometric
// binding inside the mdoc) at the highest assurance level.
const cibaVPACR = "urn:clavex:acr:oid4vp-credential"
//
//	Public tenant endpoints:
//	  POST /:org_slug/wallet/request          → create presentation request (returns request_uri)
//	  GET  /:org_slug/wallet/request/:req_id  → return the request object
//	  POST /:org_slug/wallet/response         → wallet submits vp_token
//
//	Admin endpoints (org-scoped):
//	  GET  /api/v1/organizations/:org_id/oid4vp/sessions       → list sessions
//	  GET  /api/v1/organizations/:org_id/oid4vp/sessions/:id   → get session status
type OID4VPHandler struct {
	repo           *repository.OID4WRepository
	orgs           *repository.OrgRepository
	keys           oidc.Signer
	cfg            baseURLProvider
	trustedIssuers map[string]crypto.PublicKey
	// requireTrustedIssuer rejects DCQL presentations from issuers not in
	// trustedIssuers (default true; false only for the conformance suite).
	requireTrustedIssuer bool
	// jarKey / jarCert implement the x509_san_dns client_id_scheme for JAR signing.
	// A P-256 EC key + self-signed cert (SAN = base URL hostname) are generated at
	// startup. The cert is included in the x5c JWS header so the wallet can verify
	// the signature without prior RP registration.
	jarKey          crypto.PrivateKey  // *ecdsa.PrivateKey (ES256) or *rsa.PrivateKey (RS256)
	jarCert         *x509.Certificate
	jarCertChain    [][]byte // DER-encoded chain: leaf first, then intermediates
	// cibaRequests is used to auto-approve a linked CIBA request when a
	// CIBA+OID4VP SCA flow completes successfully (credential presentation verified).
	cibaRequests   *repository.CIBARepository
}

func NewOID4VPHandler(pool *pgxpool.Pool, keys oidc.Signer, cfg baseURLProvider, trustedIssuers map[string]crypto.PublicKey, requireTrustedIssuer bool, cibaRequests *repository.CIBARepository, jarCertFile, jarKeyFile string) *OID4VPHandler {
	if trustedIssuers == nil {
		trustedIssuers = map[string]crypto.PublicKey{}
	}
	jarKey, jarCert, jarCertChain := loadOrGenerateJARCert(cfg.BaseURL(), jarCertFile, jarKeyFile)
	return &OID4VPHandler{
		repo:                 repository.NewOID4WRepository(pool),
		orgs:                 repository.NewOrgRepository(pool),
		keys:                 keys,
		cfg:                  cfg,
		trustedIssuers:       trustedIssuers,
		requireTrustedIssuer: requireTrustedIssuer,
		jarKey:               jarKey,
		jarCert:              jarCert,
		jarCertChain:         jarCertChain,
		cibaRequests:         cibaRequests,
	}
}

// loadOrGenerateJARCert returns the key and certificate used for JAR signing.
//
// If certFile and keyFile are both set, it loads the PEM certificate chain and
// private key from those files. The leaf certificate MUST have a dNSName SAN
// matching the server hostname and SHOULD be signed by a CA trusted by the
// target wallet (e.g. Let's Encrypt). All certificates in the chain are
// embedded in the x5c JWS header.
//
// If either path is empty, a P-256 self-signed cert is generated at startup.
// This is fine for development but is rejected by production wallets (EUDI ARF
// requires a trusted CA chain).
func loadOrGenerateJARCert(baseURL, certFile, keyFile string) (crypto.PrivateKey, *x509.Certificate, [][]byte) {
	if certFile != "" && keyFile != "" {
		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal().Err(err).
				Str("cert_file", certFile).Str("key_file", keyFile).
				Msg("oid4vp: failed to load JAR cert/key — set oid4vp.jar_cert_file and oid4vp.jar_key_file")
		}
		switch tlsCert.PrivateKey.(type) {
		case *ecdsa.PrivateKey, *rsa.PrivateKey:
		default:
			log.Fatal().Msgf("oid4vp: JAR key type %T is not supported (use ECDSA or RSA)", tlsCert.PrivateKey)
		}
		leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			log.Fatal().Err(err).Msg("oid4vp: failed to parse JAR leaf certificate")
		}
		log.Info().
			Str("subject", leaf.Subject.CommonName).
			Strs("san_dns", leaf.DNSNames).
			Time("not_after", leaf.NotAfter).
			Int("chain_len", len(tlsCert.Certificate)).
			Msgf("oid4vp: JAR cert loaded from file (key type: %T)", tlsCert.PrivateKey)
		return tlsCert.PrivateKey, leaf, tlsCert.Certificate
	}

	// Fallback: ephemeral self-signed cert.
	hostname := baseURL
	if u, err := url.Parse(baseURL); err == nil && u.Hostname() != "" {
		hostname = u.Hostname()
	}
	log.Warn().
		Str("hostname", hostname).
		Msg("oid4vp: using ephemeral self-signed JAR cert — set oid4vp.jar_cert_file + oid4vp.jar_key_file for production wallets")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("oid4vp: generate JAR EC key: " + err.Error())
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic("oid4vp: create JAR cert: " + err.Error())
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		panic("oid4vp: parse JAR cert: " + err.Error())
	}
	return key, parsed, [][]byte{der}
}

// ── Public tenant endpoints ───────────────────────────────────────────────────

// defaultClientMetadata is the client_metadata value included in every
// OID4VP authorization request. OID4VP 1.0 Final Annex B §B.2.2 requires
// vp_formats_supported (not vp_formats) so the wallet knows which formats are accepted.
var defaultClientMetadata = map[string]interface{}{
	"vp_formats_supported": map[string]interface{}{
		"dc+sd-jwt": map[string]interface{}{
			"sd-jwt_alg_values": []string{"ES256", "PS256"},
			"kb-jwt_alg_values": []string{"ES256", "PS256"},
		},
		"jwt_vp_json": map[string]interface{}{
			"alg_values_supported": []string{"ES256", "PS256"},
		},
		"mso_mdoc": map[string]interface{}{
			"alg_values_supported": []string{"ES256"},
		},
	},
}

type createVPRequestBody struct {
	// DCQLQuery is the OID4VP 1.0 Final DCQL credential query (§6).
	// Preferred over PresentationDefinition for new integrations.
	DCQLQuery map[string]interface{} `json:"dcql_query"`
	// PresentationDefinition is the legacy Presentation Exchange v2 definition.
	// Either dcql_query or presentation_definition must be provided.
	PresentationDefinition map[string]interface{} `json:"presentation_definition"`
	// RedirectURI is where to redirect the browser after successful verification.
	RedirectURI *string `json:"redirect_uri"`
	State       *string `json:"state"`
	// WalletAuthorizationEndpoint, when provided, causes the response to include an
	// authorization_url with the request parameters inline (url_query method).
	// Useful for conformance testing where the suite provides its own wallet endpoint.
	WalletAuthorizationEndpoint *string `json:"wallet_authorization_endpoint"`
}

// CreateRequest handles POST /:org_slug/wallet/request
// Creates a new OID4VP presentation session and returns a request_uri for the wallet.
func (h *OID4VPHandler) CreateRequest(c echo.Context) error {
	org, err := h.resolveOrgVP(c)
	if err != nil {
		return err
	}

	var req createVPRequestBody
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.DCQLQuery == nil && req.PresentationDefinition == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "dcql_query or presentation_definition is required")
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
	responseURI := baseURL + "/" + org.Slug + "/wallet/response"
	requestURI := baseURL + "/" + org.Slug + "/wallet/request/" + requestID

	// OID4VP 1.0 Final: choose client_id scheme based on request method.
	// url_query (wallet_authorization_endpoint provided) → redirect_uri prefix: no cert needed,
	// client_id is verifiable from response_uri itself.
	// request_uri (JAR) → x509_san_dns prefix: cert SAN verifies the key.
	var clientID string
	if req.WalletAuthorizationEndpoint != nil && *req.WalletAuthorizationEndpoint != "" {
		clientID = "redirect_uri:" + responseURI
	} else if h.jarCert != nil && len(h.jarCert.DNSNames) > 0 {
		clientID = "x509_san_dns:" + h.jarCert.DNSNames[0]
	} else {
		clientID = "redirect_uri:" + responseURI
	}

	session, err := h.repo.CreatePresentationSession(
		c.Request().Context(),
		org.ID,
		requestID,
		req.PresentationDefinition,
		req.DCQLQuery,
		responseURI,
		req.RedirectURI,
		req.State,
		nonce,
		time.Now().Add(10*time.Minute),
		nil, // cibaAuthReqID — nil for standalone VP sessions
		clientID,
	)
	if err != nil {
		return echo.ErrInternalServerError
	}

	resp := map[string]any{
		"request_uri": requestURI,
		"request_id":  session.RequestID,
		"expires_at":  session.ExpiresAt,
		"nonce":       nonce,
	}

	// ── GDPR Art.5(1)(c) data-minimization check ─────────────────────────────
	// Analyse the credential query for high-sensitivity claims and include
	// any findings in the response so the CISO/integrator is immediately aware.
	// This is non-blocking: the session is created regardless of warnings.
	var gdprWarnings []oid4w.GDPRWarning
	if req.DCQLQuery != nil {
		gdprWarnings = oid4w.CheckDCQLMinimization(req.DCQLQuery)
	} else if req.PresentationDefinition != nil {
		gdprWarnings = oid4w.CheckRawPDMinimization(req.PresentationDefinition)
	}
	if len(gdprWarnings) > 0 {
		resp["gdpr_warnings"] = gdprWarnings
	}

	if req.WalletAuthorizationEndpoint != nil && *req.WalletAuthorizationEndpoint != "" {
		params := url.Values{}
		params.Set("response_type", "vp_token")
		// OID4VP 1.0 Final: client_id_scheme parameter was removed in ID3.
		// For url_query requests use redirect_uri prefix so client_id is
		// self-verifiable without a certificate (client_id == "redirect_uri:" + response_uri).
		params.Set("client_id", clientID)
		params.Set("response_mode", "direct_post")
		params.Set("response_uri", responseURI)
		params.Set("nonce", nonce)
		params.Set("state", requestID)

		if req.DCQLQuery != nil {
			// OID4VP 1.0 Final: use dcql_query; do NOT also send presentation_definition.
			if dcqlJSON, jsonErr := json.Marshal(req.DCQLQuery); jsonErr == nil {
				params.Set("dcql_query", string(dcqlJSON))
			}
		} else {
			// Legacy Presentation Exchange mode.
			if pdJSON, jsonErr := json.Marshal(req.PresentationDefinition); jsonErr == nil {
				params.Set("presentation_definition", string(pdJSON))
			}
		}

		// client_metadata with vp_formats is MANDATORY per OID4VP 1.0 Final §5.1.
		if cmJSON, jsonErr := json.Marshal(defaultClientMetadata); jsonErr == nil {
			params.Set("client_metadata", string(cmJSON))
		}

		resp["authorization_url"] = *req.WalletAuthorizationEndpoint + "?" + params.Encode()
	}

	return c.JSON(http.StatusCreated, resp)
}

// GetRequest handles GET /:org_slug/wallet/request/:req_id
// Returns the authorization request object that the wallet fetches after scanning the QR code.
func (h *OID4VPHandler) GetRequest(c echo.Context) error {
	reqID := c.Param("req_id")
	if reqID == "" {
		return echo.ErrBadRequest
	}

	ctx := c.Request().Context()
	session, err := h.repo.GetPresentationSession(ctx, reqID)
	if err != nil {
		return echo.ErrNotFound
	}

	if session.Status != "pending" {
		return c.JSON(http.StatusGone, map[string]string{
			"error": "request_expired_or_used",
		})
	}

	if time.Now().After(session.ExpiresAt) {
		return c.JSON(http.StatusGone, map[string]string{
			"error": "request_expired",
		})
	}

	if _, err := h.resolveOrgVP(c); err != nil {
		return err
	}

	// OID4VP 1.0 Final §5.7.1 / x509_san_dns scheme:
	// client_id = "x509_san_dns:<hostname>"; public key verified from x5c cert SAN.
	hostname := h.jarCert.DNSNames[0]
	authReq := oid4w.AuthorizationRequest{
		ResponseType:   "vp_token",
		ClientID:       "x509_san_dns:" + hostname,
		ClientIDScheme: "x509_san_dns",
		ResponseMode:   "direct_post",
		ResponseURI:    session.ResponseURI,
		Nonce:          session.Nonce,
		ClientMetadata: defaultClientMetadata,
	}
	// state must round-trip back to us so Response() can look up the session
	// via GetPresentationSession(ctx, state) which queries WHERE request_id = $1.
	// Use the caller-supplied state if present, otherwise fall back to requestID.
	if session.State != nil {
		authReq.State = *session.State
	} else {
		authReq.State = session.RequestID
	}
	// OID4VP 1.0 Final: prefer dcql_query over legacy presentation_definition.
	if session.DCQLQuery != nil {
		authReq.DCQLQuery = session.DCQLQuery
	} else {
		pd := unmarshalPresentationDef(session.PresentationDefinition)
		authReq.PresentationDefinition = &pd
	}

	// RFC 9101 §4 / OID4VP 1.0 Final §5.7.1 (x509_san_dns): the request_uri
	// endpoint MUST return a signed JAR JWT. The wallet verifies the ES256
	// signature against the public key in the x5c cert.
	jarJWT, err := signVPAuthorizationRequest(authReq, h.jarKey, h.jarCertChain)
	if err != nil {
		return echo.ErrInternalServerError
	}
	c.Response().Header().Set(echo.HeaderContentType, "application/oauth-authz-req+jwt")
	return c.Blob(http.StatusOK, "application/oauth-authz-req+jwt", []byte(jarJWT))
}

// Response handles POST /:org_slug/wallet/response
// The wallet POSTs the vp_token here. On success returns the redirect_uri with a code.
// Per OID4VP §7.3 the wallet may also POST an error instead of a vp_token; in that
// case we mark the session as failed and return 200 so the wallet does not retry.
func (h *OID4VPHandler) Response(c echo.Context) error {
	// OID4VP §7.3: wallet error response — form-encoded error parameter.
	if walletErr := c.FormValue("error"); walletErr != "" {
		state := c.FormValue("state")
		desc := c.FormValue("error_description")
		if state != "" {
			_ = h.repo.FailPresentationSession(c.Request().Context(), state)
		}
		log.Warn().Str("error", walletErr).Str("description", desc).Str("state", state).
			Msg("oid4vp: wallet reported error on response endpoint")
		return c.JSON(http.StatusOK, map[string]string{"status": "error_acknowledged"})
	}

	// Accept either JSON body or form-encoded.
	vpToken := c.FormValue("vp_token")
	if vpToken == "" {
		var body struct {
			VPToken string `json:"vp_token"`
			State   string `json:"state"`
		}
		if err := c.Bind(&body); err == nil {
			vpToken = body.VPToken
		}
	}

	if vpToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "vp_token is required",
		})
	}

	state := c.FormValue("state")
	ctx := c.Request().Context()

	// Find the session by state or by looking at the session for this org.
	// In direct_post mode the wallet POSTs to the response endpoint from the request object;
	// we require the `state` to identify the session.
	if state == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "state is required to identify the presentation session",
		})
	}

	// Derive the request_id from the state (we store them together).
	session, err := h.repo.GetPresentationSession(ctx, state)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "presentation session not found",
		})
	}

	if session.Status != "pending" || time.Now().After(session.ExpiresAt) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "expired_or_used",
		})
	}

	// Resolve the effective client_id for KB-JWT aud verification.
	// New sessions store client_id at creation time; older sessions (pre-migration
	// 000165) fall back to the x509_san_dns scheme if a JAR cert is configured.
	effectiveClientID := session.ClientID
	if effectiveClientID == "" && h.jarCert != nil && len(h.jarCert.DNSNames) > 0 {
		effectiveClientID = "x509_san_dns:" + h.jarCert.DNSNames[0]
	}

	// Verify the vp_token.
	// For DCQL sessions (OID4VP 1.0 Final), credentials come from third-party
	// issuers; use issuer JWKS discovery instead of the local signing key.
	// OID4VP 1.0 Final §8.3: vp_token in DCQL mode is a JSON object
	// {"<credential_id>": ["<presentation>", ...]}; dispatch on credential format.
	var result *oid4w.VerificationResult
	if session.DCQLQuery != nil {
		credFmt := dcqlCredentialFormat(session.DCQLQuery)
		if credFmt == "mso_mdoc" {
			result, err = verifyMdocDCQLVPToken(vpToken)
		} else {
			sdJWT := extractDCQLVPToken(vpToken)
			// OID4VP 1.0 Final §11.4: KB-JWT aud MUST equal the client_id
			// (not response_uri as in older drafts). Use the client_id that
			// was stored on the session at request creation time so the correct
			// scheme (redirect_uri vs x509_san_dns) is used for verification.
			result, err = oid4w.VerifyDCQLPresentation(ctx, sdJWT, session.DCQLQuery, session.Nonce, effectiveClientID, h.trustedIssuers, h.requireTrustedIssuer, h.keys.PublicKey())
		}
	} else {
		def := unmarshalPresentationDef(session.PresentationDefinition)
		result, err = oid4w.VerifyPresentation(
			vpToken,
			def,
			session.Nonce,
			effectiveClientID,
			nil, // no additional trusted issuers beyond local key
			h.keys.PublicKey(),
		)
	}
	if err != nil {
		_ = h.repo.FailPresentationSession(ctx, state)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":             "vp_token_invalid",
			"error_description": err.Error(),
		})
	}

	// Persist verified claims and mark session complete.
	_ = h.repo.CompletePresentationSession(ctx, state, result.Claims)

	// If this VP session was linked to a CIBA request (CIBA+OID4VP SCA flow),
	// auto-approve the CIBA request with the verified credential claims.
	// The polling client will receive tokens on the next /token poll, with
	// acr="urn:clavex:acr:oid4vp-credential" and verified_claims in the ID token.
	if session.CIBAAuthReqID != nil && h.cibaRequests != nil {
		cibaReq, cibaGetErr := h.cibaRequests.Get(ctx, *session.CIBAAuthReqID)
		if cibaGetErr == nil && cibaReq != nil && cibaReq.Status == "pending" && cibaReq.UserID != nil {
			if approveErr := h.cibaRequests.ApproveWithVPClaims(
				ctx,
				*session.CIBAAuthReqID,
				*cibaReq.UserID,
				result.Claims,
				cibaVPACR,
			); approveErr != nil {
				// Log but don't fail — the VP is verified, auto-approval failure is non-fatal.
				c.Logger().Errorf("ciba+oid4vp: auto-approve failed for %s: %v", *session.CIBAAuthReqID, approveErr)
			}
		}
	}

	// OID4VP 1.0 Final §8.3.5: the response MUST be 200 OK and SHOULD only
	// contain redirect_uri (to redirect the wallet user agent). No extra fields.
	// Extension: chained_offers[] is included when Credential Chaining is configured.
	chainedOffers := h.buildChainedOffers(ctx, session, result.Claims, c)
	if session.RedirectURI != nil {
		resp := map[string]any{"redirect_uri": *session.RedirectURI}
		if len(chainedOffers) > 0 {
			resp["chained_offers"] = chainedOffers
		}
		return c.JSON(http.StatusOK, resp)
	}
	if len(chainedOffers) > 0 {
		return c.JSON(http.StatusOK, map[string]any{"chained_offers": chainedOffers})
	}
	return c.JSON(http.StatusOK, map[string]any{})
}

// ── In-login OID4VP challenge helpers ────────────────────────────────────────

// RequestStatus handles GET /:org_slug/wallet/request/:req_id/status
//
// A lightweight polling endpoint used by the browser challenge page to track
// wallet presentation progress. Returns {"status":"pending"|"verified"|"failed"}.
// Verified VP claims are exposed once the session is complete so the browser
// can confirm which credential was presented.
//
// This endpoint is intentionally unauthenticated: the request ID is a
// cryptographically random 16-byte value that acts as its own bearer secret.
func (h *OID4VPHandler) RequestStatus(c echo.Context) error {
	reqID := c.Param("req_id")
	if reqID == "" {
		return echo.ErrBadRequest
	}
	sess, err := h.repo.GetPresentationSession(c.Request().Context(), reqID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"status": "not_found"})
	}
	resp := map[string]any{"status": sess.Status}
	if sess.Status == "verified" && sess.VPClaims != nil {
		resp["verified_claims"] = sess.VPClaims
	}
	return c.JSON(http.StatusOK, resp)
}

// CreateLoginChallengeSession creates a presentation session for an in-login
// oid4vp_challenge step. The session reuses the org's existing
// /:org_slug/wallet/response endpoint so the wallet-side flow is unchanged.
// It is called by the OIDC login handler when the flow engine emits
// FlowResult.OID4VPChallenge.
func (h *OID4VPHandler) CreateLoginChallengeSession(
	ctx context.Context,
	orgID uuid.UUID,
	orgSlug string,
	dcqlQuery map[string]any,
	pdQuery map[string]any,
) (*models.PresentationSession, error) {
	requestID, err := generateRequestID()
	if err != nil {
		return nil, err
	}
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	baseURL := h.cfg.BaseURL()
	responseURI := baseURL + "/" + orgSlug + "/wallet/response"
	// The state MUST equal the requestID so the Response handler can look up
	// the session when the wallet POSTs without a session cookie.
	state := requestID
	loginClientID := ""
	if h.jarCert != nil && len(h.jarCert.DNSNames) > 0 {
		loginClientID = "x509_san_dns:" + h.jarCert.DNSNames[0]
	} else {
		loginClientID = "redirect_uri:" + responseURI
	}
	return h.repo.CreatePresentationSession(
		ctx, orgID, requestID,
		pdQuery, dcqlQuery,
		responseURI,
		nil,    // no redirect_uri — browser polls for status instead
		&state, // state = requestID
		nonce,
		time.Now().Add(10*time.Minute),
		nil, // not a CIBA flow
		loginClientID,
	)
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

// ListSessions handles GET /api/v1/organizations/:org_id/oid4vp/sessions
// Returns recent presentation sessions (newest first, max 50).
func (h *OID4VPHandler) ListSessions(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.ErrBadRequest
	}
	sessions, err := h.repo.ListPresentationSessions(c.Request().Context(), orgID, 50)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if sessions == nil {
		sessions = []models.PresentationSession{}
	}
	return c.JSON(http.StatusOK, sessions)
}

// GetSession handles GET /api/v1/organizations/:org_id/oid4vp/sessions/:session_id
func (h *OID4VPHandler) GetSession(c echo.Context) error {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		return echo.ErrBadRequest
	}
	session, err := h.repo.GetPresentationSession(c.Request().Context(), sessionID)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, session)
}

// RequestQR generates a scannable QR code for an OID4VP presentation request.
// GET /:org_slug/wallet/request/:req_id/qr
//
// Returns a PNG image containing the openid4vp:// deep-link URI.
// The IT-Wallet / EUDIW app scans the QR to start the presentation flow.
//
// Query params:
//
//	size — image dimension in pixels (default 320, max 1024)
func (h *OID4VPHandler) RequestQR(c echo.Context) error {
	reqID := c.Param("req_id")
	if reqID == "" {
		return echo.ErrBadRequest
	}

	ctx := c.Request().Context()
	session, err := h.repo.GetPresentationSession(ctx, reqID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "presentation session not found")
	}
	if session.Status != "pending" {
		return echo.NewHTTPError(http.StatusGone, "session already used or expired")
	}
	if time.Now().After(session.ExpiresAt) {
		return echo.NewHTTPError(http.StatusGone, "session expired")
	}

	org, err := h.resolveOrgVP(c)
	if err != nil {
		return err
	}

	baseURL := h.cfg.BaseURL()
	requestURI := baseURL + "/" + org.Slug + "/wallet/request/" + reqID
	// x509_san_dns scheme: client_id is the hostname with its scheme prefix.
	x509ClientID := "x509_san_dns:" + h.jarCert.DNSNames[0]
	qrURI := fmt.Sprintf("openid4vp://?client_id=%s&request_uri=%s",
		url.QueryEscape(x509ClientID), url.QueryEscape(requestURI))

	size := 320
	if s := c.QueryParam("size"); s != "" {
		var n int
		if _, scanErr := fmt.Sscanf(s, "%d", &n); scanErr == nil && n > 0 && n <= 1024 {
			size = n
		}
	}

	code, err := qr.Encode(qrURI, qr.M, qr.Auto)
	if err != nil {
		return echo.ErrInternalServerError
	}
	scaled, err := barcode.Scale(code, size, size)
	if err != nil {
		return echo.ErrInternalServerError
	}

	c.Response().Header().Set("Content-Type", "image/png")
	c.Response().Header().Set("Cache-Control", "no-store")
	return png.Encode(c.Response().Writer, scaled)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *OID4VPHandler) resolveOrgVP(c echo.Context) (*models.Organization, error) {
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

func generateRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// dcqlCredentialFormat returns the format of the first credential in a DCQL query,
// or empty string if the query is malformed or has no credentials.
func dcqlCredentialFormat(dcqlQuery map[string]interface{}) string {
	creds, _ := dcqlQuery["credentials"].([]interface{})
	if len(creds) == 0 {
		return ""
	}
	first, _ := creds[0].(map[string]interface{})
	fmt, _ := first["format"].(string)
	return fmt
}

// verifyMdocDCQLVPToken verifies a DCQL vp_token containing an mso_mdoc credential.
// The vp_token is a JSON object {"<id>": ["<base64url-DeviceResponse-CBOR>", ...]}.
// Issuer signature verification is intentionally skipped for external issuers
// (same policy as VerifyDCQLPresentation for SD-JWT).
func verifyMdocDCQLVPToken(vpToken string) (*oid4w.VerificationResult, error) {
	// Extract the first presentation bytes from {"<id>": ["<cbor>", ...]}.
	var obj map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &obj); err != nil {
		return nil, fmt.Errorf("mdoc dcql: parse vp_token envelope: %w", err)
	}
	var raw string
	for _, vals := range obj {
		if len(vals) > 0 {
			raw = vals[0]
			break
		}
	}
	if raw == "" {
		return nil, fmt.Errorf("mdoc dcql: no presentation found in vp_token")
	}

	der, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		// Try standard base64 as fallback.
		der, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("mdoc dcql: base64 decode: %w", err)
		}
	}

	dr, err := mdoc.ParseDeviceResponse(der)
	if err != nil {
		return nil, fmt.Errorf("mdoc dcql: parse DeviceResponse: %w", err)
	}
	if len(dr.Documents) == 0 {
		return nil, fmt.Errorf("mdoc dcql: DeviceResponse contains no documents")
	}

	// VerifyDeviceResponse checks MSO/issuer signature and digest bindings.
	// TrustedRoots left nil → skip issuer cert chain validation for external issuers.
	vdocs, errs := mdoc.VerifyDeviceResponse(dr, mdoc.VerificationOptions{})
	if len(vdocs) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("mdoc dcql: verify DeviceResponse: %v", errs[0])
	}
	if len(vdocs) == 0 {
		return nil, fmt.Errorf("mdoc dcql: no verified documents")
	}

	vd := vdocs[0]
	claims := mdoc.ToOIDCClaims(mdoc.ExtractAttributes(vd, ""), vd.DocType)
	return &oid4w.VerificationResult{Claims: claims}, nil
}

// extractDCQLVPToken handles the OID4VP 1.0 Final §8.3 vp_token format for DCQL.
// In DCQL mode the wallet sends vp_token as a JSON object:
//
//	{"<credential_id>": ["<sd-jwt-presentation>", ...], ...}
//
// This function returns the first SD-JWT string found inside that object.
// If the input is already a plain SD-JWT string (legacy PEv2 flow), it is
// returned unchanged.
func extractDCQLVPToken(vpToken string) string {
	var obj map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &obj); err != nil {
		return vpToken
	}
	for _, presentations := range obj {
		if len(presentations) > 0 {
			return presentations[0]
		}
	}
	return vpToken
}

// unmarshalPresentationDef deserialises a map[string]interface{} (from the DB
// JSONB column) into a typed PresentationDefinition.
func unmarshalPresentationDef(raw map[string]interface{}) oid4w.PresentationDefinition {
	b, _ := json.Marshal(raw)
	var def oid4w.PresentationDefinition
	_ = json.Unmarshal(b, &def)
	return def
}

// ── eIDAS 2.0 Relying Party metadata ─────────────────────────────────────────

// RPMetadata generates a signed eIDAS 2.0 Relying Party entity configuration
// JWT + metadata bundle for registration at a national Trust Anchor (e.g. AgID).
//
// GET /api/v1/organizations/:org_id/eidas-rp-metadata
//
// Query parameters:
//   - purpose         human-readable data processing purpose (required)
//   - data_categories comma-separated list of data categories requested
//   - retention_years number of years personal data is retained (default: 1)
//   - contact_email   DPO / contact e-mail to embed in the metadata
func (h *OID4VPHandler) RPMetadata(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil || org == nil {
		return echo.ErrNotFound
	}

	// ── Query params ─────────────────────────────────────────────────────────
	purpose := strings.TrimSpace(c.QueryParam("purpose"))
	if purpose == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "purpose is required")
	}

	var dataCategories []string
	if dc := strings.TrimSpace(c.QueryParam("data_categories")); dc != "" {
		for _, cat := range strings.Split(dc, ",") {
			if t := strings.TrimSpace(cat); t != "" {
				dataCategories = append(dataCategories, t)
			}
		}
	}
	if len(dataCategories) == 0 {
		dataCategories = []string{"identity", "email"}
	}

	retentionYears := 1
	if ry := c.QueryParam("retention_years"); ry != "" {
		_, _ = fmt.Sscanf(ry, "%d", &retentionYears)
		if retentionYears < 1 {
			retentionYears = 1
		}
	}

	contactEmail := strings.TrimSpace(c.QueryParam("contact_email"))

	// ── Build entity_id and redirect_uris ────────────────────────────────────
	baseURL := h.cfg.BaseURL()
	entityID := baseURL + "/" + org.Slug
	redirectURIs := []string{
		entityID + "/wallet/callback",
	}

	// ── Build the entity configuration payload ───────────────────────────────
	now := time.Now().UTC()
	exp := now.Add(365 * 24 * time.Hour)

	vpFormats := map[string]interface{}{
		"jwt_vc_json": map[string]interface{}{
			"alg_values_supported": []string{"ES256", "RS256"},
		},
		"jwt_vp_json": map[string]interface{}{
			"alg_values_supported": []string{"ES256", "RS256"},
		},
		"mso_mdoc": map[string]interface{}{
			"alg_values_supported": []string{"ES256"},
		},
		"dc+sd-jwt": map[string]interface{}{
			"sd-jwt_alg_values":    []string{"ES256", "RS256"},
			"kb-jwt_alg_values":    []string{"ES256", "RS256"},
		},
	}

	claims := make([]map[string]interface{}, 0, len(dataCategories))
	for _, cat := range dataCategories {
		claims = append(claims, map[string]interface{}{
			"name": cat,
		})
	}

	contacts := []string{}
	if contactEmail != "" {
		contacts = append(contacts, contactEmail)
	}

	rpMetadata := map[string]interface{}{
		"application_type":              "web",
		"client_id":                     entityID,
		"client_name":                   org.Name,
		"redirect_uris":                 redirectURIs,
		"response_types":                []string{"vp_token", "id_token"},
		"vp_formats":                    vpFormats,
		"subject_type":                  "pairwise",
		"id_token_signed_response_alg":  "RS256",
		"request_object_signing_alg":    "RS256",
		"purpose":                       purpose,
		"claims":                        claims,
		"retention_period_years":        retentionYears,
		"data_categories":               dataCategories,
		"contacts":                      contacts,
		"trust_anchor_id":               "https://registry.servizicie.interno.gov.it",
	}

	// Public JWKS from the org's signing key
	jwksRaw := json.RawMessage(h.keys.JWKS())

	entityConfig := map[string]interface{}{
		"iss":      entityID,
		"sub":      entityID,
		"iat":      now.Unix(),
		"exp":      exp.Unix(),
		"entity_type": []string{"openid_relying_party"},
		"jwks":     jwksRaw,
		"metadata": map[string]interface{}{
			"openid_relying_party": rpMetadata,
			"federation_entity": map[string]interface{}{
				"organization_name": org.Name,
				"contacts":          contacts,
				"homepage_uri":      entityID,
				"logo_uri":          entityID + "/logo",
				"policy_uri":        entityID + "/privacy",
			},
		},
		"_clavex": map[string]interface{}{
			"generated_at":           now.Format(time.RFC3339),
			"agid_registration_url":  "https://registry.servizicie.interno.gov.it/federation/enrollment",
			"spec_version":           "eIDAS 2.0 / OpenID Federation 1.0",
		},
	}

	// ── Sign as entity configuration JWT ─────────────────────────────────────
	tok := jwt.New()
	for k, v := range entityConfig {
		if err := tok.Set(k, v); err != nil {
			return echo.ErrInternalServerError
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, h.keys.CryptoSigner()))
	if err != nil {
		return echo.ErrInternalServerError
	}

	// ── Response bundle (JSON download) ──────────────────────────────────────
	bundle := map[string]interface{}{
		"entity_configuration_jwt": string(signed),
		"entity_id":                entityID,
		"metadata":                 entityConfig,
	}

	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return echo.ErrInternalServerError
	}

	filename := org.Slug + "-eidas-rp-metadata.json"
	c.Response().Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	return c.Blob(http.StatusOK, "application/json", out)
}

// ── Batch verify ──────────────────────────────────────────────────────────────

// batchVerifyRequest is a single item in the batch-verify body.
type batchVerifyRequest struct {
	// ID is a caller-supplied correlation identifier returned unchanged in each result.
	ID                     string                 `json:"id" validate:"required"`
	VPToken                string                 `json:"vp_token" validate:"required"`
	Nonce                  string                 `json:"nonce" validate:"required"`
	// Audience is the expected KB-JWT aud (client_id / response_uri the holder
	// targeted). Required when the presentation carries a holder-binding KB-JWT;
	// ignored for presentations without one.
	Audience               string                 `json:"audience,omitempty"`
	PresentationDefinition map[string]interface{} `json:"presentation_definition" validate:"required"`
}

// BatchVerify verifies up to 100 vp_tokens in a single request.
// Useful for HR/employer workflows where dozens of credential presentations
// must be checked without issuing one OID4VP session per candidate.
//
//	POST /api/v1/organizations/:org_id/oid4vp/batch-verify
//
// Body:
//
//	{
//	  "items": [
//	    {
//	      "id":                      "<caller correlation id>",
//	      "vp_token":                "<SD-JWT VP token>",
//	      "nonce":                   "<nonce used when the presentation was requested>",
//	      "presentation_definition": { ... }
//	    }
//	  ]
//	}
func (h *OID4VPHandler) BatchVerify(c echo.Context) error {
	if _, err := uuid.Parse(c.Param("org_id")); err != nil {
		return echo.ErrBadRequest
	}

	var body struct {
		Items []batchVerifyRequest `json:"items" validate:"required"`
	}
	if err := bindAndValidate(c, &body); err != nil {
		return err
	}
	if len(body.Items) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "items must not be empty")
	}
	if len(body.Items) > 100 {
		return echo.NewHTTPError(http.StatusBadRequest, "items must not exceed 100 entries per request")
	}

	type itemResult struct {
		ID       string         `json:"id"`
		Verified bool           `json:"verified"`
		Error    *string        `json:"error,omitempty"`
		Claims   map[string]any `json:"claims,omitempty"`
	}

	results := make([]itemResult, len(body.Items))
	for i, item := range body.Items {
		def := unmarshalPresentationDef(item.PresentationDefinition)
		vr, err := oid4w.VerifyPresentation(item.VPToken, def, item.Nonce, item.Audience, nil, h.keys.PublicKey())
		if err != nil {
			msg := err.Error()
			results[i] = itemResult{ID: item.ID, Verified: false, Error: &msg}
		} else {
			results[i] = itemResult{ID: item.ID, Verified: true, Claims: vr.Claims}
		}
	}

	return c.JSON(http.StatusOK, map[string]any{"results": results})
}

// signVPAuthorizationRequest signs an OID4VP AuthorizationRequest as a JAR JWT
// using the x509_san_dns client_id_scheme (OID4VP 1.0 Final §5.7.1).
//
// Header: alg=ES256|RS256, typ=oauth-authz-req+jwt, x5c=[<cert DER>]
// Claims: iss=client_id, aud=https://self-issued.me/v2, iat, exp + all authReq fields.
//
// The wallet verifies the signature against the public key in the x5c cert
// and checks that the cert's dNSName SAN matches the hostname in client_id.
func signVPAuthorizationRequest(authReq oid4w.AuthorizationRequest, key crypto.PrivateKey, certChain [][]byte) (string, error) {
	now := time.Now().UTC()

	// Serialise the struct to a generic map so we can merge JWT registered claims.
	reqJSON, err := json.Marshal(authReq)
	if err != nil {
		return "", fmt.Errorf("marshal authz request: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(reqJSON, &claims); err != nil {
		return "", fmt.Errorf("unmarshal authz request to map: %w", err)
	}

	claims["iss"] = authReq.ClientID
	claims["aud"] = "https://self-issued.me/v2"
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(10 * time.Minute).Unix()

	b := jwt.NewBuilder()
	for k, v := range claims {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("build jar jwt: %w", err)
	}

	// x5c header: full chain, base64-encoded DER (not base64url, per RFC 7515 §4.1.6).
	// Leaf first, then intermediates — wallets need the full path to a trusted root.
	var x5cChain cert.Chain
	for i, der := range certChain {
		if err := x5cChain.AddString(base64.StdEncoding.EncodeToString(der)); err != nil {
			return "", fmt.Errorf("build x5c chain[%d]: %w", i, err)
		}
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.TypeKey, "oauth-authz-req+jwt"); err != nil {
		return "", fmt.Errorf("set typ header: %w", err)
	}
	if err := hdrs.Set(jws.X509CertChainKey, &x5cChain); err != nil {
		return "", fmt.Errorf("set x5c header: %w", err)
	}

	alg := jwa.ES256
	if _, ok := key.(*rsa.PrivateKey); ok {
		alg = jwa.RS256
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("sign jar jwt: %w", err)
	}
	return string(signed), nil
}

// ── Credential Chaining helpers ───────────────────────────────────────────────

// extractInputVCT returns the Verifiable Credential Type identifier of the
// verified credential, trying (in order):
//  1. SD-JWT-VC mandatory "vct" claim (SD-JWT-VC Final §4.1.2).
//  2. "doctype" claim exposed by some mdoc implementations.
//  3. First vct_values / doctype from the DCQL query (session metadata).
//
// Returns "" if the VCT cannot be determined.
func extractInputVCT(session *models.PresentationSession, claims map[string]interface{}) string {
	if vct, ok := claims["vct"].(string); ok && vct != "" {
		return vct
	}
	if dt, ok := claims["doctype"].(string); ok && dt != "" {
		return dt
	}
	// Fall back to DCQL query metadata (mdoc doctype / SD-JWT vct_values).
	if session.DCQLQuery != nil {
		if creds, ok := session.DCQLQuery["credentials"].(map[string]interface{}); ok {
			for _, v := range creds {
				if credMap, ok := v.(map[string]interface{}); ok {
					if meta, ok := credMap["meta"].(map[string]interface{}); ok {
						if vctVals, ok := meta["vct_values"].([]interface{}); ok && len(vctVals) > 0 {
							if s, ok := vctVals[0].(string); ok {
								return s
							}
						}
					}
					if dt, ok := credMap["doctype"].(string); ok && dt != "" {
						return dt
					}
				}
				break // only inspect first credential entry
			}
		}
	}
	return ""
}

// buildChainedOffers creates pre-authorized OID4VCI offers for every credential
// config whose chain_source_vct matches the just-verified input credential's VCT.
// Returns a (possibly nil) slice of offer objects ready for JSON serialisation.
func (h *OID4VPHandler) buildChainedOffers(
	ctx context.Context,
	session *models.PresentationSession,
	claims map[string]interface{},
	c echo.Context,
) []map[string]any {
	inputVCT := extractInputVCT(session, claims)
	if inputVCT == "" {
		return nil
	}

	chainConfigs, err := h.repo.GetCredentialConfigsByChainSourceVCT(ctx, session.OrgID, inputVCT)
	if err != nil || len(chainConfigs) == 0 {
		return nil
	}

	org, err := h.orgs.GetByID(ctx, session.OrgID)
	if err != nil {
		c.Logger().Errorf("credential-chaining: GetByID %s: %v", session.OrgID, err)
		return nil
	}

	// System claims that should not be forwarded into the derived credential payload.
	systemClaims := map[string]bool{
		"iss": true, "sub": true, "iat": true, "exp": true, "nbf": true,
		"jti": true, "vct": true, "cnf": true, "status": true,
	}

	var offers []map[string]any
	for _, chainCfg := range chainConfigs {
		// Build output payload, applying chain_claims_mapping when configured.
		var payload map[string]interface{}
		if chainCfg.ChainClaimsMapping != nil {
			// Selective forwarding: {"output_claim": "input_vp_claim"}.
			payload = make(map[string]interface{}, len(chainCfg.ChainClaimsMapping))
			for outKey, inKeyRaw := range chainCfg.ChainClaimsMapping {
				if inKey, ok := inKeyRaw.(string); ok {
					if val, exists := claims[inKey]; exists {
						payload[outKey] = val
					}
				}
			}
		} else {
			// Forward all non-system VP claims verbatim.
			payload = make(map[string]interface{}, len(claims))
			for k, v := range claims {
				if !systemClaims[k] {
					payload[k] = v
				}
			}
		}

		preAuthCode, err := generateSecureCode()
		if err != nil {
			c.Logger().Errorf("credential-chaining: generateSecureCode for %s: %v", chainCfg.VCT, err)
			continue
		}

		ttl := time.Duration(chainCfg.ChainOfferTTLMins) * time.Minute
		if ttl <= 0 {
			ttl = 15 * time.Minute
		}

		// userID is nil: the VP presentation itself is the authentication mechanism.
		// No tx_code required — the pre-auth code is sufficient for the wallet.
		offer, err := h.repo.CreateCredentialOffer(
			ctx,
			session.OrgID,
			nil,
			chainCfg.VCT,
			preAuthCode,
			nil,
			payload,
			time.Now().Add(ttl),
		)
		if err != nil {
			c.Logger().Errorf("credential-chaining: CreateCredentialOffer for %s: %v", chainCfg.VCT, err)
			continue
		}

		offerURI := buildOfferDeepLink(h.cfg.BaseURL(), org.Slug, offer.ID)
		offers = append(offers, map[string]any{
			"vct":                  chainCfg.VCT,
			"display_name":         chainCfg.DisplayName,
			"credential_offer_uri": offerURI,
			"expires_at":           offer.ExpiresAt,
		})
	}
	return offers
}