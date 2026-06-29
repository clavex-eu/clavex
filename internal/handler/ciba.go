package handler

// OpenID Connect Client-Initiated Backchannel Authentication (CIBA) Core 1.0
// — poll delivery mode.
//
// CIBA decouples the authentication device from the consumption device.
// A client (e.g. a call-centre agent's screen) initiates a backchannel
// authentication request; the end-user authenticates on a separate channel
// (e.g. a mobile push notification); the client polls /token to obtain tokens.
//
// FAPI 2.0 CIBA profile additionally requires:
//   - private_key_jwt or tls_client_auth at the backchannel endpoint
//   - Signed request objects (JAR — RFC 9101) with a `request` parameter
//   - binding_message MUST be present and ≤ 128 chars
//   - login_hint or login_hint_token MUST be present
//   - Polling interval ≥ 5 seconds (CIBA Core §7.3)
//
// This file implements:
//   - BackchannelAuthorize (POST /:org_slug/bc-authorize)
//   - cibaGrant            — polling leg, called from Token()
//   - Admin approve/deny   — POST /api/v1/organizations/:org_id/ciba/:auth_req_id/{approve,deny}
//   - Admin list           — GET  /api/v1/organizations/:org_id/ciba/pending

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/cibanotify"
	"github.com/clavex-eu/clavex/internal/mailer"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/sms"
	"github.com/clavex-eu/clavex/internal/tracing"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
)

const (
	// cibaGrantType is the CIBA grant type URI (CIBA Core §10.1.1).
	cibaGrantType = "urn:openid:params:grant-type:ciba"

	// cibaDefaultExpiresIn is the default auth_req validity in seconds.
	cibaDefaultExpiresIn = 120 * time.Second

	// cibaMaxBindingMessage is the maximum length for the binding_message
	// parameter. FAPI2 CIBA §5.2.3.1 allows up to 128 characters.
	cibaMaxBindingMessage = 128

	// cibaConformanceOrgSlug is the dedicated org seeded for OIDF conformance
	// runs. CIBA poll mode has no real authentication device in that setting,
	// so the suite drives approval/denial out-of-band via the automated CIBA
	// approval endpoint (ConformanceCIBAAutomate), gated to this org alone.
	cibaConformanceOrgSlug = "conformance"
)

// ── BackchannelAuthorize ─────────────────────────────────────────────────────

// BackchannelAuthorize implements CIBA Core §7.1.
//
//	POST /:org_slug/bc-authorize
//
// Request parameters (form-encoded):
//
//	scope            REQUIRED  — MUST contain "openid"
//	login_hint       OPTIONAL* — end-user email; *one of login_hint / id_token_hint required
//	id_token_hint    OPTIONAL* — previously-issued ID token for the user
//	binding_message  REQUIRED for FAPI2 — short text displayed on both devices
//	request          OPTIONAL  — signed JAR (required when client has jwks_uri)
//	requested_expiry OPTIONAL  — hint for requested expiry in seconds
//	acr_values       OPTIONAL  — requested ACR; use "urn:clavex:acr:oid4vp-credential"
//	                             for PSD2 SCA via credential presentation
//	dcql_query       OPTIONAL  — OID4VP DCQL query (JSON) requesting a credential;
//	                             when present, a VP session is created and linked so
//	                             the user's wallet can present a verifiable credential
//	                             (e.g. CIE mdoc) instead of a simple tap-to-approve.
//	                             The response includes `vp_request_uri` for the client.
func (h *OIDCHandler) BackchannelAuthorize(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.oidc.bc_authorize")
	defer span.End()
	span.SetAttributes(attribute.String("org_slug", orgSlug))

	// ── 1. Client authentication ─────────────────────────────────────────────
	clientID, _, _, err := h.authenticateClient(c)
	if err != nil {
		span.SetStatus(otelcodes.Error, "invalid_client")
		return tokenError(c, "invalid_client", err.Error())
	}
	span.SetAttributes(attribute.String("oauth.client_id", clientID))

	client, err := h.clients.GetByClientID(ctx, clientID)
	if err != nil || !client.IsActive {
		return tokenError(c, "invalid_client", "client not found")
	}

	// Validate that client is registered for the CIBA grant type.
	hasGrant := false
	for _, g := range client.GrantTypes {
		if g == cibaGrantType {
			hasGrant = true
			break
		}
	}
	if !hasGrant {
		return tokenError(c, "unauthorized_client", "client not registered for CIBA grant")
	}

	// ── 2. Resolve request parameters (plain form OR signed JAR) ─────────────
	params := make(map[string]string)
	// Read plain form params first.
	for _, k := range []string{"scope", "login_hint", "id_token_hint", "binding_message", "requested_expiry", "client_notification_token", "acr_values", "dcql_query"} {
		if v := c.FormValue(k); v != "" {
			params[k] = v
		}
	}

	// FAPI-CIBA §5.2.2 requires the authentication request to be a signed request
	// object; an unsigned (plain form) request from a FAPI client must be rejected
	// (CIBA-13). FAPI clients authenticate with private_key_jwt or tls_client_auth.
	requestJWT := c.FormValue("request")
	if requestJWT == "" &&
		(client.TokenEndpointAuthMethod == "private_key_jwt" || client.TokenEndpointAuthMethod == "tls_client_auth") {
		return tokenError(c, "invalid_request", "FAPI-CIBA requires a signed request object")
	}

	// If a signed `request` JAR is present, parse and merge its claims.
	if requestJWT != "" {
		// FAPI-CIBA requires the signed request object to carry aud (CIBA-13).
		jarClaims, jarErr := oidc.ParseJAR(ctx, requestJWT, client, h.issuerFromRequest(c, orgSlug), oidc.WithStrictIssAud())
		if jarErr != nil {
			// CIBA Core §13 defines no invalid_request_object code for the
			// backchannel endpoint; a bad request object maps to invalid_request.
			return tokenError(c, "invalid_request", jarErr.Error())
		}
		// JAR claims override plain form params (RFC 9101 §6.1).
		for k, v := range jarClaims {
			params[k] = v
		}
	}

	// ── 3. Validate required parameters ──────────────────────────────────────
	scope := params["scope"]
	if scope == "" {
		return tokenError(c, "invalid_request", "scope is required")
	}
	if !strings.Contains(scope, "openid") {
		return tokenError(c, "invalid_request", "scope must include openid")
	}
	// RFC 6749 §3.3: constrain to the client's registered scopes (empty ⇒ allow-all).
	scope = oidc.FilterScope(scope, client.Scopes)

	bindingMessage := params["binding_message"]
	if bindingMessage == "" {
		// FAPI2 CIBA §5.2.3.1 requires binding_message for confidential clients.
		// For non-FAPI clients we allow it to be optional.
		if client.TokenEndpointAuthMethod == "private_key_jwt" || client.TokenEndpointAuthMethod == "tls_client_auth" {
			return tokenError(c, "invalid_request", "binding_message is required for FAPI2 CIBA")
		}
	}
	if len(bindingMessage) > cibaMaxBindingMessage {
		// CIBA Core §13: when the binding_message is unusable (too long to
		// display on the Authentication Device), return invalid_binding_message.
		return tokenError(c, "invalid_binding_message", "binding_message exceeds maximum length")
	}

	loginHint := params["login_hint"]
	idTokenHint := params["id_token_hint"]
	if loginHint == "" && idTokenHint == "" {
		return tokenError(c, "invalid_request", "login_hint or id_token_hint is required")
	}

	// ── 4. Resolve end-user from hint ─────────────────────────────────────────
	org, err := h.orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return tokenError(c, "invalid_request", "org not found")
	}

	var resolvedUserID *uuid.UUID
	if loginHint != "" {
		// Try to look up the user by email within this org.
		user, lookupErr := h.users.GetByEmail(ctx, org.ID, loginHint)
		if lookupErr == nil && user.IsActive {
			uid := user.ID
			resolvedUserID = &uid
		}
		// If the user is not found we still create the request — the approval
		// step will re-validate. This avoids leaking user enumeration.
	}
	if idTokenHint != "" && resolvedUserID == nil {
		// Verify the id_token_hint was issued by this AS before trusting its
		// `sub` claim — otherwise a client could select an arbitrary victim by
		// forging the hint. (CIBA Core §7.1 resolution; expiry not enforced.)
		tc := h.newTC(h.issuerFromRequest(c, orgSlug))
		tok, hintErr := tc.ParseTrustedIDToken(idTokenHint)
		if hintErr != nil {
			return tokenError(c, "invalid_request", "id_token_hint is invalid or not issued by this server")
		}
		if uid, parseErr := uuid.Parse(tok.Subject()); parseErr == nil {
			resolvedUserID = &uid
		}
	}

	// ── 5. Determine expires_in ───────────────────────────────────────────────
	expiresIn := cibaDefaultExpiresIn
	if re := params["requested_expiry"]; re != "" {
		var secs int
		if _, err := parseIntParam(re, &secs); err == nil && secs > 0 && secs <= 600 {
			expiresIn = time.Duration(secs) * time.Second
		}
	}

	// ── 6. Persist CIBA request ───────────────────────────────────────────────
	authReqID, err := h.cibaRequests.Create(ctx, repository.CIBACreateParams{
		OrgID:          org.ID,
		ClientID:       clientID,
		UserID:         resolvedUserID,
		Scope:          scope,
		BindingMessage: bindingMessage,
		LoginHint:      loginHint,
		ExpiresIn:      expiresIn,
		Interval:       5, // CIBA Core §7.3 minimum
	})
	if err != nil {
		log.Error().Err(err).Str("client_id", clientID).Msg("ciba: create request")
		return echo.ErrInternalServerError
	}

	span.SetAttributes(attribute.String("ciba.auth_req_id", authReqID))
	log.Info().
		Str("auth_req_id", authReqID).
		Str("client_id", clientID).
		Str("org", orgSlug).
		Str("login_hint", loginHint).
		Str("binding_message", bindingMessage).
		Msg("ciba: backchannel auth request accepted")

	// ── 8. If a DCQL query was provided, create a linked OID4VP session ───────
	//
	// This enables CIBA + OID4VP SCA: instead of a simple tap the user's wallet
	// presents a verifiable credential (e.g. CIE as ISO 18013-5 mdoc or SD-JWT VC).
	// The VP session auto-approves the CIBA request on successful credential
	// verification — no separate admin action is needed.
	//
	// The openid4vp:// deep link is embedded in the push notification so the
	// wallet app opens the correct presentation flow directly.
	var vpRequestURI string
	if dcqlParam := params["dcql_query"]; dcqlParam != "" {
		var dcqlQuery map[string]interface{}
		if parseErr := json.Unmarshal([]byte(dcqlParam), &dcqlQuery); parseErr == nil {
			baseURL := h.cfg.Auth.IssuerBase
			vpRequestID, vpNonce, vpErr := h.createCIBALinkedVPSession(ctx, org, authReqID, orgSlug, dcqlQuery)
			if vpErr != nil {
				log.Warn().Err(vpErr).Str("auth_req_id", authReqID).Msg("ciba: failed to create linked VP session — falling back to simple CIBA")
			} else {
				_ = vpNonce // embedded in the VP session; wallet retrieves it via request_uri
				requestURI := baseURL + "/" + orgSlug + "/wallet/request/" + vpRequestID
				vpRequestURI = "openid4vp://?request_uri=" + requestURI
				span.SetAttributes(attribute.String("ciba.vp_request_id", vpRequestID))
				log.Info().
					Str("auth_req_id", authReqID).
					Str("vp_request_id", vpRequestID).
					Str("acr_values", params["acr_values"]).
					Msg("ciba: linked VP session created for OID4VP SCA")
			}
		} else {
			log.Warn().Err(parseErr).Str("auth_req_id", authReqID).Msg("ciba: invalid dcql_query JSON — ignoring VP-enhanced SCA")
		}
	}

	// ── 9. Send end-user notification (non-blocking) ──────────────────────────
	go h.sendCIBANotification(org.ID, resolvedUserID, authReqID, client.Name, loginHint, bindingMessage, int(expiresIn.Seconds()), vpRequestURI)

	// CIBA Core §7.3 response.
	resp := map[string]any{
		"auth_req_id": authReqID,
		"expires_in":  int(expiresIn.Seconds()),
		"interval":    5,
	}
	// Include vp_request_uri when a VP-enhanced SCA session was created.
	// The merchant/client embeds this in their mobile payment app so the
	// wallet can be launched directly.
	if vpRequestURI != "" {
		resp["vp_request_uri"] = vpRequestURI
	}
	return c.JSON(http.StatusOK, resp)
}

// ── Conformance automated approval ─────────────────────────────────────────────

// ConformanceCIBAAutomate approves or denies a pending CIBA request without any
// device interaction. It exists solely to drive the OIDF conformance suite,
// which calls a configured automated_ciba_approval_url with the auth_req_id and
// an action of "allow" or "deny" (poll mode has no device to tap).
//
// SECURITY: this endpoint performs NO user authentication, so it is restricted
// to the dedicated conformance org slug and returns 404 for any other tenant.
// It must never be reachable for a real org — an unauthenticated caller could
// otherwise approve another user's backchannel authentication.
func (h *OIDCHandler) ConformanceCIBAAutomate(c echo.Context) error {
	if c.Param("org_slug") != cibaConformanceOrgSlug {
		return c.NoContent(http.StatusNotFound)
	}

	authReqID := c.QueryParam("auth_req_id")
	if authReqID == "" {
		authReqID = c.FormValue("auth_req_id")
	}
	if authReqID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "auth_req_id is required"})
	}

	action := c.QueryParam("action")
	if action == "" {
		action = c.FormValue("action")
	}

	ctx := c.Request().Context()
	var (
		err    error
		status string
	)
	switch action {
	case "allow", "approve":
		err, status = h.cibaRequests.Approve(ctx, authReqID), "approved"
	case "deny", "reject":
		err, status = h.cibaRequests.Deny(ctx, authReqID), "denied"
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "action must be allow or deny"})
	}
	if err != nil {
		log.Warn().Err(err).Str("auth_req_id", authReqID).Str("action", action).Msg("ciba: conformance automate failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update request"})
	}
	log.Info().Str("auth_req_id", authReqID).Str("action", action).Msg("ciba: conformance automate")
	return c.JSON(http.StatusOK, map[string]string{"status": status})
}

// ── Polling grant ─────────────────────────────────────────────────────────────

// cibaGrant handles the token endpoint polling leg of CIBA Core §11.
// Called from Token() when grant_type=urn:openid:params:grant-type:ciba.
func (h *OIDCHandler) cibaGrant(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")

	clientID, _, _, err := h.authenticateClient(c)
	if err != nil {
		return tokenError(c, "invalid_client", err.Error())
	}

	authReqID := c.FormValue("auth_req_id")
	if authReqID == "" {
		return tokenError(c, "invalid_request", "auth_req_id is required")
	}

	cr, err := h.cibaRequests.Get(ctx, authReqID)
	if err != nil || cr == nil {
		return tokenError(c, "invalid_grant", "auth_req_id not found")
	}
	if cr.ClientID != clientID {
		return tokenError(c, "invalid_grant", "auth_req_id was not issued to this client")
	}
	if time.Now().After(cr.ExpiresAt) {
		return tokenError(c, "expired_token", "auth_req_id has expired")
	}

	// RFC 8705 §3 / FAPI-CIBA holder-of-key: tls_client_certificate_bound_access_tokens
	// requires a valid TLS client certificate on every token request, including the
	// CIBA polling leg. Reject before status checks so a missing certificate errors
	// out regardless of approval state (otherwise a still-pending poll would mask the
	// missing cert with authorization_pending).
	if cl, clErr := h.clients.GetByClientID(ctx, clientID); clErr == nil && cl != nil &&
		cl.TLSClientCertBoundAccessTokens && oidc.CertFromRequest(c.Request()) == nil {
		return tokenError(c, "invalid_client", "mTLS client certificate is required for this client")
	}

	// CIBA Core §11 / RFC 8628 §3.5: the client MUST wait at least `interval`
	// seconds between polls; a faster poll is answered with slow_down. Enforced
	// with a short-lived Redis key whose TTL equals the interval.
	interval := cr.Interval
	if interval <= 0 {
		interval = 5
	}
	if ok, _ := h.rdb.SetNX(ctx, "ciba:poll:"+authReqID, "1", time.Duration(interval)*time.Second).Result(); !ok {
		return tokenError(c, "slow_down", "polling too frequently; wait for the interval before retrying")
	}

	switch cr.Status {
	case "pending":
		// CIBA Core §11 — client must wait for approval.
		return tokenError(c, "authorization_pending", "user has not yet approved the request")

	case "denied":
		// Clean up so denied requests don't accumulate.
		_ = h.cibaRequests.Delete(ctx, authReqID)
		return tokenError(c, "access_denied", "user denied the backchannel authentication request")

	case "approved":
		if cr.UserID == nil {
			return tokenError(c, "invalid_grant", "user identity not resolved")
		}

		user, err := h.users.GetByID(ctx, *cr.UserID)
		if err != nil || !user.IsActive {
			return tokenError(c, "invalid_grant", "user not found or inactive")
		}

		tc := h.newTC(h.issuerFromRequest(c, orgSlug))
		// Apply per-org/per-client TTL overrides for the CIBA polling grant.
		var cibaCl *models.OIDCClient
		if fetched, clErr := h.clients.GetByClientID(ctx, clientID); clErr == nil {
			cibaCl = fetched
		}
		var cibaOrg *models.Organization
		if o, oErr := h.orgs.GetBySlug(ctx, orgSlug); oErr == nil {
			cibaOrg = o
		}
		h.applyOrgOverrides(ctx, tc, cibaOrg, cibaCl)

		uc := oidc.UserClaimsFromModel(user)
		if roleNames, err := h.users.FlattenRoleNames(ctx, user.ID); err == nil {
			uc.Roles = roleNames
		}
		if gnames, err := h.groups.GroupsForUser(ctx, user.ID); err == nil {
			uc.Groups = gnames
		}
		uc.ExtraClaims = oidc.ResolveMapperExtraClaims(ctx, h.mappers, clientID, uc, user.Metadata)

		// When this CIBA was approved via OID4VP credential presentation, enrich
		// the ID token with the ACR value and the verified credential claims.
		// The bank receives acr="urn:clavex:acr:oid4vp-credential" + verified_claims
		// in the ID token, satisfying PSD2 RTS Article 9 Level 2 SCA requirements.
		if cr.ACR != "" {
			uc.Acr = cr.ACR
		}
		if len(cr.VPClaims) > 0 {
			if uc.ExtraClaims == nil {
				uc.ExtraClaims = make(map[string]any)
			}
			uc.ExtraClaims["verified_claims"] = map[string]any{
				"verification": map[string]any{
					"trust_framework": "oid4vp",
					"assurance_level": "high",
				},
				"claims": cr.VPClaims,
			}
			uc.ExtraClaims["amr"] = []string{"pop"} // proof-of-possession via credential
		}

		// DPoP (RFC 9449): when the client presents a proof on the successful
		// token poll, bind the issued access + refresh tokens to its key.
		if dpopVals := c.Request().Header.Values("DPoP"); len(dpopVals) > 1 {
			return tokenError(c, "invalid_dpop_proof", "exactly one DPoP header is allowed (RFC 9449 §7.1)")
		}
		dpopKey, dpopErr := oidc.ParseDPoPProof(c.Request().Header.Get("DPoP"), c.Request().Method, h.htuFromEcho(c))
		if dpopErr != nil {
			return tokenError(c, "invalid_dpop_proof", dpopErr.Error())
		}
		if dpopKey != nil {
			if replayErr := oidc.CheckJTI(ctx, dpopKey.JTI, h.rdb); replayErr != nil {
				return tokenError(c, "invalid_dpop_proof", "dpop proof jti already used")
			}
		}

		// Extract client cert for certificate-bound access tokens (RFC 8705).
		mtlsCert := oidc.CertFromRequest(c.Request())
		if mtlsCert == nil {
			// FAPI-CIBA clients are certificate-bound; a nil cert here means the
			// mTLS terminator did not forward the client cert to this endpoint,
			// so the issued token carries no cnf and downstream binding checks
			// cannot run. Log which cert-bearing headers actually arrived to
			// pinpoint where in the proxy chain the cert is dropped.
			hdr := c.Request().Header
			log.Warn().
				Str("client_id", clientID).
				Bool("tls_peer", c.Request().TLS != nil && len(c.Request().TLS.PeerCertificates) > 0).
				Bool("ssl_client_cert", hdr.Get("Ssl-Client-Cert") != "" || hdr.Get("X-SSL-Client-Cert") != "").
				Bool("x_fwd_tls_client_cert", hdr.Get("X-Forwarded-Tls-Client-Cert") != "").
				Bool("xfcc", hdr.Get("X-Forwarded-Client-Cert") != "").
				Msg("ciba: no mTLS cert at token endpoint — token will not be certificate-bound")
		}

		accessToken, _, err := tc.IssueAccessToken(clientID, cr.Scope, &uc, dpopKey, mtlsCert)
		if err != nil {
			return echo.ErrInternalServerError
		}
		uc.AtHash = oidc.ComputeAtHash(accessToken)

		idTokenAlg := ""
		if cl, clErr := h.clients.GetByClientID(ctx, clientID); clErr == nil {
			idTokenAlg = cl.IDTokenSignedResponseAlg
		}
		idToken, err := tc.IssueIDToken(clientID, "", uc, oidc.ResolveIDTokenAlg(idTokenAlg))
		if err != nil {
			return echo.ErrInternalServerError
		}

		dpopJKT := ""
		if dpopKey != nil {
			dpopJKT = dpopKey.JKT
		}
		familyID := uuid.New()
		refreshToken, err := oidc.IssueRefreshToken(ctx, h.tokens, repository.CreateRefreshTokenParams{
			OrgID:     cr.OrgID,
			ClientID:  clientID,
			UserID:    cr.UserID,
			FamilyID:  familyID,
			Scope:     cr.Scope,
			ExpiresAt: time.Now().Add(tc.RefreshTokenTTL),
			DpopJKT:   dpopJKT,
		})
		if err != nil {
			return echo.ErrInternalServerError
		}

		// Delete the consumed auth_req to prevent double-spending.
		_ = h.cibaRequests.Delete(ctx, authReqID)

		// DPoP-bound tokens use token_type=DPoP (RFC 9449 §5); mTLS binding
		// stays Bearer (cnf.x5t#S256 is carried in the token body).
		tokenType := "Bearer"
		if dpopKey != nil {
			tokenType = "DPoP"
		}

		return c.JSON(http.StatusOK, &oidc.TokenSet{
			AccessToken:  accessToken,
			IDToken:      idToken,
			RefreshToken: refreshToken,
			TokenType:    tokenType,
			ExpiresIn:    int(tc.AccessTokenTTL.Seconds()),
			Scope:        cr.Scope,
		})
	}

	return echo.ErrInternalServerError
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

// CIBAListPending lists pending CIBA requests for an org (admin).
//
//	GET /api/v1/organizations/:org_id/ciba/pending
func (h *OIDCHandler) CIBAListPending(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	reqs, err := h.cibaRequests.ListPending(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if reqs == nil {
		reqs = []*repository.CIBARequest{}
	}
	return c.JSON(http.StatusOK, reqs)
}

// CIBAApprove marks a CIBA request as approved (admin / out-of-band system).
//
//	POST /api/v1/organizations/:org_id/ciba/:auth_req_id/approve
//
// The approved user is the one resolved from login_hint/id_token_hint when the
// backchannel request was created — the approver MUST NOT be able to substitute
// a different user_id, or any actor with the "sessions" permission could mint
// tokens impersonating an arbitrary user (CIBA Core §7.3 binds consent to the
// requested user). The request body is therefore ignored.
func (h *OIDCHandler) CIBAApprove(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	authReqID := c.Param("auth_req_id")
	if authReqID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "auth_req_id is required")
	}

	// Verify the request belongs to this org.
	ctx := c.Request().Context()
	cr, err := h.cibaRequests.Get(ctx, authReqID)
	if err != nil || cr == nil {
		return echo.NewHTTPError(http.StatusNotFound, "auth_req_id not found")
	}
	if cr.OrgID != orgID {
		return echo.NewHTTPError(http.StatusNotFound, "auth_req_id not found")
	}
	// The user must already be resolved (from the hint at request time). If the
	// hint did not match a known user, the request cannot be approved.
	if cr.UserID == nil {
		return echo.NewHTTPError(http.StatusConflict, "user identity was not resolved for this request; cannot approve")
	}

	if err := h.cibaRequests.Approve(ctx, authReqID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "approved"})
}

// CIBADeny marks a CIBA request as denied (admin / out-of-band system).
//
//	POST /api/v1/organizations/:org_id/ciba/:auth_req_id/deny
func (h *OIDCHandler) CIBADeny(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	authReqID := c.Param("auth_req_id")
	if authReqID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "auth_req_id is required")
	}

	ctx := c.Request().Context()
	cr, err := h.cibaRequests.Get(ctx, authReqID)
	if err != nil || cr == nil {
		return echo.NewHTTPError(http.StatusNotFound, "auth_req_id not found")
	}
	if cr.OrgID != orgID {
		return echo.NewHTTPError(http.StatusNotFound, "auth_req_id not found")
	}

	if err := h.cibaRequests.Deny(ctx, authReqID); err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "denied"})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// extractSubFromHint decodes an id_token_hint (JWT) without verification
// and returns the `sub` claim. Used for user resolution only — security
// is not a concern here because the approval step re-validates.
func extractSubFromHint(rawJWT string) (string, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) < 2 {
		return "", echo.ErrBadRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	sub, _ := claims["sub"].(string)
	return sub, nil
}

// parseIntParam parses a decimal integer string into *out and returns nil on success.
func parseIntParam(s string, out *int) (int, error) {
	var n int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, echo.ErrBadRequest
		}
		n = n*10 + int(ch-'0')
	}
	*out = n
	return n, nil
}

// ── CIBA notification dispatcher ─────────────────────────────────────────────

// sendCIBANotification builds and fires the per-org CIBA notification. It is
// called as a goroutine so it never blocks the HTTP response. All errors are
// logged at Warn level; failures do NOT fail the CIBA request itself — the
// call-centre agent can always approve/deny via the admin console.
//
// vpRequestURI, when non-empty, indicates this is a CIBA+OID4VP SCA flow. The
// openid4vp:// deep link is forwarded to push, email, and webhook receivers so
// the wallet app can be launched to present a verifiable credential.
func (h *OIDCHandler) sendCIBANotification(
	orgID uuid.UUID,
	userID *uuid.UUID,
	authReqID, appName, loginHint, bindingMessage string,
	expiresIn int,
	vpRequestURI string,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg, err := h.cibaNotifyCfg.Get(ctx, orgID)
	if err != nil {
		log.Warn().Err(err).Str("org_id", orgID.String()).Msg("ciba-notify: failed to load notification config")
		return
	}
	if cfg == nil {
		// No notification config — silent mode (admin console only).
		return
	}

	// Build approve/deny URLs.  The approve and deny API endpoints are at:
	//   POST /api/v1/organizations/:org_id/ciba/:auth_req_id/{approve,deny}
	// We expose them as direct API endpoints; call-centre UIs embed an admin
	// token in the Authorization header.  For SMS/email "1-click" links we
	// would need a separate short-lived signed-URL gateway (future work).
	baseURL := h.cfg.Auth.IssuerBase // fallback
	if cfg.BaseURL != nil && *cfg.BaseURL != "" {
		baseURL = *cfg.BaseURL
	}
	approveURL := baseURL + "/api/v1/organizations/" + orgID.String() + "/ciba/" + authReqID + "/approve"
	denyURL := baseURL + "/api/v1/organizations/" + orgID.String() + "/ciba/" + authReqID + "/deny"

	// Resolve registered push tokens for this user (if any).
	var deviceTokens []cibanotify.DeviceToken
	if cfg.PushEnabled && userID != nil {
		if dts, dtErr := h.cibaPushTokens.ListForUser(ctx, orgID, *userID); dtErr == nil {
			for _, dt := range dts {
				deviceTokens = append(deviceTokens, cibanotify.DeviceToken{
					Platform:    dt.Platform,
					DeviceToken: dt.DeviceToken,
				})
			}
		} else {
			log.Warn().Err(dtErr).Str("org_id", orgID.String()).Msg("ciba-notify: failed to load device tokens")
		}
	}

	params := cibanotify.Params{
		AuthReqID:      authReqID,
		AppName:        appName,
		UserEmail:      loginHint,
		BindingMessage: bindingMessage,
		ApproveURL:     approveURL,
		DenyURL:        denyURL,
		ExpiresIn:      expiresIn,
		DeviceTokens:   deviceTokens,
		VPRequestURI:   vpRequestURI,
	}

	var webhook cibanotify.WebhookSender
	if cfg.WebhookURL != nil && *cfg.WebhookURL != "" {
		secret := ""
		if cfg.WebhookSecret != nil {
			secret = *cfg.WebhookSecret
		}
		webhook = cibanotify.NewWebhookChannel(cibanotify.WebhookConfig{
			URL:     *cfg.WebhookURL,
			Secret:  secret,
			Headers: cfg.WebhookHeaders,
		})
	}

	var emailSender cibanotify.EmailSender
	if cfg.EmailEnabled && loginHint != "" {
		if m, mailErr := mailer.ForOrg(ctx, h.smtp, orgID); mailErr == nil {
			emailSender = cibanotify.NewEmailChannel(m, appName)
		} else {
			log.Warn().Err(mailErr).Str("org_id", orgID.String()).Msg("ciba-notify: mailer not configured")
		}
	}

	var smsSender cibanotify.SMSSender
	if cfg.SMSEnabled {
		if p, smsErr := sms.ForOrg(ctx, h.smsSettings, orgID); smsErr == nil {
			smsSender = cibanotify.NewSMSChannel(p)
		} else {
			log.Warn().Err(smsErr).Str("org_id", orgID.String()).Msg("ciba-notify: sms provider not configured")
		}
	}

	// Build the push channel if credentials are configured.
	var pushSender cibanotify.PushSender
	if cfg.PushEnabled && len(deviceTokens) > 0 {
		var apnsCfg *cibanotify.APNsConfig
		if cfg.APNsKeyP8 != nil && cfg.APNsKeyID != nil && cfg.APNsTeamID != nil && cfg.APNsBundleID != nil {
			apnsCfg = &cibanotify.APNsConfig{
				KeyP8:      *cfg.APNsKeyP8,
				KeyID:      *cfg.APNsKeyID,
				TeamID:     *cfg.APNsTeamID,
				BundleID:   *cfg.APNsBundleID,
				Production: cfg.APNsProduction,
			}
		}
		var fcmCfg *cibanotify.FCMConfig
		if cfg.FCMServiceAccountJSON != nil && *cfg.FCMServiceAccountJSON != "" {
			fcmCfg = &cibanotify.FCMConfig{ServiceAccountJSON: *cfg.FCMServiceAccountJSON}
		}
		if apnsCfg != nil || fcmCfg != nil {
			pushSender = cibanotify.NewPushChannel(apnsCfg, fcmCfg)
		}
	}

	notifier := cibanotify.New(webhook, emailSender, smsSender)
	if pushSender != nil {
		notifier = notifier.WithPush(pushSender)
	}
	if err := notifier.Notify(ctx, params); err != nil {
		log.Warn().Err(err).Str("auth_req_id", authReqID).Msg("ciba-notify: notification failed")
	}
}

// ── CIBA + OID4VP SCA helpers ─────────────────────────────────────────────────

// createCIBALinkedVPSession creates an OID4VP presentation session linked to
// the given CIBA auth request. It returns the VP session's requestID and nonce.
//
// The session uses the provided DCQL query to specify which verifiable
// credential the wallet must present (e.g. CIE as ISO 18013-5 mdoc).
// When the wallet submits a valid vp_token, the CIBA request is automatically
// approved by OID4VPHandler.Response() without any separate admin action.
func (h *OIDCHandler) createCIBALinkedVPSession(
	ctx context.Context,
	org *models.Organization,
	authReqID string,
	orgSlug string,
	dcqlQuery map[string]interface{},
) (requestID, nonce string, err error) {
	requestID, err = generateRequestID()
	if err != nil {
		return "", "", err
	}
	nonce, err = generateNonce()
	if err != nil {
		return "", "", err
	}

	baseURL := h.cfg.Auth.IssuerBase
	responseURI := baseURL + "/" + orgSlug + "/wallet/response"

	_, err = h.vpSessions.CreatePresentationSession(
		ctx,
		org.ID,
		requestID,
		nil, // presentationDefinition — nil because DCQL is used
		dcqlQuery,
		responseURI,
		nil, // redirectURI
		nil, // state
		nonce,
		time.Now().Add(10*time.Minute),
		&authReqID,
		"redirect_uri:"+responseURI,
	)
	if err != nil {
		return "", "", err
	}
	return requestID, nonce, nil
}

