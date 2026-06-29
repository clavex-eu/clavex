package handler

// RFC 9126 – OAuth 2.0 Pushed Authorization Requests (PAR)
// Methods on OIDCHandler.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/tracing"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
)

const parTTL = 90 * time.Second
const parKeyPrefix = "par:"

// PushedAuthorizationRequest implements RFC 9126.
// POST /:org_slug/par
//
// Clients POST their authorization parameters here and receive a request_uri
// that they pass to the standard /authorize endpoint within 90 seconds.
//
// When fapi_request_method=signed_non_repudiation (FAPI 2.0 §5.3.3) the
// client sends the parameters inside a signed JAR (RFC 9101 `request` JWT).
// We parse the JWT and merge its claims before validating required fields so
// that parameters carried only inside the JWT are correctly accepted.
func (h *OIDCHandler) PushedAuthorizationRequest(c echo.Context) error {
	ctx := c.Request().Context()
	orgSlug := c.Param("org_slug")
	ctx, span := tracing.Tracer("clavex/handler").Start(ctx, "handler.oidc.par")
	defer span.End()
	span.SetAttributes(attribute.String("org_slug", orgSlug))

	// Client authentication required.
	clientID, _, _, err := h.authenticateClient(c)
	if err != nil {
		span.SetStatus(otelcodes.Error, "invalid_client")
		return tokenError(c, "invalid_client", echoMsg(err))
	}

	// Collect all form values.
	if err := c.Request().ParseForm(); err != nil {
		return tokenError(c, "invalid_request", "unable to parse request body")
	}

	// Build canonical parameter map (exclude client_secret).
	params := make(map[string]string)
	for k, vs := range c.Request().Form {
		if k == "client_secret" {
			continue
		}
		if len(vs) > 0 {
			params[k] = vs[0]
		}
	}
	params["client_id"] = clientID

	// RFC 9126 §2.1: the "request_uri" parameter is NOT allowed in a PAR request.
	if _, hasReqURI := c.Request().Form["request_uri"]; hasReqURI {
		return tokenError(c, "invalid_request",
			"request_uri is not allowed in a pushed authorization request (RFC 9126 §2.1)")
	}

	// JAR (RFC 9101 / FAPI 2.0 §5.3.3): if a signed request object is present,
	// parse it and merge its claims on top of the form params. JWT claims take
	// precedence per RFC 9101 §6.1. This allows all authorization parameters
	// (including response_type) to be carried inside the signed JWT rather than
	// as plain form fields, which is required by fapi_request_method=signed_non_repudiation.
	if requestJWT := params["request"]; requestJWT != "" {
		if jarClient, jarErr := h.clients.GetByClientID(ctx, clientID); jarErr == nil {
			jarParams, parseErr := oidc.ParseJAR(ctx, requestJWT, jarClient, h.issuerFromRequest(c, orgSlug), h.jarDecryptOpts()...)
			if parseErr != nil {
				// JAR RFC 9101 §6.3: request object violations use "invalid_request_object".
				return tokenError(c, "invalid_request_object", parseErr.Error())
			}
			// JAR RFC 9101 §6.2: the request object MUST NOT contain
			// a "request" or "request_uri" authorization request parameter.
			if _, has := jarParams["request"]; has {
				return tokenError(c, "invalid_request_object",
					"request object must not contain a 'request' claim (JAR RFC 9101 §6.2)")
			}
			if _, has := jarParams["request_uri"]; has {
				return tokenError(c, "invalid_request_object",
					"request object must not contain a 'request_uri' claim (JAR RFC 9101 §6.2)")
			}
			for k, v := range jarParams {
				params[k] = v
			}
		}
		// Re-pin client_id to the authenticated client: a signed request object
		// MUST NOT be able to substitute a different client_id (which the
		// authorize endpoint would then trust when the request_uri is presented).
		params["client_id"] = clientID
		// Keep "request" in params so the authorize endpoint can re-use it if needed,
		// but strip it to avoid confusion — PAR stores the resolved flat map.
		delete(params, "request")
	}

	// Require response_type (may now have been supplied via the JAR above).
	if params["response_type"] == "" {
		return tokenError(c, "invalid_request", "response_type is required")
	}

	// RFC 7591 §2 / FAPI 2.0 §5.3.1.1: validate response_type against the
	// client's registered response_types at PAR time. This allows the error to
	// be returned as a direct HTTP 400 response (not a JARM-wrapped redirect),
	// which is required for conformance tests that use signed_non_repudiation.
	if parClient, clientErr := h.clients.GetByClientID(ctx, clientID); clientErr == nil {
		rt := params["response_type"]
		if len(parClient.ResponseTypes) > 0 {
			rtOK := false
			for _, registered := range parClient.ResponseTypes {
				if registered == rt {
					rtOK = true
					break
				}
			}
			if !rtOK {
				return tokenError(c, "unsupported_response_type",
					"response_type is not registered for this client")
			}
		}
		switch rt {
		case "code", "code id_token", "code token", "code id_token token":
			// supported
		default:
			return tokenError(c, "unsupported_response_type",
				"unsupported response_type")
		}
	}

	// FAPI2 Security Profile §5.3.3 + JAR RFC 9101 §6.3:
	// Clients that have registered request_object_signing_alg MUST send all
	// authorization parameters inside a signed request object at the PAR endpoint.
	// A PAR request that arrives as plain form fields (no `request` JWT) MUST be
	// rejected with invalid_request — this is what the conformance test
	// "ensure-unsigned-request-at-par-endpoint-fails" checks.
	//
	// FAPI 2.0 §5.2.2-18 / RFC 7636: PKCE with S256 is required independently
	// of JAR. Enforced below based on client.RequirePKCE.
	if client, clientErr := h.clients.GetByClientID(ctx, clientID); clientErr == nil {
		// JAR enforcement: requires a signed request object.
		if client.RequestObjectSigningAlg != "" && client.RequestObjectSigningAlg != "none" {
			// Enforce JAR: the original POST body must have contained a `request` parameter.
			// c.Request().FormValue reads from the parsed form (not the params map, which
			// had `request` deleted after JAR processing).
			if c.Request().FormValue("request") == "" {
				// No request object was provided at all — use invalid_request per PAR spec
				// (RFC 9126 §2.1).  invalid_request_object is reserved for a request
				// parameter that IS present but contains an invalid JWT (JAR RFC 9101 §6.3).
				return tokenError(c, "invalid_request",
					"signed request object required at PAR endpoint (FAPI 2.0 §5.3.3 / JAR RFC 9101 §6.3)")
			}
		}
		// PKCE enforcement: FAPI 2.0 §5.2.2-18 requires code_challenge with S256.
		// Applied independently of JAR — unsigned FAPI clients also need PKCE.
		if client.RequirePKCE {
			if params["code_challenge"] == "" {
				return tokenError(c, "invalid_request",
					"PKCE code_challenge is required (FAPI 2.0 §5.2.2-18 / RFC 7636)")
			}
			if params["code_challenge_method"] != "S256" {
				return tokenError(c, "invalid_request", "code_challenge_method must be S256")
			}
		}
	}

	// RFC 9449 §10: if a DPoP proof is present in the PAR request, use it to
	// establish (or validate) the dpop_jkt binding for the authorization code.
	//
	// Case 1 – client sends explicit dpop_jkt + DPoP proof: the proof's JWK
	//   thumbprint MUST match the dpop_jkt parameter (RFC 9449 §10.1).
	// Case 2 – client sends DPoP proof but no dpop_jkt: derive dpop_jkt from
	//   the proof's public key so the token endpoint can detect a key switch
	//   (RFC 9449 §10.1 — "the authorization server can derive dpop_jkt from
	//   the DPoP proof if one is present").
	if proofJWT := c.Request().Header.Get("DPoP"); proofJWT != "" {
		htu := h.htuFromEcho(c)
		dpopKey, dpopErr := oidc.ParseDPoPProof(proofJWT, c.Request().Method, htu)
		if dpopErr != nil {
			return tokenError(c, "invalid_dpop_proof", dpopErr.Error())
		}
		if dpopKey != nil {
			if dpopJKT := params["dpop_jkt"]; dpopJKT != "" {
				// Case 1: validate explicit dpop_jkt matches the proof key.
				if dpopKey.JKT != dpopJKT {
					return tokenError(c, "invalid_dpop_proof",
						"dpop_jkt does not match the JWK thumbprint in the DPoP proof")
				}
			} else {
				// Case 2: derive dpop_jkt from the proof key and store it so
				// the auth code is bound to this key even without an explicit
				// dpop_jkt parameter.
				params["dpop_jkt"] = dpopKey.JKT
			}
		}
	}

	// Generate a unique request URI token.
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return echo.ErrInternalServerError
	}
	token := hex.EncodeToString(b)
	requestURI := "urn:ietf:params:oauth:request-uri:" + token
	redisKey := parKeyPrefix + orgSlug + ":" + token

	// Encode params as Redis hash fields.
	args := make([]interface{}, 0, len(params)*2)
	for k, v := range params {
		args = append(args, k, v)
	}

	pipe := h.rdb.Pipeline()
	pipe.HSet(ctx, redisKey, args...)
	pipe.Expire(ctx, redisKey, parTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"request_uri": requestURI,
		"expires_in":  int(parTTL.Seconds()),
	})
}
