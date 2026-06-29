package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/clavex-eu/clavex/internal/tracing"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
)

// AuthorizeRequest represents the validated parameters of an authorization request.
type AuthorizeRequest struct {
	OrgSlug        string
	OrgID          string
	ClientID       string
	RedirectURI    string
	Scope          string
	State          string
	Nonce          string
	PKCEChallenge  string
	PKCEMethod     string
	IsPublicClient bool
	// ResponseMode selects how the authorization response is returned.
	// Supported: "query" (default), "fragment" (hybrid default), "form_post",
	// "jwt", "query.jwt", "fragment.jwt" (JARM).
	ResponseMode string
	// ResponseType is the value from the authorization request, e.g. "code"
	// or "code id_token" (hybrid flow). Defaults to "code".
	ResponseType string
	// OIDC Interactive parameters
	Prompt    string // "none", "login", "consent", "select_account"
	MaxAge    int    // 0 = not set; seconds until re-auth required
	LoginHint string // pre-fill email in login form
	Display   string // "page", "popup", "touch", "wap" (informational)
	// Set by the handler after successful user authentication
	AuthTime int64 // Unix timestamp

	// AuthorizationDetails is the parsed RFC 9396 RAR array from the
	// authorization request. nil = no RAR in this request.
	AuthorizationDetails []map[string]any
	// AcrValues is the space-separated list of requested ACR values.
	// The server selects the highest it can satisfy and stores it in the
	// auth code so the ID token can include the acr claim (OIDC Core §2).
	AcrValues string
	// ClaimsParam is the raw JSON value of the OIDC claims request parameter
	// (OIDC Core §5.5). Carried through to the auth code so BuildUserInfo can
	// return explicitly requested claims regardless of scope.
	ClaimsParam string
	// ExtraClaims are additional claims injected by the login flow engine
	// (enrich_claims / set_claim steps). Merged into the id_token at exchange.
	ExtraClaims map[string]any
	// DpopJKT is the JWK Thumbprint committed by the client via the dpop_jkt
	// authorization request parameter (RFC 9449 §10). When present the token
	// endpoint MUST verify that the DPoP proof key matches this value.
	DpopJKT string
	// SessionIsolation, when true, means this client's SSO session is kept
	// separate from all other clients' sessions — login on App A does not grant
	// silent SSO to App B even within the same org.
	SessionIsolation bool
}

// AuthorizeError is an OAuth2 error that must be returned via redirect.
type AuthorizeError struct {
	Code         string // OAuth2 error code, e.g. "invalid_request"
	Description  string
	RedirectURI  string // may be empty if redirect_uri itself is invalid
	State        string
	ResponseMode string // if set, error response must use this mode (e.g. "query.jwt")
	ClientID     string // required for JARM error response (JWT aud claim)
	OrgSlug      string // required for JARM issuer construction
}

func (e *AuthorizeError) Error() string {
	return fmt.Sprintf("authorize error %s: %s", e.Code, e.Description)
}

// ClientLookup abstracts the client lookup needed by ValidateAuthorizeRequest.
// It is implemented by *repository.ClientRepository.
type ClientLookup interface {
	GetByClientID(ctx context.Context, clientID string) (*models.OIDCClient, error)
}

// ValidateAuthorizeRequest validates the incoming authorization request parameters
// against the registered client. Returns a clean AuthorizeRequest or an
// AuthorizeError describing how to respond.
//
// requestObjectProcessed must be true when the caller has already parsed a PAR
// request_uri or a JAR request object for this request. Clients that declare a
// request_object_signing_alg (FAPI 2.0 §5.2.2) MUST use PAR; requests that
// arrive without one are rejected with invalid_request.
func ValidateAuthorizeRequest(
	ctx context.Context,
	params map[string]string,
	orgSlug, orgID string,
	clients ClientLookup,
	requestObjectProcessed bool,
	// credentialScopes is an optional set of OID4VCI credential scope values
	// registered for this org. When a non-empty scope consists solely of
	// credential scopes (no "openid"), the OIDC "must include openid" check is
	// skipped so that wallet-initiated authorization code flows work correctly.
	credentialScopes ...map[string]bool,
) (*AuthorizeRequest, *AuthorizeError) {
	ctx, span := tracing.Tracer("clavex/oidc").Start(ctx, "oidc.authorize.validate")
	defer span.End()

	clientID := params["client_id"]
	span.SetAttributes(
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.org_id", orgID),
		attribute.String("oauth.response_type", params["response_type"]),
		attribute.String("oauth.scope", params["scope"]),
	)

	if clientID == "" {
		return nil, &AuthorizeError{Code: "invalid_request", Description: "client_id is required"}
	}

	client, err := clients.GetByClientID(ctx, clientID)
	if err != nil || !client.IsActive {
		// An unknown / unresolvable client_id (e.g. an invalid federation entity
		// identifier) is a malformed request parameter: invalid_request is the
		// spec-correct authorization-endpoint error and is what conformance
		// expects for this case.
		return nil, &AuthorizeError{Code: "invalid_request", Description: "invalid client_id: unknown or inactive client"}
	}
	if client.OrgID.String() != orgID {
		return nil, &AuthorizeError{Code: "unauthorized_client", Description: "client does not belong to this organization"}
	}

	redirectURI := params["redirect_uri"]
	if !isAllowedRedirectURI(redirectURI, client.RedirectURIs) {
		// redirect_uri invalid → cannot redirect back, must show error page
		return nil, &AuthorizeError{Code: "invalid_request", Description: "redirect_uri not allowed"}
	}

	// From here on, errors redirect to redirect_uri
	state := params["state"]

	// Apply the hybrid-flow response_mode default EARLY so that all error
	// redirects (including the PAR check below) use the correct channel.
	// OIDC Core §3.3.2.1: default response_mode for hybrid flows is "fragment".
	// This must happen before any authErr() call that reads params["response_mode"].
	if params["response_mode"] == "" &&
		(strings.Contains(params["response_type"], "id_token") ||
			strings.Contains(params["response_type"], "token")) {
		params["response_mode"] = "fragment"
	}

	// helper to build a redirectable error with full context so callers
	// can construct JARM-wrapped error responses when needed.
	authErr := func(code, desc string) *AuthorizeError {
		rm := normaliseResponseMode(params["response_mode"])
		return &AuthorizeError{
			Code:         code,
			Description:  desc,
			RedirectURI:  redirectURI,
			State:        state,
			ResponseMode: rm,
			ClientID:     clientID,
			OrgSlug:      orgSlug,
		}
	}

	// OpenID Federation §12.1.1.1 / RFC 9101: a signed authorization request
	// object must not carry a sub claim — it would resemble a client
	// authentication assertion. Reject it (redirected back to the client) when
	// the request was conveyed as a request object.
	if requestObjectProcessed && params["sub"] != "" {
		return nil, authErr("invalid_request_object",
			"request object must not contain a sub claim (OpenID Federation 12.1.1.1)")
	}

	// A federation request-object policy violation detected while parsing the JAR
	// (e.g. a missing required claim) is surfaced here, now that the redirect_uri
	// is validated, as a redirectable error to the RP.
	if requestObjectProcessed && params[JARPolicyErrorKey] != "" {
		return nil, authErr(params[JARPolicyErrorKey], params[JARPolicyDescKey])
	}

	// FAPI 2.0 §5.2.2: PAR is required when either:
	//  a) the client flag require_par is set (explicit FAPI 2.0 enforcement), or
	//  b) the client declares a real request-object signing algorithm (not empty
	//     or "none"), which implies JAR+PAR usage. "none" means unsigned request
	//     objects are allowed — PAR is not required for that case alone.
	requiresPAR := client.RequirePAR ||
		(client.RequestObjectSigningAlg != "" && client.RequestObjectSigningAlg != "none")
	if !requestObjectProcessed && requiresPAR {
		return nil, authErr("invalid_request",
			"this client requires PAR: authorization request must use a request_uri obtained from the PAR endpoint")
	}

	rt := params["response_type"]
	// Validate response_type against the client's registered response_types.
	// RFC 7591 §2 defaults response_types to ["code"] when not specified.
	// This rejects e.g. code id_token for FAPI2 clients that only registered "code".
	if len(client.ResponseTypes) > 0 {
		rtOK := false
		for _, registered := range client.ResponseTypes {
			if registered == rt {
				rtOK = true
				break
			}
		}
		if !rtOK {
			return nil, authErr("unsupported_response_type",
				"response_type is not registered for this client")
		}
	}
	// Validate response_type is a value the server supports at all.
	switch rt {
	case "code", "code id_token", "code token", "code id_token token":
		// supported
	default:
		return nil, authErr("unsupported_response_type", "only response_type=code is supported")
	}

	scope := params["scope"]
	hasAuthDetails := params["authorization_details"] != ""
	// OIDC Core §3.1.2.1: the client MUST explicitly include "openid" in scope
	// for an OIDC request.  We no longer auto-default to "openid" when scope is
	// absent: a missing scope is a valid plain OAuth2 / OID4VCI code flow and
	// MUST NOT produce an id_token (ExpectNoIdTokenInTokenResponse in VCI tests).
	//
	// We only reject a non-empty scope that lacks "openid" AND has no
	// authorization_details; when authorization_details is present the wallet may
	// use any credential-specific scope values alongside (or instead of) "openid".
	//
	// Additionally, attest_jwt_client_auth clients are exclusively OID4VCI/HAIP
	// wallets whose scope carries a credential configuration ID (OID4VCI §5.1),
	// not an OIDC scope — so "openid" is not required for them either.
	isAttestClient := client.TokenEndpointAuthMethod == "attest_jwt_client_auth"
	// Check whether every token in scope is a registered credential scope
	// (OID4VCI wallet-initiated auth code flow — no "openid" needed).
	isCredentialScope := false
	if len(credentialScopes) > 0 && credentialScopes[0] != nil && scope != "" {
		allCredential := true
		for _, s := range strings.Fields(scope) {
			if !credentialScopes[0][s] {
				allCredential = false
				break
			}
		}
		isCredentialScope = allCredential
	}
	if scope != "" && !strings.Contains(scope, "openid") && !hasAuthDetails && !isAttestClient && !isCredentialScope {
		return nil, authErr("invalid_scope", "scope must include openid")
	}

	// RFC 6749 §3.3: silently downgrade the requested scope to the client's
	// registered scopes (extras dropped). Skipped for OID4VCI/HAIP wallet flows
	// whose scope carries credential configuration IDs that are not registered
	// as client scopes, and for authorization_details-only requests.
	if !hasAuthDetails && !isAttestClient && !isCredentialScope {
		scope = FilterScope(scope, client.Scopes)
	}

	// A client is "public" only when it explicitly declares no authentication
	// (token_endpoint_auth_method = "none").  Confidential clients that use
	// private_key_jwt or self-signed TLS have no ClientSecretHash either, so
	// testing for a nil secret is not sufficient.
	isPublic := client.TokenEndpointAuthMethod == "none"
	pkceChallenge := params["code_challenge"]
	pkceMethod := params["code_challenge_method"]

	if isPublic && pkceChallenge == "" {
		return nil, authErr("invalid_request", "PKCE code_challenge required for public clients")
	}
	// FAPI2 Security Profile §5.3.1.1: all FAPI2 clients MUST use PKCE with S256.
	// FAPI2 clients are identified by a real signing alg (not empty or "none").
	if client.RequestObjectSigningAlg != "" && client.RequestObjectSigningAlg != "none" && pkceChallenge == "" {
		return nil, authErr("invalid_request", "PKCE code_challenge required")
	}
	if pkceChallenge != "" && pkceMethod != "S256" {
		return nil, authErr("invalid_request", "only code_challenge_method=S256 is supported")
	}

	// Validate response_mode (JARM: draft-ietf-oauth-jarm; also form_post + fragment)
	// For hybrid flows, default to "fragment" if no mode specified (OIDC Core §3.3.2.1).
	isHybridRT := strings.Contains(params["response_type"], "id_token") ||
		strings.Contains(params["response_type"], "token")
	if isHybridRT && params["response_mode"] == "" {
		params["response_mode"] = "fragment"
	}
	rm := normaliseResponseMode(params["response_mode"])
	switch rm {
	case "query", "query.jwt", "fragment.jwt", "form_post", "fragment":
		// supported
	default:
		return nil, authErr("invalid_request", "unsupported response_mode: "+params["response_mode"])
	}

	// OIDC Core §3.3.2.11 / §3.2.2.1: nonce is REQUIRED for all flows that
	// return an id_token from the authorization endpoint (hybrid + implicit).
	// Absence of nonce in these flows MUST be rejected with invalid_request.
	if strings.Contains(params["response_type"], "id_token") && params["nonce"] == "" {
		return nil, authErr("invalid_request", "nonce is required when response_type includes id_token")
	}

	span.SetAttributes(
		attribute.Bool("oauth.pkce", pkceChallenge != ""),
		attribute.String("oauth.response_mode", rm),
		attribute.Bool("oauth.public_client", isPublic),
	)
	return &AuthorizeRequest{
		OrgSlug:          orgSlug,
		OrgID:            orgID,
		ClientID:         clientID,
		RedirectURI:      redirectURI,
		Scope:            scope,
		State:            state,
		Nonce:            params["nonce"],
		PKCEChallenge:    pkceChallenge,
		PKCEMethod:       pkceMethod,
		IsPublicClient:   isPublic,
		ResponseMode:     rm,
		ResponseType:     params["response_type"],
		Prompt:           params["prompt"],
		LoginHint:        params["login_hint"],
		Display:          params["display"],
		MaxAge:           parseMaxAge(params["max_age"]),
		DpopJKT:          params["dpop_jkt"],
		SessionIsolation: client.SessionIsolation,
	}, nil
}

// parseMaxAge converts the max_age query parameter string to int.
// Returns 0 if the parameter is absent or invalid (0 = not set).
func parseMaxAge(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// IssueAuthorizationCode generates a cryptographically random authorization code,
// stores its SHA-256 hash in the session store (Redis), and returns the opaque code.
func IssueAuthorizationCode(
	ctx context.Context,
	req *AuthorizeRequest,
	userID string,
	store *session.Store,
	codes *repository.AuthCodeRepository,
) (string, error) {
	ctx, span := tracing.Tracer("clavex/oidc").Start(ctx, "oidc.authorize.issue_code")
	defer span.End()
	span.SetAttributes(
		attribute.String("oauth.client_id", req.ClientID),
		attribute.String("oauth.org_id", req.OrgID),
		attribute.String("oauth.user_id", userID),
		attribute.String("oauth.scope", req.Scope),
	)

	// Generate 32-byte random opaque code
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate authorization code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(raw)
	codeHash := hashString(code)

	orgID, err := uuid.Parse(req.OrgID)
	if err != nil {
		return "", fmt.Errorf("invalid org id: %w", err)
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return "", fmt.Errorf("invalid user id: %w", err)
	}

	expires := time.Now().Add(60 * time.Second)
	if err := codes.Create(ctx, repository.CreateAuthCodeParams{
		OrgID:                orgID,
		ClientID:             req.ClientID,
		UserID:               userUUID,
		CodeHash:             codeHash,
		RedirectURI:          req.RedirectURI,
		Scope:                req.Scope,
		Nonce:                req.Nonce,
		PKCEChallenge:        req.PKCEChallenge,
		PKCEMethod:           req.PKCEMethod,
		AuthTime:             req.AuthTime,
		ExpiresAt:            expires,
		AuthorizationDetails: req.AuthorizationDetails,
		Acr:                  resolveAcr(req.AcrValues),
		ClaimsParam:          req.ClaimsParam,
		ExtraClaims:          req.ExtraClaims,
		DpopJKT:              req.DpopJKT,
	}); err != nil {
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, err.Error())
		return "", fmt.Errorf("store authorization code: %w", err)
	}

	return code, nil
}

// resolveAcr selects the ACR value to include in the ID token.
// When acr_values is requested, we return "0" (password authentication per
// NIST 800-63). The caller must not request acr_values that require MFA or
// higher — those flows are not yet supported.
// Returns "" (omit acr claim) when acr_values was not requested.
func resolveAcr(acrValues string) string {
	if strings.TrimSpace(acrValues) == "" {
		return ""
	}
	return "0" // password-based authentication
}

// VerifyPKCE verifies the code_verifier against the stored challenge.
// Returns an error if verification fails.
func VerifyPKCE(challenge, verifier string) error {
	if challenge == "" {
		return nil // PKCE not used for this code
	}
	if verifier == "" {
		return errors.New("code_verifier is required")
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if computed != challenge {
		return errors.New("code_verifier does not match code_challenge")
	}
	return nil
}

// isAllowedRedirectURI validates a redirect_uri against the client's registered
// list.  Registered entries may be exact URIs or single-subdomain wildcard
// patterns of the form https://*.host.tld/path (only the first label may be *).
func isAllowedRedirectURI(uri string, allowed []string) bool {
	if uri == "" {
		return false
	}
	for _, a := range allowed {
		if a == uri {
			return true
		}
		if strings.Contains(a, "*") && matchWildcardRedirectURI(a, uri) {
			return true
		}
	}
	return false
}

// matchWildcardRedirectURI checks whether uri matches a wildcard pattern.
// Security rules:
//   - Only the first hostname label may be "*" (subdomain wildcard).
//   - The wildcard label in the candidate must not contain dots.
//   - Scheme, path, query and fragment must match exactly.
//
// Example: "https://*.vercel.app/cb" matches "https://my-pr-123.vercel.app/cb"
// but NOT "https://a.b.vercel.app/cb" (nested subdomain).
func matchWildcardRedirectURI(pattern, uri string) bool {
	p, err1 := url.Parse(pattern)
	u, err2 := url.Parse(uri)
	if err1 != nil || err2 != nil {
		return false
	}
	if p.Scheme != u.Scheme || p.Path != u.Path || p.RawQuery != u.RawQuery || p.Fragment != u.Fragment {
		return false
	}
	// Pattern host must be "*.base.tld" — exactly one wildcard in first label.
	pParts := strings.SplitN(p.Host, ".", 2)
	uParts := strings.SplitN(u.Host, ".", 2)
	if len(pParts) != 2 || pParts[0] != "*" {
		return false
	}
	if len(uParts) != 2 {
		return false
	}
	if pParts[1] != uParts[1] {
		return false
	}
	// Candidate subdomain must be a single label (no dots, not empty).
	subdomain := uParts[0]
	if subdomain == "" || strings.Contains(subdomain, ".") {
		return false
	}
	return true
}

// hashString returns the base64url-encoded SHA-256 of s.
// HashToken returns the storage hash of an opaque token (SHA-256, base64url).
// Exposed for callers that need to reference a token by its stored hash.
func HashToken(s string) string { return hashString(s) }

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// normaliseResponseMode maps the requested response_mode to the canonical
// internal value.  Empty / "query" → "query" (plain redirect, default).
// JARM modes: "jwt" → "query.jwt" (FAPI 2.0 default), "query.jwt",
// "fragment.jwt".  "form_post" and "fragment" are also supported.
func normaliseResponseMode(raw string) string {
	switch raw {
	case "", "query":
		return "query"
	case "jwt", "query.jwt":
		return "query.jwt"
	case "fragment.jwt":
		return "fragment.jwt"
	case "form_post":
		return "form_post"
	case "fragment":
		return "fragment"
	default:
		return raw // validation will reject unsupported modes downstream
	}
}

// SanitizeErrorDescription strips characters not permitted in an OAuth
// error_description value per RFC 6749 §4.1.2.1, whose allowed set is
// %x09-0A / %x0D / %x20-21 / %x23-5B / %x5D-7E (i.e. it excludes the double
// quote, backslash, most control characters and all non-ASCII). Disallowed
// characters are replaced with a space so the message stays readable.
func SanitizeErrorDescription(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0x09, r == 0x0A, r == 0x0D,
			r >= 0x20 && r <= 0x21,
			r >= 0x23 && r <= 0x5B,
			r >= 0x5D && r <= 0x7E:
			b.WriteRune(r)
		default:
			b.WriteByte(' ')
		}
	}
	return b.String()
}
