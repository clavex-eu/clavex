package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// errJAR is returned when a request object JWT is malformed or invalid.
var errJAR = errors.New("invalid_request_object")

// ErrFAPIJAR is returned when a request object violates FAPI 2.0-specific
// requirements (e.g. lifetime > 60 minutes). These are distinct from core JAR
// format errors: PAR maps them to "invalid_request" rather than
// "invalid_request_object" per the conformance suite expectations.
var ErrFAPIJAR = errors.New("invalid_request_object")

// JWEDecrypter decrypts a compact JWE request object to its inner JWT plaintext.
// *EncKeySet satisfies it. Supplied to ParseJAR via WithJWEDecrypter so an
// encrypted request object (RFC 9101 §6.2) is unwrapped before signature
// verification.
type JWEDecrypter interface {
	DecryptJWE(compact string) (string, error)
}

// jarOptions collects the optional behaviours of ParseJAR / FetchRequestURI.
type jarOptions struct {
	// strict makes the iss and aud claims mandatory (FAPI-CIBA CIBA-13).
	strict bool
	// decrypter, when set, is used to unwrap an encrypted request object before
	// signature verification.
	decrypter JWEDecrypter
}

// JAROption configures ParseJAR / FetchRequestURI.
type JAROption func(*jarOptions)

// WithStrictIssAud makes the iss and aud claims (plus exp/nbf/iat/jti) mandatory.
// RFC 9101 treats iss/aud as optional, but FAPI-CIBA (CIBA-13) requires them.
func WithStrictIssAud() JAROption { return func(o *jarOptions) { o.strict = true } }

// WithJWEDecrypter enables decryption of an encrypted (JWE) request object using
// the OP's request-object encryption key before signature verification.
func WithJWEDecrypter(d JWEDecrypter) JAROption {
	return func(o *jarOptions) { o.decrypter = d }
}

func collectJAROptions(opts []JAROption) jarOptions {
	var o jarOptions
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// IsJWE reports whether raw is a compact JWE (five base64url segments) rather
// than a compact JWS (three segments) or unsecured JWT (two segments).
func IsJWE(raw string) bool {
	return strings.Count(raw, ".") == 4
}

// ParseJAR parses, verifies, and extracts claims from a JWT Authorization
// Request object (RFC 9101 §3).
//
// Verification strategy:
//   - alg=none (unsecured): accepted for standard OIDC clients (those without
//     a request_object_signing_alg configured). FAPI clients (RequestObjectSigningAlg
//     != "") always require a signed request object — alg=none is rejected.
//   - Signed JWT: the client's public key set is resolved as follows
//     (inline JWKS takes precedence over jwks_uri, same as private_key_jwt auth):
//     1. client.JWKS  — inline JSON Web Key Set stored at registration time
//     2. client.JWKSUri — remote JWKS URI fetched at verification time
//     Symmetric HMAC is not supported (secret is stored as bcrypt hash).
//
// Returns a map of all claims extracted from the JWT payload. The caller
// should merge these claims on top of any query-string parameters, per
// RFC 9101 §6.1: "…claims in the JWT take precedence over those in the
// request query string".
// Options (default none): WithStrictIssAud makes iss/aud mandatory (FAPI-CIBA
// CIBA-13); WithJWEDecrypter unwraps an encrypted (JWE) request object before
// signature verification (RFC 9101 §6.2, OpenID Federation §12).
func ParseJAR(ctx context.Context, requestJWT string, client *models.OIDCClient, issuer string, opts ...JAROption) (map[string]string, error) {
	o := collectJAROptions(opts)
	mustHaveIssAud := o.strict

	// RFC 9101 §6.2: an encrypted request object is a JWE wrapping the (signed
	// or unsecured) request-object JWT. Decrypt with the OP's enc key, then
	// process the inner JWT exactly as a plaintext request object.
	if IsJWE(requestJWT) {
		if o.decrypter == nil {
			return nil, fmt.Errorf("%w: encrypted request objects are not supported", errJAR)
		}
		inner, derr := o.decrypter.DecryptJWE(requestJWT)
		if derr != nil {
			return nil, fmt.Errorf("%w: %v", errJAR, derr)
		}
		requestJWT = strings.TrimSpace(inner)
	}

	if isUnsecuredJWT(requestJWT) {
		// FAPI clients require a signed request object (FAPI 2.0 §5.3.1).
		if client.RequestObjectSigningAlg != "" {
			return nil, fmt.Errorf("%w: request object must be signed - alg=none is not permitted (RFC 7518 sec. 3.6, FAPI 2.0 sec. 5.3.1)", ErrFAPIJAR)
		}
		// Standard OIDC client: accept unsigned request object per RFC 9101.
		return parseUnsecuredJAR(requestJWT)
	}

	var token jwt.Token
	// Signed JWT: resolve key set — inline JWKS takes precedence over jwks_uri.
	keySet, err := resolveClientKeySet(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errJAR, err)
	}

	// Parse and verify the signed JWT.
	// Use WithRequireKid(false) so request objects without a kid header
	// (RFC 9101 does not mandate kid) still verify against all keys in the
	// set. Use WithInferAlgorithmFromKey(true) so keys without an explicit
	// "alg" field still work (common in JWKS from dynamic clients).
	var parseErr error
	token, parseErr = jwt.Parse(
		[]byte(requestJWT),
		jwt.WithKeySet(keySet,
			jws.WithRequireKid(false),
			jws.WithInferAlgorithmFromKey(true),
		),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if parseErr != nil {
		return nil, fmt.Errorf("%w: %v", errJAR, parseErr)
	}

	// Verify optional RFC 9101 claims — both iss and aud are optional per RFC 9101 §4:
	// "if present, MUST" semantics apply.
	// iss: OPTIONAL per RFC 9101 — if present, MUST be the client_id. FAPI-CIBA
	// (CIBA-13) makes it mandatory.
	if iss, ok := token.Get("iss"); ok {
		// For federation clients the iss value check is deferred to the
		// consolidated §12.1.1.1 block below, which reports it as a redirectable
		// error instead of a non-redirectable error page.
		if fmt.Sprint(iss) != client.ClientID && !isFederationClient(client) {
			return nil, fmt.Errorf("%w: iss claim must equal client_id", errJAR)
		}
	} else if mustHaveIssAud {
		return nil, fmt.Errorf("%w: iss claim is required in the request object", errJAR)
	}
	// aud: OPTIONAL per RFC 9101 §4 — "if present, MUST" semantics apply.
	// When aud is present it MUST contain the authorization server's issuer URL.
	// A bad aud (e.g. pointing at a different AS) MUST be rejected to prevent
	// replay of request objects across authorization servers.
	if aud := token.Audience(); len(aud) == 0 {
		// FAPI-CIBA (CIBA-13): the signed authentication request MUST contain aud.
		if mustHaveIssAud {
			return nil, fmt.Errorf("%w: aud claim is required in the request object", errJAR)
		}
	} else if issuer != "" {
		audOK := false
		for _, a := range aud {
			if a == issuer {
				audOK = true
				break
			}
		}
		if !audOK && !isFederationClient(client) {
			// Federation: deferred to the §12.1.1.1 block below as a redirectable error.
			return nil, fmt.Errorf("%w: aud claim does not include the authorization server issuer", errJAR)
		}
	}

	// FAPI 2.0 §5.3.3/§5.3.4: for signed request objects exp and nbf are
	// required, and the lifetime (exp − reference) must not exceed 60 minutes.
	// These checks are FAPI-specific and only apply to clients with
	// request_object_signing_alg configured. OpenID Federation RPs also sign
	// their request objects but follow RFC 9101 (nbf/lifetime optional), so
	// federation-registered clients are exempt from the FAPI timing rules.
	if client.RequestObjectSigningAlg != "" && !isFederationClient(client) {
		exp := token.Expiration()
		if exp.IsZero() {
			return nil, fmt.Errorf("%w: exp claim is required in request object", errJAR)
		}
		if token.NotBefore().IsZero() {
			return nil, fmt.Errorf("%w: nbf claim is required in request object (FAPI 2.0 §5.3.4)", errJAR)
		}
		if time.Since(token.NotBefore()) > 60*time.Minute+30*time.Second {
			return nil, fmt.Errorf("%w: request object nbf is more than 60 minutes in the past (FAPI 2.0 §5.3.3)", ErrFAPIJAR)
		}
		lifeBase := token.NotBefore()
		if iat := token.IssuedAt(); !iat.IsZero() {
			lifeBase = iat
		}
		if exp.Sub(lifeBase) > 60*time.Minute {
			return nil, fmt.Errorf("%w: request object lifetime must not exceed 60 minutes (FAPI 2.0 §5.3.3)", ErrFAPIJAR)
		}
	}

	// FAPI-CIBA (CIBA-13) requires the signed authentication request to carry
	// exp, nbf, iat and jti in addition to iss/aud (checked above). RFC 9101
	// leaves these optional, so they are only enforced for the CIBA path.
	if mustHaveIssAud {
		if token.Expiration().IsZero() {
			return nil, fmt.Errorf("%w: exp claim is required in the request object", errJAR)
		}
		if token.NotBefore().IsZero() {
			return nil, fmt.Errorf("%w: nbf claim is required in the request object", errJAR)
		}
		if token.IssuedAt().IsZero() {
			return nil, fmt.Errorf("%w: iat claim is required in the request object", errJAR)
		}
		if token.JwtID() == "" {
			return nil, fmt.Errorf("%w: jti claim is required in the request object", errJAR)
		}
	}

	// Extract all private claims as strings.
	params := make(map[string]string)
	for iter := token.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		k := fmt.Sprint(pair.Key)
		// Skip standard JWT meta-claims that are not authorization params.
		switch k {
		case "iss", "aud", "exp", "nbf", "iat", "jti":
			continue
		}
		params[k] = fmt.Sprint(pair.Value)
	}

	// OpenID Federation §12.1.1.1 constrains the signed authorization request
	// object: iss, aud, exp and jti are required, iss MUST equal the client_id,
	// and aud MUST include the authorization server issuer. Any violation is
	// recorded in reserved params so ValidateAuthorizeRequest — which has already
	// validated the redirect_uri — can return a redirectable
	// invalid_request_object error to the RP instead of a non-redirectable error
	// page. Descriptions are kept within the RFC 6749 §4.1.2.1 error_description
	// charset (plain ASCII, no quotes/backslash/non-ASCII).
	if isFederationClient(client) {
		var desc string
		switch {
		case token.Issuer() == "":
			desc = "request object is missing the required iss claim (OpenID Federation 12.1.1.1)"
		case token.Issuer() != client.ClientID:
			desc = "request object iss claim must equal the client_id (OpenID Federation 12.1.1.1)"
		case len(token.Audience()) == 0:
			desc = "request object is missing the required aud claim (OpenID Federation 12.1.1.1)"
		case issuer != "" && !audienceContains(token.Audience(), issuer):
			desc = "request object aud claim must include the authorization server issuer (OpenID Federation 12.1.1.1)"
		case token.Expiration().IsZero():
			desc = "request object is missing the required exp claim (OpenID Federation 12.1.1.1)"
		case token.JwtID() == "":
			desc = "request object is missing the required jti claim (OpenID Federation 12.1.1.1)"
		}
		if desc != "" {
			params[JARPolicyErrorKey] = "invalid_request_object"
			params[JARPolicyDescKey] = desc
		} else {
			// Surface jti and exp so the caller (which has the replay store) can
			// enforce jti single-use per OpenID Federation §12.1.1.1.
			params[JARJtiKey] = token.JwtID()
			if exp := token.Expiration(); !exp.IsZero() {
				params[JARExpKey] = strconv.FormatInt(exp.Unix(), 10)
			}
		}
	}
	return params, nil
}

// audienceContains reports whether aud includes target.
func audienceContains(aud []string, target string) bool {
	for _, a := range aud {
		if a == target {
			return true
		}
	}
	return false
}

// Reserved params keys used to carry an OpenID Federation request-object policy
// violation detected during JAR parsing through to ValidateAuthorizeRequest,
// where it can be turned into a redirectable authorization error.
const (
	JARPolicyErrorKey = "__jar_policy_error"
	JARPolicyDescKey  = "__jar_policy_desc"
	// JARJtiKey / JARExpKey carry the request object's jti and exp (unix seconds)
	// to the caller so it can enforce jti single-use against a replay store.
	JARJtiKey = "__jar_jti"
	JARExpKey = "__jar_exp"
)

// isFederationClient reports whether the client was registered through OpenID
// Federation automatic client registration, identified by the
// federation_entity_id marker stored in its metadata. Such clients follow RFC
// 9101 request-object semantics rather than the stricter FAPI 2.0 timing rules.
func isFederationClient(client *models.OIDCClient) bool {
	if client == nil || client.Metadata == nil {
		return false
	}
	v, ok := client.Metadata["federation_entity_id"]
	if !ok {
		return false
	}
	s, _ := v.(string)
	return s != ""
}

// jarHTTPClient is SSRF-guarded: request_uri and jwks_uri come from OIDC client
// requests, so it refuses to dial private/loopback targets unless the operator
// opts in via http.allow_private_outbound_targets.
var jarHTTPClient = safehttp.Client(10*time.Second, false)

// SetJARHTTPClient overrides the JAR/JWKS HTTP client (SSRF-relaxed opt-in).
func SetJARHTTPClient(hc *http.Client) {
	if hc != nil {
		jarHTTPClient = hc
	}
}

// FetchRequestURI fetches the Request Object JWT at requestURI (RFC 9101 §5)
// and parses it with ParseJAR.  The URI must use https (or http for local test
// suites).  The fragment component, if present, is stripped by the HTTP client
// and not sent to the remote server.
func FetchRequestURI(ctx context.Context, requestURI string, client *models.OIDCClient, issuer string, opts ...JAROption) (map[string]string, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, requestURI, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid request_uri: %v", errJAR, err)
	}

	resp, err := jarHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: could not fetch request_uri: %v", errJAR, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: request_uri returned HTTP %d", errJAR, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("%w: could not read request_uri body: %v", errJAR, err)
	}

	return ParseJAR(ctx, strings.TrimSpace(string(body)), client, issuer, opts...)
}

// IsJARError returns true if err originated from JAR processing so callers
// can map it to the correct OAuth2 error code.
func IsJARError(err error) bool {
	return errors.Is(err, errJAR)
}

// parseUnsecuredJAR decodes a JWT with alg=none (no signature verification)
// and extracts its authorization request parameters. The standard JWT meta-claims
// (iss, aud, exp, nbf, iat, jti) are stripped from the result.
// Used for standard OIDC clients that send unsigned request objects (RFC 9101).
func parseUnsecuredJAR(raw string) (map[string]string, error) {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: malformed unsigned JWT", errJAR)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: cannot decode unsigned JWT payload: %v", errJAR, err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: cannot parse unsigned JWT payload: %v", errJAR, err)
	}
	params := make(map[string]string, len(claims))
	for k, v := range claims {
		switch k {
		case "iss", "aud", "exp", "nbf", "iat", "jti":
			continue
		}
		params[k] = fmt.Sprint(v)
	}
	return params, nil
}

// isUnsecuredJWT returns true if the JWT header declares alg=none.
func isUnsecuredJWT(raw string) bool {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) < 2 {
		return false
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return false
	}
	return strings.EqualFold(hdr.Alg, "none")
}

// resolveClientKeySet returns the key set to use for verifying a client's signed JWT
// (either a JAR request object or a client assertion).
// Resolution order:
//  1. Inline JWKS stored at registration time (client.JWKS) — no network call.
//  2. Remote jwks_uri fetched on demand (client.JWKSUri).
func resolveClientKeySet(ctx context.Context, client *models.OIDCClient) (jwk.Set, error) {
	if client.JWKS != nil && len(*client.JWKS) > 2 { // "{}" is 2 bytes
		ks, err := jwk.Parse(*client.JWKS)
		if err != nil {
			return nil, fmt.Errorf("invalid inline JWKS: %v", err)
		}
		return ks, nil
	}
	if client.JWKSUri != nil && *client.JWKSUri != "" {
		fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		ks, err := fetchJWKS(fetchCtx, *client.JWKSUri)
		if err != nil {
			return nil, fmt.Errorf("could not fetch client jwks_uri: %v", err)
		}
		return ks, nil
	}
	return nil, fmt.Errorf("client has no JWKS configured (set jwks or jwks_uri at registration)")
}

// fetchJWKS retrieves a JWKS from the given URI.
func fetchJWKS(ctx context.Context, uri string) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := jarHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks_uri returned HTTP %d", resp.StatusCode)
	}
	return jwk.ParseReader(resp.Body)
}
