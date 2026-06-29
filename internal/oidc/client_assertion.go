package oidc

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// JTICache is an interface for JTI replay prevention with SetNX semantics.
// CheckAndSet atomically marks a JTI as used. Returns (true, nil) if the JTI
// was already present (replay detected), (false, nil) if it was newly stored.
// An error means the store was unavailable — callers should decide whether to
// fail open or closed; the handler fails closed (rejects the request).
type JTICache interface {
	CheckAndSet(ctx context.Context, key string, ttl time.Duration) (alreadyUsed bool, err error)
}

// ValidateClientAssertionJWT verifies a private_key_jwt client assertion per
// RFC 7523 §2.2 and returns the authenticated clientID.
//
// The caller is responsible for:
//   - resolving the client's public keySet from DB / jwks_uri
//   - performing a DB lookup for the returned clientID
//   - optionally passing a non-nil jtiCache to prevent replay
//
// Errors are *TokenError with Code "invalid_client".
func ValidateClientAssertionJWT(
	ctx context.Context,
	assertion string,
	keySet jwk.Set,
	tokenEndpoint string,
	issuer string,
	jtiCache JTICache,
	extraAudiences ...string,
) (clientID string, err error) {
	invalid := func(desc string) (string, error) {
		return "", &TokenError{Code: "invalid_client", Description: desc}
	}

	// ── Step 1: parse unverified to extract clientID from iss/sub ────────────
	unverified, err := jwt.Parse([]byte(assertion),
		jwt.WithVerify(false),
		jwt.WithValidate(false),
	)
	if err != nil {
		return invalid("invalid client_assertion")
	}

	clientID = unverified.Issuer()
	if clientID == "" {
		clientID = unverified.Subject()
	}
	if clientID == "" {
		return invalid("client_assertion missing iss/sub")
	}
	// RFC 7523 §3: both iss and sub MUST be present and MUST equal the client_id.
	if sub := unverified.Subject(); sub == "" || sub != clientID {
		return invalid("client_assertion sub must be present and must match iss (RFC 7523 sec. 3)")
	}

	// ── Step 2: verify signature + exp + iat ─────────────────────────────────
	// Use WithRequireKid(false) so the function works when clients omit kid
	// (RFC 7523 does not require it). Use WithInferAlgorithmFromKey(true) so
	// keys without an explicit "alg" field still work (common in JWKS served
	// by older IdPs). jwt.Parse rejects alg=none by default with a key set.
	if _, err = jwt.Parse([]byte(assertion),
		jwt.WithKeySet(keySet,
			jws.WithRequireKid(false),
			jws.WithInferAlgorithmFromKey(true),
		),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	); err != nil {
		return invalid("client_assertion verification failed: " + strings.ReplaceAll(err.Error(), `"`, ""))
	}

	// ── Step 3: validate aud contains token endpoint, issuer, or an extra accepted URL ──
	validAuds := append([]string{tokenEndpoint, issuer}, extraAudiences...)
	audOK := false
outer:
	for _, a := range unverified.Audience() {
		for _, v := range validAuds {
			if a == v {
				audOK = true
				break outer
			}
		}
	}
	if !audOK {
		return invalid("client_assertion aud must include token endpoint")
	}

	// ── Step 4: JTI replay prevention (RFC 7523 §3 item 9) ───────────────────
	if jtiCache != nil {
		if jti := unverified.JwtID(); jti != "" {
			ttl := time.Until(unverified.Expiration())
			if ttl <= 0 {
				ttl = 5 * time.Minute
			}
			used, cacheErr := jtiCache.CheckAndSet(ctx, "ca:jti:"+jti, ttl)
			if cacheErr == nil && used {
				return invalid("client_assertion jti already used")
			}
		}
	}

	return clientID, nil
}

// ValidateAttestationAssertionJWT verifies an OAuth 2.0 Attestation-Based
// Client Authentication assertion (draft-ietf-oauth-attestation-based-client-auth)
// passed as client_assertion when client_assertion_type is
// urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation.
//
// The assertion format is "<attest_jwt>~<pop_jwt>" (tilde-separated).
//
//   - attestJWT is verified against clientKeySet (the client's registered JWKS).
//     In the self-attestation model the client signs its own attestation JWT, so
//     clientKeySet is the client's public JWKS stored at registration.
//   - cnf.jwk is extracted from the verified attestation JWT.
//   - popJWT is verified against the cnf.jwk key.  Full iss/sub/aud/jti checks
//     are delegated to ValidateClientAssertionJWT.
//
// Returns a *TokenError with Code "invalid_client" on any failure.
// ValidateAttestationAssertionJWT validates an OAuth2-ATCA assertion and
// returns the JWK Thumbprint (S256, base64url) of the client instance key
// (cnf.jwk from the attestation JWT) on success.
func ValidateAttestationAssertionJWT(
	ctx context.Context,
	clientAssertion string, // "<attest_jwt>~<pop_jwt>"
	clientKeySet jwk.Set,   // client's registered JWKS (verifies attest_jwt)
	tokenEndpoint string,
	issuer string,
	expectedClientID string,
	jtiCache JTICache,
	extraAudiences ...string,
) (string, error) {
	invalid := func(desc string) error {
		return &TokenError{Code: "invalid_client", Description: desc}
	}

	// ── Step 1: split "<attest_jwt>~<pop_jwt>" ───────────────────────────────
	parts := strings.SplitN(clientAssertion, "~", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", invalid("client_assertion must be <attest_jwt>~<pop_jwt> (tilde-separated)")
	}
	attestJWT, popJWT := parts[0], parts[1]

	// ── Step 2: parse attestation JWT unverified to get sub (= client_id) ────
	unverifiedAttest, err := jwt.Parse([]byte(attestJWT),
		jwt.WithVerify(false),
		jwt.WithValidate(false),
	)
	if err != nil {
		return "", invalid("attestation JWT parse error")
	}
	clientID := unverifiedAttest.Subject()
	if clientID == "" {
		return "", invalid("attestation JWT missing sub (client_id)")
	}
	if clientID != expectedClientID {
		return "", invalid("attestation JWT sub does not match client_id")
	}

	// ── Step 3: verify attestation JWT signature + time claims ───────────────
	if _, err = jwt.Parse([]byte(attestJWT),
		jwt.WithKeySet(clientKeySet,
			jws.WithRequireKid(false),
			jws.WithInferAlgorithmFromKey(true),
		),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	); err != nil {
		return "", invalid("attestation JWT verification failed: " + strings.ReplaceAll(err.Error(), `"`, ""))
	}

	// ── Step 4: extract cnf.jwk from attestation JWT ─────────────────────────
	cnfRaw, ok := unverifiedAttest.Get("cnf")
	if !ok {
		return "", invalid("attestation JWT missing cnf claim")
	}
	cnfBytes, marshalErr := json.Marshal(cnfRaw)
	if marshalErr != nil {
		return "", invalid("attestation JWT cnf claim unserializable")
	}
	var cnfMap struct {
		JWK json.RawMessage `json:"jwk"`
	}
	if jsonErr := json.Unmarshal(cnfBytes, &cnfMap); jsonErr != nil || len(cnfMap.JWK) == 0 {
		return "", invalid("attestation JWT cnf.jwk missing or invalid")
	}
	popKeySet, parseErr := jwk.Parse(cnfMap.JWK)
	if parseErr != nil {
		return "", invalid("attestation JWT cnf.jwk parse error: " + parseErr.Error())
	}

	// ── Step 5: validate PoP JWT ─────────────────────────────────────────────
	// The attestation PoP JWT (oauth-client-attestation-pop+jwt) differs from
	// private_key_jwt (RFC 7523) in one important way: it does NOT require a
	// "sub" claim (draft-ietf-oauth-attestation-based-client-auth-07 §5.2).
	// We therefore validate it in-line rather than delegating to
	// ValidateClientAssertionJWT which enforces iss==sub.
	if err = validateAttestationPopJWT(ctx, popJWT, popKeySet, tokenEndpoint, issuer, expectedClientID, jtiCache, extraAudiences...); err != nil {
		return "", err
	}

	// ── Step 6: compute JWK Thumbprint of the client instance key ────────────
	// OAuth2-ATCA §10.3: bind the refresh token to this key so rotation
	// requests from a different instance key can be rejected.
	popKey, ok := popKeySet.Key(0)
	if !ok {
		return "", invalid("attestation JWT cnf.jwk: empty key set")
	}
	instanceJKT, tpErr := thumbprint(popKey)
	if tpErr != nil {
		return "", invalid("attestation JWT cnf.jwk thumbprint: " + tpErr.Error())
	}

	return instanceJKT, nil
}

// validateAttestationPopJWT validates the Client Attestation PoP JWT per
// draft-ietf-oauth-attestation-based-client-auth-07 §5.2.
// Required claims: iss (== client_id), aud (includes tokenEndpoint or issuer), exp, jti.
// Unlike private_key_jwt (RFC 7523), no "sub" claim is required.
func validateAttestationPopJWT(
	ctx context.Context,
	popJWT string,
	popKeySet jwk.Set,
	tokenEndpoint string,
	issuer string,
	expectedClientID string,
	jtiCache JTICache,
	extraAudiences ...string,
) error {
	invalid := func(desc string) error {
		return &TokenError{Code: "invalid_client", Description: "PoP JWT: " + desc}
	}

	// Parse unverified first to read claims.
	unverified, err := jwt.Parse([]byte(popJWT),
		jwt.WithVerify(false),
		jwt.WithValidate(false),
	)
	if err != nil {
		return invalid("parse error")
	}

	// iss MUST equal the client_id.
	if iss := unverified.Issuer(); iss == "" {
		return invalid("missing iss")
	} else if iss != expectedClientID {
		return invalid("iss does not match client_id")
	}

	// Verify signature + exp.
	if _, err = jwt.Parse([]byte(popJWT),
		jwt.WithKeySet(popKeySet,
			jws.WithRequireKid(false),
			jws.WithInferAlgorithmFromKey(true),
		),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	); err != nil {
		return invalid("verification failed: " + strings.ReplaceAll(err.Error(), `"`, ""))
	}

	// aud MUST include the token endpoint, the issuer, or an accepted extra audience.
	validAuds := append([]string{tokenEndpoint, issuer}, extraAudiences...)
	audOK := false
outer:
	for _, a := range unverified.Audience() {
		for _, v := range validAuds {
			if a == v {
				audOK = true
				break outer
			}
		}
	}
	if !audOK {
		return invalid("aud must include token endpoint or issuer")
	}

	// jti replay prevention.
	if jtiCache != nil {
		if jti := unverified.JwtID(); jti != "" {
			ttl := time.Until(unverified.Expiration())
			if ttl <= 0 {
				ttl = 5 * time.Minute
			}
			used, cacheErr := jtiCache.CheckAndSet(ctx, "pop:jti:"+jti, ttl)
			if cacheErr == nil && used {
				return invalid("jti already used")
			}
		}
	}

	return nil
}
