package oidc

import (
	"context"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ValidateJWTBearerGrant verifies a JWT Bearer authorization grant assertion
// per RFC 7523 §2.1/§3 — the generic authorization-grant use of the profile,
// NOT the RFC 7523 §2.2 client-assertion use (see ValidateClientAssertionJWT).
//
// The two differ on one key point: a client assertion authenticates the
// client to itself, so iss MUST equal sub (RFC 7523 §3 item 2 variant for
// client auth). A JWT Bearer grant asserts a subject's identity on behalf of
// a trusted external issuer, so iss (the issuer) and sub (the asserted
// subject) are independent and MUST NOT be compared.
//
// The caller is responsible for:
//   - parsing the assertion's unverified "iss" claim
//   - looking up the trusted-issuer configuration for (org, iss)
//   - resolving that issuer's public keySet (inline JWKS or a fetched jwks_uri)
//
// Required claims (RFC 7523 §3): iss, sub, aud, exp. aud MUST identify the
// token endpoint as an intended audience. nbf/iat, when present, are
// enforced with a clock-skew tolerance by the underlying JWT validation.
//
// This function implements only the generic RFC 7523 profile. It does not
// interpret or require any claims specific to the ID-JAG draft
// (draft-ietf-oauth-identity-assertion-authz-grant) — see
// docs/ID-JAG-ROADMAP.md.
//
// Errors are *TokenError with Code "invalid_grant" (RFC 7523 §3.1).
func ValidateJWTBearerGrant(
	ctx context.Context,
	assertion string,
	keySet jwk.Set,
	tokenEndpoint string,
	jtiCache JTICache,
) (jwt.Token, error) {
	invalid := func(desc string) (jwt.Token, error) {
		return nil, &TokenError{Code: "invalid_grant", Description: desc}
	}

	// ── Step 1: parse unverified to check required claims are present ────────
	unverified, err := jwt.Parse([]byte(assertion),
		jwt.WithVerify(false),
		jwt.WithValidate(false),
	)
	if err != nil {
		return invalid("invalid assertion")
	}
	if unverified.Issuer() == "" {
		return invalid("assertion missing iss (RFC 7523 sec. 3)")
	}
	if unverified.Subject() == "" {
		return invalid("assertion missing sub (RFC 7523 sec. 3)")
	}
	if unverified.Expiration().IsZero() {
		return invalid("assertion missing exp (RFC 7523 sec. 3)")
	}

	// ── Step 2: verify signature + exp/nbf/iat (with clock-skew tolerance) ───
	if _, err = jwt.Parse([]byte(assertion),
		jwt.WithKeySet(keySet,
			jws.WithRequireKid(false),
			jws.WithInferAlgorithmFromKey(true),
		),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	); err != nil {
		return invalid("assertion verification failed: " + strings.ReplaceAll(err.Error(), `"`, ""))
	}

	// ── Step 3: aud MUST identify the token endpoint (RFC 7523 §3 item 3) ────
	audOK := false
	for _, a := range unverified.Audience() {
		if a == tokenEndpoint {
			audOK = true
			break
		}
	}
	if !audOK {
		return invalid("assertion aud must include the token endpoint (RFC 7523 sec. 3)")
	}

	// ── Step 4: JTI replay prevention ─────────────────────────────────────────
	if jtiCache != nil {
		if jti := unverified.JwtID(); jti != "" {
			ttl := time.Until(unverified.Expiration())
			if ttl <= 0 {
				ttl = 5 * time.Minute
			}
			used, cacheErr := jtiCache.CheckAndSet(ctx, "jwtbearer:jti:"+jti, ttl)
			if cacheErr == nil && used {
				return invalid("assertion jti already used")
			}
		}
	}

	return unverified, nil
}
