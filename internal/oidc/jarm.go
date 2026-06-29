package oidc

// Package oidc — JARM: JWT Secured Authorization Response Mode
//
// Implements draft-ietf-oauth-jarm (FAPI 2.0 Message Signing).
// When a client requests response_mode=jwt (or query.jwt / fragment.jwt),
// the authorization response parameters (code, state, iss) are wrapped in
// a signed JWT instead of being added as plain query parameters.
//
// JWT structure (signed PS256, same RSA key as ID tokens):
//   Header: {"alg":"RS256","kid":"<kid>","typ":"JWT"}
//   Claims: {
//     "iss":   "<issuer>",
//     "aud":   "<client_id>",
//     "exp":   <now+60s>,
//     "iat":   <now>,
//     "code":  "<authorization_code>",
//     "state": "<state>",       // present only when state was in the request
//   }
// The client decodes the JWT, verifies the signature against the OP's JWKS,
// and extracts code/state from the JWT claims.
//
// References:
//   - draft-ietf-oauth-jarm-04 (IANA registered response_mode values)
//   - FAPI 2.0 Message Signing §5 (mandates response_mode=jwt for protected resources)
//   - OpenID FAPI 2.0 Implementer's Draft 2 §7.1

import (
	"fmt"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
) // JARMResponseTTL is the lifetime of a JARM JWT.
// JARM §4.4: SHOULD be short — 60 seconds is the typical recommendation.
const JARMResponseTTL = 60 * time.Second

// BuildJARMResponse builds a signed JARM JWT containing the authorization
// response parameters.  Returns the compact-serialised JWT.
func BuildJARMResponse(ks Signer, issuer, clientID, code, state string) (string, error) {	now := time.Now().UTC()

	b := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{clientID}).
		IssuedAt(now).
		Expiration(now.Add(JARMResponseTTL)).
		Claim("code", code)

	if state != "" {
		b = b.Claim("state", state)
	}

	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("jarm: build token: %w", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.AlgorithmKey, jwa.PS256)
	_ = hdrs.Set(jws.KeyIDKey, ks.KID())
	_ = hdrs.Set("typ", "JWT")

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, ks.CryptoSigner(), jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("jarm: sign: %w", err)
	}
	return string(signed), nil
}

// BuildJARMRedirectURL constructs the redirect URL for a JARM response.
//
// Per draft-ietf-oauth-jarm §4.3, "jwt" is equivalent to "query.jwt"
// for response_type=code (already normalised by normaliseResponseMode).
func BuildJARMRedirectURL(jarmJWT, redirectURI, mode string) (string, error) {
	base, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("jarm: parse redirect_uri: %w", err)
	}

	switch mode {
	case "fragment.jwt":
		frag := url.Values{"response": {jarmJWT}}
		base.Fragment = frag.Encode()
	default: // "query.jwt" (and legacy "jwt")
		q := base.Query()
		q.Set("response", jarmJWT)
		base.RawQuery = q.Encode()
	}
	return base.String(), nil
}

// IsJARMMode reports whether the response_mode requires a JARM JWT response.
func IsJARMMode(responseMode string) bool {
	switch responseMode {
	case "jwt", "query.jwt", "fragment.jwt":
		return true
	}
	return false
}

// BuildJARMErrorResponse builds a signed JARM JWT carrying an OAuth2 error
// response (JARM §4.2 / FAPI 2.0 Message Signing §5.4.2).
// Per the spec, error responses MUST also be wrapped in the JARM JWT when
// the client requested a JWT response mode.
//
//	Claims: {"iss","aud","exp","iat","error","error_description"(opt),"state"(opt)}
func BuildJARMErrorResponse(ks Signer, issuer, clientID, errorCode, errorDescription, state string) (string, error) {
	now := time.Now().UTC()

	b := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{clientID}).
		IssuedAt(now).
		Expiration(now.Add(JARMResponseTTL)).
		Claim("error", errorCode)

	if errorDescription != "" {
		b = b.Claim("error_description", errorDescription)
	}
	if state != "" {
		b = b.Claim("state", state)
	}

	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("jarm: build error token: %w", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.AlgorithmKey, jwa.PS256)
	_ = hdrs.Set(jws.KeyIDKey, ks.KID())
	_ = hdrs.Set("typ", "JWT")

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.PS256, ks.CryptoSigner(), jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("jarm: sign error token: %w", err)
	}
	return string(signed), nil
}
