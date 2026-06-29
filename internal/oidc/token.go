package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TokenConfig holds the parameters needed to issue tokens.
type TokenConfig struct {
	Keys            Signer
	Issuer          string // per-tenant issuer URL, e.g. https://clavex.eu/inwit
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	IDTokenTTL      time.Duration
}

// UserClaims groups the user attributes embedded into tokens.
type UserClaims struct {
	UserID    string
	OrgID     string
	Email     string
	FirstName string
	LastName  string
	Roles     []string
	Groups    []string
	// ExtraClaims are additional claims produced by protocol mappers.
	// Keys must not shadow reserved claims (sub, iss, aud, exp, iat, jti, scope).
	ExtraClaims   map[string]any
	EmailVerified bool   // emitted as email_verified in ID token
	AuthTime      int64  // Unix timestamp of user authentication; 0 = not set
	AtHash        string // at_hash for ID token (left half of SHA-256 of access token)
	// CHash is the code_hash for hybrid flow ID tokens (OIDC Core §3.3.2.11).
	// Computed as base64url(left half of SHA-256 of the authorization code).
	// Set only when response_type includes id_token in the authorization response.
	CHash         string
	// AuthorizationDetails carries the RFC 9396 RAR array to be embedded in the
	// access token as the "authorization_details" claim (RFC 9396 §9).
	AuthorizationDetails []map[string]any
	// Acr is the Authentication Context Class Reference value achieved (OIDC Core §2).
	// Empty string means the claim is omitted from the ID token.
	Acr string
	// ReqClaims is the raw JSON value of the OIDC claims request parameter
	// (OIDC Core §5.5). When non-empty, included in the access token as
	// req_claims so BuildUserInfo can return explicitly requested claims.
	ReqClaims string
}

// TokenSet is the response returned by the token endpoint.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	// AuthorizationDetails is included in the token response per RFC 9396 §9.
	AuthorizationDetails []map[string]any `json:"authorization_details,omitempty"`
}

// IssueAccessToken creates and signs a JWT access token (RS256).
// For client_credentials grants, user may be nil — sub is then the client_id.
// dpop is optional: when non-nil the token gains a cnf.jkt claim and
// token_type is set to "DPoP" in the returned TokenSet.
// mtls is optional: when non-nil the token gains a cnf.x5t#S256 claim for
// RFC 8705 certificate-bound access tokens.
func (tc *TokenConfig) IssueAccessToken(clientID, scope string, user *UserClaims, dpop *DPoPKey, mtls *MTLSCert) (string, string, error) {
	now := time.Now()
	jti := uuid.NewString()

	b := jwt.NewBuilder().
		JwtID(jti).
		Issuer(tc.Issuer).
		Audience([]string{clientID}).
		IssuedAt(now).
		Expiration(now.Add(tc.AccessTokenTTL)).
		Claim("scope", scope)

	if user != nil {
		groups := user.Groups
		if groups == nil {
			groups = []string{}
		}
		roles := user.Roles
		if roles == nil {
			roles = []string{}
		}
		b = b.
			Subject(user.UserID).
			Claim("org_id", user.OrgID).
			Claim("email", user.Email).
			// Keycloak-compatible realm_access claim consumed by downstream services
			Claim("realm_access", map[string]any{"roles": roles}).
			Claim("groups", groups)
		// Apply extra claims from protocol mappers
		for k, v := range user.ExtraClaims {
			b = b.Claim(k, v)
		}
		// RFC 9396: include authorization_details in the access token if present.
		if len(user.AuthorizationDetails) > 0 {
			b = b.Claim("authorization_details", user.AuthorizationDetails)
		}
		// OIDC Core §5.5: carry claims parameter into access token for userinfo.
		if user.ReqClaims != "" {
			b = b.Claim("req_claims", user.ReqClaims)
		}
	} else {
		// M2M: subject is the client itself
		b = b.Subject(clientID).Claim("client_id", clientID)
	}

	// cnf claim: binds the token to a key or certificate (RFC 9449 / RFC 8705).
	// Both DPoP and mTLS bindings may coexist in the same token.
	cnf := map[string]any{}
	if dpop != nil {
		// DPoP (RFC 9449 §6): bind to the client's asymmetric public key.
		cnf["jkt"] = dpop.JKT
	}
	if mtls != nil {
		// mTLS (RFC 8705 §3.1): bind to the SHA-256 thumbprint of the client cert.
		cnf["x5t#S256"] = mtls.X5TS256
	}
	if len(cnf) > 0 {
		b = b.Claim("cnf", cnf)
	}

	tok, err := b.Build()
	if err != nil {
		return "", "", fmt.Errorf("build access token: %w", err)
	}

	signed, err := signToken(tok, tc.Keys)
	if err != nil {
		return "", "", err
	}
	return signed, jti, nil
}

// IssueIDToken creates and signs an OIDC ID token.
// The signing algorithm defaults to PS256 (server default). Pass an explicit
// jwa.SignatureAlgorithm as the optional fourth argument to override — used
// when the client registered with id_token_signed_response_alg=RS256 etc.
//
// Per OIDC Core §5.4: for response_type=code, profile/email claims are
// delivered via the UserInfo endpoint, not the ID token. The ID token
// contains only authentication event claims (sub, iss, aud, exp, iat,
// nonce, auth_time, at_hash). Protocol mapper extra claims are still
// included as they may carry custom auth-context data.
func (tc *TokenConfig) IssueIDToken(clientID, nonce string, user UserClaims, alg ...jwa.SignatureAlgorithm) (string, error) {
	now := time.Now()

	b := jwt.NewBuilder().
		JwtID(uuid.NewString()).
		Issuer(tc.Issuer).
		Subject(user.UserID).
		Audience([]string{clientID}).
		IssuedAt(now).
		Expiration(now.Add(tc.IDTokenTTL))

	if nonce != "" {
		b = b.Claim("nonce", nonce)
	}
	if user.AuthTime > 0 {
		b = b.Claim("auth_time", user.AuthTime) // OIDC Core §2
	}
	if user.Acr != "" {
		b = b.Claim("acr", user.Acr) // OIDC Core §2
	}
	if user.AtHash != "" {
		b = b.Claim("at_hash", user.AtHash) // OIDC Core §3.1.3.6
	}
	if user.CHash != "" {
		b = b.Claim("c_hash", user.CHash) // OIDC Core §3.3.2.11
	}
	// Protocol mapper extra claims (custom auth-context, roles, etc.)
	for k, v := range user.ExtraClaims {
		b = b.Claim(k, v)
	}

	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("build id token: %w", err)
	}
	sigAlg := jwa.PS256 // server default
	if len(alg) > 0 {
		sigAlg = alg[0]
	}
	return signTokenWithAlg(tok, tc.Keys, sigAlg)
}

// VerifyAccessToken parses and validates a signed access token.
// Returns the parsed token, its JTI, and its expiry.
func (tc *TokenConfig) VerifyAccessToken(raw string) (jwt.Token, string, time.Time, error) {
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKey(jwa.PS256, tc.Keys.PublicKey()),
		jwt.WithIssuer(tc.Issuer),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("verify access token: %w", err)
	}
	jti := tok.JwtID()
	exp := tok.Expiration()
	return tok, jti, exp, nil
}

// ParseTrustedIDToken verifies an ID token that this AS previously issued
// (signature + issuer), returning the parsed token. Used to authenticate an
// id_token_hint before trusting its `sub` claim (e.g. CIBA Core §7.1 user
// resolution) so a client cannot select an arbitrary victim by forging the hint.
// Expiry is not enforced: an id_token_hint legitimately refers to a past login.
func (tc *TokenConfig) ParseTrustedIDToken(raw string) (jwt.Token, error) {
	// WithKey verifies the signature; WithValidate(false) skips claim validation
	// so an expired hint (referring to a past login) is still accepted. The
	// issuer is therefore checked explicitly below rather than via WithIssuer
	// (which only takes effect during validation).
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKey(jwa.PS256, tc.Keys.PublicKey()),
		jwt.WithValidate(false),
	)
	if err != nil {
		return nil, fmt.Errorf("verify id_token_hint: %w", err)
	}
	if tok.Issuer() != tc.Issuer {
		return nil, fmt.Errorf("verify id_token_hint: issuer mismatch")
	}
	return tok, nil
}

func signToken(tok jwt.Token, ks Signer) (string, error) {
	return signTokenWithAlg(tok, ks, jwa.PS256)
}

func signTokenWithAlg(tok jwt.Token, ks Signer, alg jwa.SignatureAlgorithm) (string, error) {
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, ks.KID())
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, ks.CryptoSigner(), jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return string(signed), nil
}

// ResolveIDTokenAlg converts the string value stored in id_token_signed_response_alg
// (e.g. "RS256") to a jwa.SignatureAlgorithm. Returns the server default (PS256) for
// empty or unrecognised values. Also used for userinfo_signed_response_alg.
func ResolveIDTokenAlg(alg string) jwa.SignatureAlgorithm {
	switch alg {
	case "RS256":
		return jwa.RS256
	case "ES256":
		return jwa.ES256
	case "PS256":
		return jwa.PS256
	default:
		return jwa.PS256
	}
}

// ComputeAtHash computes the at_hash claim value for an access token (RS256).
// OIDC Core §3.1.3.6: left half of SHA-256, base64url encoded.
func ComputeAtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// SignUserInfoClaims signs the userinfo claims map as a JWT per OIDC Core §5.3.2.
// The returned compact serialisation must be returned with Content-Type: application/jwt.
// iss and aud are injected automatically; all other claims are copied from the map.
func (tc *TokenConfig) SignUserInfoClaims(clientID string, claims map[string]any, alg jwa.SignatureAlgorithm) (string, error) {
	b := jwt.NewBuilder().
		Issuer(tc.Issuer).
		Audience([]string{clientID})
	for k, v := range claims {
		if k == "iss" || k == "aud" {
			continue // handled above
		}
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("build userinfo JWT: %w", err)
	}
	return signTokenWithAlg(tok, tc.Keys, alg)
}
