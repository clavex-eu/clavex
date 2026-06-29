// Package itsme implements a itsme® Relying Party following the
// itsme® OIDC profile (Belgium / Luxembourg).
//
// itsme® uses standard OIDC Authorization Code Flow with PKCE (S256) and nonce.
//
// # Endpoints
//
//	Production discovery: https://idp.prd.itsme.services/v2/.well-known/openid-configuration
//	Sandbox discovery:    https://idp.e2e.itsme.services/v2/.well-known/openid-configuration
//
// # Key differences from standard OIDC
//
//   - Token endpoint requires JWT client assertion (private_key_jwt), NOT client_secret_basic.
//   - The service_code parameter (issued by itsme during onboarding) is required in each
//     authorization request.
//   - The `sub` claim is per-service and pseudonymous (stable — use it as primary key).
//   - Assurance levels: loa2 (basic) and loa3 (high — in-person ID card verification).
//
// # Onboarding (sandbox)
//
//  1. Sign up at https://brand.belgianmobileid.be/d/CX5Qcb8xmqRHN
//  2. Create a "Partner" and a "Service" — you receive a client_id and service_code.
//  3. Configure redirect URIs and upload your RP public key (JWKS endpoint or inline).
//  4. Use the e2e sandbox IdP; no real Belgian eID needed for test flows.
//
// # Onboarding (production)
//
//  1. Sign a partnership agreement with Belgian Mobile ID SA (commercial — contact sales@itsme.be).
//  2. Complete the technical integration review with the itsme partner team.
//  3. Receive production client_id, service_code, and environment credentials.
//  4. Production requires a real itsme® app installation (Belgian/LU mobile number).
package itsme

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

// Environment selects sandbox vs. production itsme endpoint set.
type Environment string

const (
	EnvSandbox    Environment = "sandbox"
	EnvProduction Environment = "production"
)

// Endpoints holds all itsme OIDC endpoint URLs for an environment.
type Endpoints struct {
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	JWKSURL          string
	DiscoveryURL     string
}

var endpointMap = map[Environment]Endpoints{
	EnvSandbox: {
		AuthorizationURL: "https://idp.e2e.itsme.services/v2/authorization",
		TokenURL:         "https://idp.e2e.itsme.services/v2/token",
		UserinfoURL:      "https://idp.e2e.itsme.services/v2/userinfo",
		JWKSURL:          "https://idp.e2e.itsme.services/v2/jwk",
		DiscoveryURL:     "https://idp.e2e.itsme.services/v2/.well-known/openid-configuration",
	},
	EnvProduction: {
		AuthorizationURL: "https://idp.prd.itsme.services/v2/authorization",
		TokenURL:         "https://idp.prd.itsme.services/v2/token",
		UserinfoURL:      "https://idp.prd.itsme.services/v2/userinfo",
		JWKSURL:          "https://idp.prd.itsme.services/v2/jwk",
		DiscoveryURL:     "https://idp.prd.itsme.services/v2/.well-known/openid-configuration",
	},
}

// GetEndpoints returns the itsme OIDC endpoints for the given environment string.
// Unknown environments fall back to sandbox.
func GetEndpoints(env string) Endpoints {
	e, ok := endpointMap[Environment(env)]
	if !ok {
		return endpointMap[EnvSandbox]
	}
	return e
}

// DefaultScopes covers basic identity. itsme also supports:
// "address", "phone", "eid" (eID card data), "claim:name", "claim:birthdate", etc.
const DefaultScopes = "openid profile email"

// Assurance level constants for the acr_values parameter.
const (
	LoA2 = "http://eidas.europa.eu/LoA/low"  // basic — app approval
	LoA3 = "http://eidas.europa.eu/LoA/high" // high — ID card verification
)

// ClaimMapping maps itsme userinfo claim keys to Clavex user fields.
type ClaimMapping struct {
	SubClaim       string
	EmailClaim     string
	FirstNameClaim string
	LastNameClaim  string
	BirthdateClaim string
	PhoneClaim     string
}

// DefaultClaimMapping is the standard itsme claim → user field mapping.
var DefaultClaimMapping = ClaimMapping{
	SubClaim:       "sub",
	EmailClaim:     "email",
	FirstNameClaim: "given_name",
	LastNameClaim:  "family_name",
	BirthdateClaim: "birthdate",
	PhoneClaim:     "phone_number",
}

// ItsmeUserInfo holds the normalised identity returned by itsme.
type ItsmeUserInfo struct {
	// Sub is the per-service pseudonymous subject identifier (stable primary key).
	Sub         string
	Email       string
	FirstName   string
	LastName    string
	Birthdate   string
	PhoneNumber string
}

// ParseUserInfo normalises raw itsme userinfo claims into an ItsmeUserInfo struct.
func ParseUserInfo(claims map[string]interface{}) *ItsmeUserInfo {
	u := &ItsmeUserInfo{}
	u.Sub, _ = claims["sub"].(string)
	u.Email, _ = claims["email"].(string)
	u.FirstName, _ = claims["given_name"].(string)
	u.LastName, _ = claims["family_name"].(string)
	u.Birthdate, _ = claims["birthdate"].(string)
	u.PhoneNumber, _ = claims["phone_number"].(string)
	return u
}

// BuildPKCEPair generates a PKCE S256 code_challenge from the verifier.
func BuildPKCEPair(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BuildAuthzURL constructs the full itsme authorization URL.
// serviceCode is the itsme service code assigned during onboarding (required).
// acrValues selects assurance level: use LoA2 or LoA3 constants.
func BuildAuthzURL(
	env string,
	clientID, redirectURI, state, nonce, codeVerifier string,
	serviceCode, acrValues string,
	addtlScopes ...string,
) (authzURL string, codeChallenge string) {
	eps := GetEndpoints(env)
	codeChallenge = BuildPKCEPair(codeVerifier)

	if acrValues == "" {
		acrValues = LoA2
	}

	scopes := DefaultScopes
	for _, s := range addtlScopes {
		scopes += " " + s
	}

	u, _ := url.Parse(eps.AuthorizationURL)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("service_code", serviceCode)
	q.Set("acr_values", acrValues)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), codeChallenge
}

// EnvFromTokenURL infers the itsme environment from a stored token endpoint URL.
func EnvFromTokenURL(tokenURL string) string {
	if len(tokenURL) > 10 && tokenURL[8:11] == "e2e" {
		return "sandbox"
	}
	for i := 0; i+3 <= len(tokenURL); i++ {
		if tokenURL[i:i+3] == "e2e" {
			return "sandbox"
		}
	}
	return "production"
}
