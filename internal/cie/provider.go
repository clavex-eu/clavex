// Package cie implements a CIE (Carta d'Identità Elettronica) Relying Party
// following the CIE OpenID Connect 3.0 profile issued by the Italian Ministry of Interior.
//
// CIE uses standard OIDC Authorization Code Flow with PKCE (S256) and nonce.
// Claims include: given_name, family_name, birthdate, fiscal_number (TINIT-…), gender.
//
// # Endpoints
//
//	Production:     https://idserver.servizicie.interno.gov.it/idp/...
//	Pre-production: https://preproduzione.idserver.servizicie.interno.gov.it/idp/...
//
// The pre-production environment requires no prior approval and is suitable for
// integration testing with the CieID app (available on iOS/Android).
//
// # Registration (production)
//
//  1. Register your RP at the Ministero dell'Interno developer portal:
//     https://id.servizicie.interno.gov.it/idp/registrazioneRP
//  2. Provide client_id, redirect_uri(s), and the RP signing certificate.
//  3. The Ministry issues production credentials after a lightweight review.
//  4. Test device: CieID app + a NFC-capable Italian eID card (or use the pre-prod IdP
//     which accepts test accounts without a physical card).
package cie

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
)

// Environment selects prod vs. pre-production CIE IdP.
type Environment string

const (
	EnvProduction    Environment = "production"
	EnvPreproduction Environment = "preproduction"
)

// Endpoints holds all CIE OIDC endpoint URLs for an environment.
type Endpoints struct {
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	JWKSURL          string
}

// endpointMap contains the official CIE endpoint URLs.
var endpointMap = map[Environment]Endpoints{
	EnvProduction: {
		AuthorizationURL: "https://idserver.servizicie.interno.gov.it/idp/profile/oidc/authorize",
		TokenURL:         "https://idserver.servizicie.interno.gov.it/idp/profile/oidc/token",
		UserinfoURL:      "https://idserver.servizicie.interno.gov.it/idp/profile/oidc/userinfo",
		JWKSURL:          "https://idserver.servizicie.interno.gov.it/idp/profile/oidc/keyset",
	},
	EnvPreproduction: {
		AuthorizationURL: "https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/oidc/authorize",
		TokenURL:         "https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/oidc/token",
		UserinfoURL:      "https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/oidc/userinfo",
		JWKSURL:          "https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/oidc/keyset",
	},
}

// GetEndpoints returns the CIE OIDC endpoints for the given environment string.
// Unknown environments fall back to pre-production.
func GetEndpoints(env string) Endpoints {
	e, ok := endpointMap[Environment(env)]
	if !ok {
		return endpointMap[EnvPreproduction]
	}
	return e
}

// DefaultScopes are the OIDC scopes to request from the CIE IdP.
// "profile" includes given_name, family_name, birthdate, gender, place_of_birth, address.
const DefaultScopes = "openid profile"

// ClaimMapping maps CIE userinfo claim keys to Clavex user fields.
// CIE fiscal number comes as "fiscal_number" with value "TINIT-<codicefiscale>".
type ClaimMapping struct {
	EmailClaim     string
	FirstNameClaim string
	LastNameClaim  string
	FiscalNumClaim string
}

// DefaultClaimMapping is the standard CIE claim → user field mapping.
var DefaultClaimMapping = ClaimMapping{
	EmailClaim:     "email",
	FirstNameClaim: "given_name",
	LastNameClaim:  "family_name",
	FiscalNumClaim: "fiscal_number",
}

// StripTINITPrefix removes the "TINIT-" prefix that CIE prepends to fiscal numbers.
func StripTINITPrefix(fiscalNumber string) string {
	if len(fiscalNumber) > 6 && fiscalNumber[:6] == "TINIT-" {
		return fiscalNumber[6:]
	}
	return fiscalNumber
}

// BuildPKCEPair generates a PKCE code_verifier and its S256 code_challenge.
// The verifier must be stored in the session and the challenge sent in the authorization request.
func BuildPKCEPair(verifier string) (codeChallenge string) {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BuildAuthzURL constructs the full CIE authorization URL including PKCE and nonce.
func BuildAuthzURL(
	env string,
	clientID, redirectURI, state, nonce, codeVerifier string,
	addtlScopes ...string,
) (authzURL string, codeChallenge string) {
	eps := GetEndpoints(env)
	codeChallenge = BuildPKCEPair(codeVerifier)

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
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), codeChallenge
}

// ExtractFiscalNumber extracts and normalises the fiscal number from a CIE userinfo map.
// Returns empty string if not present.
func ExtractFiscalNumber(claims map[string]interface{}) string {
	raw, _ := claims[DefaultClaimMapping.FiscalNumClaim].(string)
	return StripTINITPrefix(raw)
}

// ExtractEmail attempts to get an email address.
// CIE may not always return an email; we fall back to constructing one from the fiscal number.
func ExtractEmail(claims map[string]interface{}, fiscalNumber string) (string, bool) {
	if email, ok := claims["email"].(string); ok && email != "" {
		return email, true
	}
	if fiscalNumber != "" {
		return fmt.Sprintf("%s@cie.internal", fiscalNumber), false
	}
	return "", false
}

// CIEUserInfo contains the normalised identity extracted from CIE userinfo response.
type CIEUserInfo struct {
	FiscalNumber   string // normalised (without TINIT- prefix)
	FirstName      string
	LastName       string
	DateOfBirth    string
	Gender         string
	Email          string
	EmailSynthetic bool // true if the email was synthesised from the fiscal number
}

// ParseUserInfo normalises raw CIE userinfo claims into a CIEUserInfo struct.
func ParseUserInfo(claims map[string]interface{}) *CIEUserInfo {
	u := &CIEUserInfo{}
	u.FiscalNumber = ExtractFiscalNumber(claims)
	u.FirstName, _ = claims["given_name"].(string)
	u.LastName, _ = claims["family_name"].(string)
	u.DateOfBirth, _ = claims["birthdate"].(string)
	u.Gender, _ = claims["gender"].(string)
	email, synthetic := ExtractEmail(claims, u.FiscalNumber)
	u.Email = email
	u.EmailSynthetic = !synthetic
	return u
}
