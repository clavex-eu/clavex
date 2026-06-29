// Package bundid implements a BundID Relying Party following the BundID SAML 2.0 / OIDC profile
// issued by the German federal government (BMI / FITKO).
//
// # Overview
//
// BundID (https://id.bund.de) is the unified German federal eID account, replacing the former
// Servicekonto Bund.  It supports three authentication levels:
//   - STORK QL2 / eIDAS "Substantial": username+password
//   - STORK QL3 / eIDAS "High":        Online-Ausweise (nPA/eID), EU eID cards, smart card
//   - BundID OIDC (OIDC Connect with IAL/AAL):   newer REST-based variant
//
// The current (2025) recommended SP integration uses the BundID OIDC interface, a standard
// OIDC Authorization Code Flow with PKCE (S256). Legacy integrations used SAML 2.0.
//
// # Endpoints
//
//	Production:  https://id.bund.de/oidc
//	Test:        https://int.id.bund.de/oidc   (requires test eID card or SoftID)
//
// # Attribute mapping
//
//	Given name:   given_name
//	Family name:  family_name
//	Date of birth: birthdate  (YYYY-MM-DD)
//	Place of birth: place_of_birth
//	Address:      address   (structured, DIN 5008)
//	eID (Steuer-ID): tax_id (only with scope "tax_id", requires separate SP approval)
//	Pseudonym:    sub        (per-SP, stable — do NOT use as email)
//
// # Registration
//
// Register your SP at https://id.bund.de/de/fuer-dienstleister/registrierung.
// You will receive a client_id (public UUID) and choose an SP-side client_secret.
// The redirect_uri must exactly match what is registered.
// eIDAS "High" (nPA) requires a separate assessment; "Substantial" is self-declare.
//
// # FITKO Test system (integration)
//
// The integration environment at https://int.id.bund.de/oidc is accessible after requesting
// access via the FITKO support portal (fitko.de).  A software eID simulator ("SoftID") is
// provided for CI/CD testing.
package bundid

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

// Environment selects production vs. integration BundID OIDC.
type Environment string

const (
	EnvProduction  Environment = "production"
	EnvIntegration Environment = "integration"
)

// Endpoints holds all BundID OIDC endpoint URLs for an environment.
type Endpoints struct {
	// Discovery is the OIDC discovery document URL.
	// Retrieve it once at startup; it contains all other endpoints + JWKS.
	Discovery        string
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	JWKSURL          string
}

var endpointMap = map[Environment]Endpoints{
	EnvProduction: {
		Discovery:        "https://id.bund.de/oidc/.well-known/openid-configuration",
		AuthorizationURL: "https://id.bund.de/oidc/authorize",
		TokenURL:         "https://id.bund.de/oidc/token",
		UserinfoURL:      "https://id.bund.de/oidc/userinfo",
		JWKSURL:          "https://id.bund.de/oidc/jwk",
	},
	EnvIntegration: {
		Discovery:        "https://int.id.bund.de/oidc/.well-known/openid-configuration",
		AuthorizationURL: "https://int.id.bund.de/oidc/authorize",
		TokenURL:         "https://int.id.bund.de/oidc/token",
		UserinfoURL:      "https://int.id.bund.de/oidc/userinfo",
		JWKSURL:          "https://int.id.bund.de/oidc/jwk",
	},
}

// GetEndpoints returns the BundID OIDC endpoints for the given environment string.
// Unknown environments fall back to integration for safety.
func GetEndpoints(env string) Endpoints {
	e, ok := endpointMap[Environment(env)]
	if !ok {
		return endpointMap[EnvIntegration]
	}
	return e
}

// DefaultScopes covers the minimal identity data (name + birth date).
// Additional scopes require explicit approval during SP registration:
//   - "address"   — residential address (structured)
//   - "tax_id"    — Steuer-ID (strict legal basis required)
//   - "document"  — document data (requires eIDAS High + BMI approval)
const DefaultScopes = "openid profile email"

// Assurance level constants for the acr_values / vtr parameter.
// BundID maps eIDAS LoA to standard URI values.
const (
	// LoASubstantial maps to STORK QL2 / eIDAS Substantial.
	// Satisfied by username+password ("BundID Konto").
	LoASubstantial = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI" // used in acr
	// LoAHigh maps to STORK QL3 / eIDAS High.
	// Requires Online-Ausweis (nPA), EU eID, or smart card.
	LoAHigh = "https://www.authenticationlevel.bund.de/ns/eID/internet"
)

// ClaimMapping maps BundID userinfo claim keys to Clavex user fields.
type ClaimMapping struct {
	EmailClaim        string
	FirstNameClaim    string
	LastNameClaim     string
	BirthdateClaim    string
	PlaceOfBirthClaim string
}

// DefaultClaimMapping is the standard BundID claim → user field mapping.
var DefaultClaimMapping = ClaimMapping{
	EmailClaim:        "email",
	FirstNameClaim:    "given_name",
	LastNameClaim:     "family_name",
	BirthdateClaim:    "birthdate",
	PlaceOfBirthClaim: "place_of_birth",
}

// BuildPKCEPair generates a PKCE S256 code_challenge from a verifier.
func BuildPKCEPair(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BuildAuthzURL constructs the full BundID authorization URL including PKCE and nonce.
// acrValues may be empty (no LoA enforcement) or one of the LoA* constants above.
func BuildAuthzURL(
	env string,
	clientID, redirectURI, state, nonce, codeVerifier string,
	acrValues string,
) string {
	eps := GetEndpoints(env)
	codeChallenge := BuildPKCEPair(codeVerifier)

	u, _ := url.Parse(eps.AuthorizationURL)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", DefaultScopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	if acrValues != "" {
		q.Set("acr_values", acrValues)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// BundIDUserInfo contains the normalised identity extracted from BundID userinfo response.
type BundIDUserInfo struct {
	Sub            string // per-SP pseudonym — use as primary key, not email
	Email          string
	EmailSynthetic bool // true when email was derived from sub
	FirstName      string
	LastName       string
	Birthdate      string // YYYY-MM-DD
	PlaceOfBirth   string
}

// ParseUserInfo normalises raw BundID userinfo claims into a BundIDUserInfo struct.
func ParseUserInfo(claims map[string]interface{}) *BundIDUserInfo {
	u := &BundIDUserInfo{}
	u.Sub, _ = claims["sub"].(string)
	u.FirstName, _ = claims["given_name"].(string)
	u.LastName, _ = claims["family_name"].(string)
	u.Birthdate, _ = claims["birthdate"].(string)
	u.PlaceOfBirth, _ = claims["place_of_birth"].(string)

	if email, ok := claims["email"].(string); ok && email != "" {
		u.Email = email
		u.EmailSynthetic = false
	} else if u.Sub != "" {
		// BundID does not always release email; synthesise a stable internal address.
		u.Email = u.Sub + "@bundid.internal"
		u.EmailSynthetic = true
	}
	return u
}
