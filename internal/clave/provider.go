// Package clave implements a Cl@ve Relying Party following the Cl@ve SAML 2.0 / OIDC profile
// issued by the Spanish state secretary for digitalisation (SEDIA / SGAD).
//
// # Overview
//
// Cl@ve (https://clave.gob.es) is Spain's shared electronic authentication system for
// public administration services.  It covers 48M citizens and is mandated for digital
// public services by Ley 39/2015.
//
// Cl@ve supports two authentication levels aligned to eIDAS:
//   - Cl@ve PIN (Substantial): one-time PIN sent to mobile/email, valid 10 minutes
//   - Cl@ve Permanente (High):  user-managed password + optional OTP (≈ username+password+OTP)
//   - DNIe / certificado electrónico (High): electronic national ID card / certificates
//
// The modern "Cl@ve OIDC" interface is a standard OIDC Authorization Code Flow with PKCE.
// Legacy integrations used SAML 2.0 via the eIDAS node.
//
// # Endpoints
//
//	Production:  https://clave.gob.es (proxy at SGAD infrastructure)
//	Pre-production / test: https://preproduccion.clave.gob.es
//
// Official discovery (production):
//
//	https://preprod.clave.gob.es/ClaveIdP/oidc/.well-known/openid-configuration
//	https://clave.gob.es/ClaveIdP/oidc/.well-known/openid-configuration  (production)
//
// # Attribute mapping
//
//	Given name:  given_name
//	Family name: family_name
//	DNI/NIE:     PersonIdentifier  (for SAML) / "document_number" for OIDC variant
//	Date of birth: birthdate
//	Email:       email (only if user has consented)
//
// # Registration (SP registration)
//
// Complete the form at https://administracionelectronica.gob.es/ctt/clave
// and submit the SP metadata XML.  SGAD will issue a client_id and approve the callback URL.
// Cl@ve PIN access is granted first; Permanente (High) may require a separate authorisation.
//
// Nota: the "level" parameter in the auth request selects the authentication method:
//
//	level=1 → Cl@ve PIN
//	level=2 → Cl@ve Permanente + OTP
//	level=3 → certificado electrónico / DNIe (High)
package clave

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

// Environment selects production vs. pre-production Cl@ve OIDC.
type Environment string

const (
	EnvProduction    Environment = "production"
	EnvPreproduction Environment = "preproduction"
)

// Endpoints holds all Cl@ve OIDC endpoint URLs for an environment.
type Endpoints struct {
	Discovery        string
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	JWKSURL          string
}

var endpointMap = map[Environment]Endpoints{
	EnvProduction: {
		Discovery:        "https://clave.gob.es/ClaveIdP/oidc/.well-known/openid-configuration",
		AuthorizationURL: "https://clave.gob.es/ClaveIdP/oidc/authorize",
		TokenURL:         "https://clave.gob.es/ClaveIdP/oidc/token",
		UserinfoURL:      "https://clave.gob.es/ClaveIdP/oidc/userinfo",
		JWKSURL:          "https://clave.gob.es/ClaveIdP/oidc/jwks",
	},
	EnvPreproduction: {
		Discovery:        "https://preprod.clave.gob.es/ClaveIdP/oidc/.well-known/openid-configuration",
		AuthorizationURL: "https://preprod.clave.gob.es/ClaveIdP/oidc/authorize",
		TokenURL:         "https://preprod.clave.gob.es/ClaveIdP/oidc/token",
		UserinfoURL:      "https://preprod.clave.gob.es/ClaveIdP/oidc/userinfo",
		JWKSURL:          "https://preprod.clave.gob.es/ClaveIdP/oidc/jwks",
	},
}

// GetEndpoints returns the Cl@ve OIDC endpoints for the given environment string.
// Unknown environments fall back to pre-production for safety.
func GetEndpoints(env string) Endpoints {
	e, ok := endpointMap[Environment(env)]
	if !ok {
		return endpointMap[EnvPreproduction]
	}
	return e
}

// DefaultScopes covers the minimal identity data.
// "profile" yields given_name + family_name + birthdate.
// "email" is returned only when the user has explicitly consented.
const DefaultScopes = "openid profile email"

// AuthLevel selects the Cl@ve authentication method via the "acr_values" / level parameter.
// Use the eIDAS URI form for interoperability.
const (
	// LevelPIN is eIDAS Substantial — Cl@ve PIN (OTP sent to mobile/email).
	LevelPIN = "http://eidas.europa.eu/LoA/substantial"
	// LevelPermanente is eIDAS Substantial/High — Cl@ve Permanente (password + optional OTP).
	LevelPermanente = "http://eidas.europa.eu/LoA/substantial"
	// LevelCertificate is eIDAS High — certificado electrónico / DNIe.
	LevelCertificate = "http://eidas.europa.eu/LoA/high"
)

// ClaimMapping maps Cl@ve userinfo claim keys to Clavex user fields.
type ClaimMapping struct {
	EmailClaim     string
	FirstNameClaim string
	LastNameClaim  string
	BirthdateClaim string
	DocumentClaim  string // DNI/NIE identifier
}

// DefaultClaimMapping is the standard Cl@ve claim → user field mapping.
var DefaultClaimMapping = ClaimMapping{
	EmailClaim:     "email",
	FirstNameClaim: "given_name",
	LastNameClaim:  "family_name",
	BirthdateClaim: "birthdate",
	DocumentClaim:  "document_number", // national document number (DNI/NIE)
}

// BuildPKCEPair generates a PKCE S256 code_challenge from a verifier.
func BuildPKCEPair(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BuildAuthzURL constructs the full Cl@ve authorization URL with PKCE and nonce.
// acrValues selects the authentication strength; if empty the IdP chooses.
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

// ClaveUserInfo contains the normalised identity extracted from Cl@ve userinfo response.
type ClaveUserInfo struct {
	Sub            string // per-SP pseudonym
	Email          string
	EmailSynthetic bool // true when email was derived from document number
	FirstName      string
	LastName       string
	Birthdate      string // YYYY-MM-DD
	DocumentNumber string // DNI/NIE (when available)
}

// ParseUserInfo normalises raw Cl@ve userinfo claims into a ClaveUserInfo struct.
func ParseUserInfo(claims map[string]interface{}) *ClaveUserInfo {
	u := &ClaveUserInfo{}
	u.Sub, _ = claims["sub"].(string)
	u.FirstName, _ = claims["given_name"].(string)
	u.LastName, _ = claims["family_name"].(string)
	u.Birthdate, _ = claims["birthdate"].(string)
	u.DocumentNumber, _ = claims["document_number"].(string)

	if email, ok := claims["email"].(string); ok && email != "" {
		u.Email = email
		u.EmailSynthetic = false
	} else if u.DocumentNumber != "" {
		u.Email = u.DocumentNumber + "@clave.internal"
		u.EmailSynthetic = true
	} else if u.Sub != "" {
		u.Email = u.Sub + "@clave.internal"
		u.EmailSynthetic = true
	}
	return u
}
