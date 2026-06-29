// Package digid implements a DigiD Relying Party following the DigiD OIDC/SAML profile
// issued by Logius (Dutch Ministry of the Interior — BZK).
//
// # Overview
//
// DigiD (https://www.digid.nl) is the Dutch national digital identity for citizens.
// It is used by 17M Dutch citizens to authenticate with government services and is
// mandated by the Wet elektronische bestuurlijke gegevensverkeer (WEBV) / BSN Act.
//
// DigiD supports four authentication levels (Substantieel / Hoog per eIDAS):
//   - DigiD Basis (LoA 1):  username + password
//   - DigiD Midden (LoA 2): username + password + SMS OTP
//   - DigiD Substantieel (LoA 3): DigiD app with biometrics or NFC-capable eNIK
//   - DigiD Hoog (LoA 4):  NFC chip read of driving licence or ID card (eIDAS High)
//
// DigiD uses SAML 2.0 as the primary protocol for service providers.  An OIDC-based
// interface ("DigiD OIDC Koppelvlak") exists and is in rollout as of 2025.
// This package targets the DigiD OIDC interface; the SAML variant requires the
// crewjam/saml library and a separate Logius-issued certificate.
//
// # Endpoints (DigiD OIDC — "Koppelvlak")
//
// Logius provides a pre-production environment and production.
// All connections require mTLS (client certificate) — Logius issues an SP certificate
// after the SP registration is accepted.
//
//	Production discovery:
//	  https://authenticatie.digid.nl/oidc/.well-known/openid-configuration
//	Pre-production (acceptatie / acc):
//	  https://authenticatie-machtigen.acc.digid.nl/oidc/.well-known/openid-configuration
//
// # Attribute mapping
//
// DigiD is intentionally minimal: it only asserts the BSN (Burgerservicenummer),
// the authentication level (acr), and a per-SP pseudonym.
// Personal data (name, address) must be fetched from the BRP (Basisregistratie Personen)
// using the BSN after authentication — DigiD does NOT release PII itself.
//
//	BSN:  "bsn" (custom claim in the OIDC userinfo, hashed or encrypted depending on configuration)
//	acr:  assurance level achieved
//	sub:  per-SP pseudonym (stable)
//
// # Registration
//
// 1. Complete the SP questionnaire at https://www.logius.nl/diensten/digid
// 2. Pass the "Toelatingsproces" (admission process) — includes a security audit
// 3. Receive the SP certificate from Logius PKIoverheid
// 4. Submit the service description and redirect URIs
// 5. Test against the acc environment (no real BSNs, test accounts provided)
//
// Note: BSN use in non-public-authority applications requires a legal basis per
// Article 10 Wet algemene bepalingen burgerservicenummer (Wabb).
package digid

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

// Environment selects production vs. pre-production DigiD OIDC.
type Environment string

const (
	EnvProduction Environment = "production"
	EnvAcceptance Environment = "acceptance" // Logius pre-production / "acc"
)

// Endpoints holds all DigiD OIDC endpoint URLs for an environment.
type Endpoints struct {
	Discovery        string
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	JWKSURL          string
}

var endpointMap = map[Environment]Endpoints{
	EnvProduction: {
		Discovery:        "https://authenticatie.digid.nl/oidc/.well-known/openid-configuration",
		AuthorizationURL: "https://authenticatie.digid.nl/oidc/authorize",
		TokenURL:         "https://authenticatie.digid.nl/oidc/token",
		UserinfoURL:      "https://authenticatie.digid.nl/oidc/userinfo",
		JWKSURL:          "https://authenticatie.digid.nl/oidc/jwks",
	},
	EnvAcceptance: {
		Discovery:        "https://authenticatie-machtigen.acc.digid.nl/oidc/.well-known/openid-configuration",
		AuthorizationURL: "https://authenticatie-machtigen.acc.digid.nl/oidc/authorize",
		TokenURL:         "https://authenticatie-machtigen.acc.digid.nl/oidc/token",
		UserinfoURL:      "https://authenticatie-machtigen.acc.digid.nl/oidc/userinfo",
		JWKSURL:          "https://authenticatie-machtigen.acc.digid.nl/oidc/jwks",
	},
}

// GetEndpoints returns the DigiD OIDC endpoints for the given environment string.
// Unknown environments fall back to acceptance for safety.
func GetEndpoints(env string) Endpoints {
	e, ok := endpointMap[Environment(env)]
	if !ok {
		return endpointMap[EnvAcceptance]
	}
	return e
}

// DefaultScopes contains the minimal scope set.
// DigiD intentionally exposes very few claims; "bsn" must be explicitly requested
// and requires a legal basis per Wabb Art.10.
const DefaultScopes = "openid bsn"

// Assurance level constants (acr_values).
// DigiD maps to eIDAS LoA URIs:
const (
	// LoA1 is DigiD Basis — username + password.
	LoA1 = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	// LoA2 is DigiD Midden — password + SMS OTP (eIDAS Low+).
	LoA2 = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
	// LoA3 is DigiD Substantieel — DigiD app with biometrics / eNIK NFC (eIDAS Substantial).
	LoA3 = "http://eidas.europa.eu/LoA/substantial"
	// LoA4 is DigiD Hoog — NFC driving licence or ID card (eIDAS High).
	LoA4 = "http://eidas.europa.eu/LoA/high"
)

// ClaimMapping maps DigiD userinfo claim keys to Clavex user fields.
// DigiD only provides sub and bsn from the IdP itself; all PII comes from BRP.
type ClaimMapping struct {
	BSNClaim string
}

// DefaultClaimMapping is the standard DigiD claim → user field mapping.
var DefaultClaimMapping = ClaimMapping{
	BSNClaim: "bsn",
}

// BuildPKCEPair generates a PKCE S256 code_challenge from a verifier.
func BuildPKCEPair(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BuildAuthzURL constructs the full DigiD authorization URL with PKCE and nonce.
// acrValues selects the minimum assurance level; use one of the LoA* constants.
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

// DigiDUserInfo contains the normalised identity extracted from DigiD userinfo response.
// Note: DigiD does NOT release name, email, or address — only BSN + assurance level.
// Enrich with BRP after authentication if PII is needed.
type DigiDUserInfo struct {
	Sub            string // per-SP pseudonym — use as stable primary key
	BSN            string // Burgerservicenummer — hash before storing (privacy)
	ACR            string // achieved assurance level
	Email          string // always synthetic (BSN-derived); DigiD does not release email
	EmailSynthetic bool
}

// ParseUserInfo normalises raw DigiD userinfo claims into a DigiDUserInfo struct.
func ParseUserInfo(claims map[string]interface{}) *DigiDUserInfo {
	u := &DigiDUserInfo{}
	u.Sub, _ = claims["sub"].(string)
	u.BSN, _ = claims["bsn"].(string)
	u.ACR, _ = claims["acr"].(string)

	// DigiD never releases email; synthesise from BSN hash for internal use.
	if u.BSN != "" {
		h := sha256.Sum256([]byte(u.BSN))
		u.Email = base64.RawURLEncoding.EncodeToString(h[:12]) + "@digid.internal"
	} else if u.Sub != "" {
		u.Email = u.Sub + "@digid.internal"
	}
	u.EmailSynthetic = true
	return u
}

// HashBSN returns a non-reversible SHA-256 hex hash of a BSN for storage.
// Storing raw BSNs requires Wabb Art.10 authorisation; hashed BSNs are safer
// for use as user correlation keys in systems that are not authorised holders.
func HashBSN(bsn string) string {
	h := sha256.Sum256([]byte("bsn:" + bsn))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
