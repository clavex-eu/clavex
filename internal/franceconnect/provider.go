// Package franceconnect implements a FranceConnect Relying Party following the
// FranceConnect v2 OIDC profile issued by the French government (DINUM).
//
// FranceConnect uses standard OIDC Authorization Code Flow with PKCE (S256) and nonce.
// The `sub` claim is pseudonymous and per-SP — never share it across services.
// Stable identifier: "sub" (store it; don't use email as a primary key for FC users).
//
// Sandbox (public, no prior approval needed):
//   Discovery: https://fcp.integ01.dev-franceconnect.fr/api/v2/.well-known/openid-configuration
//
// Production (requires DINUM approval + convention):
//   Discovery: https://app.franceconnect.gouv.fr/api/v2/.well-known/openid-configuration
//
// Mandatory scopes: openid
// Identity scopes: given_name family_name birthdate birthplace birthcountry gender email phone address
// Each scope must be individually requested; FC does not bundle them.
package franceconnect

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
)

// Environment selects sandbox vs. production FC endpoint set.
type Environment string

const (
	EnvSandbox    Environment = "sandbox"
	EnvProduction Environment = "production"
)

// Endpoints holds all FranceConnect OIDC endpoint URLs for an environment.
type Endpoints struct {
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	JWKSURL          string
	LogoutURL        string
}

var endpointMap = map[Environment]Endpoints{
	EnvSandbox: {
		AuthorizationURL: "https://fcp.integ01.dev-franceconnect.fr/api/v2/authorize",
		TokenURL:         "https://fcp.integ01.dev-franceconnect.fr/api/v2/token",
		UserinfoURL:      "https://fcp.integ01.dev-franceconnect.fr/api/v2/userinfo",
		JWKSURL:          "https://fcp.integ01.dev-franceconnect.fr/api/v2/jwks",
		LogoutURL:        "https://fcp.integ01.dev-franceconnect.fr/api/v2/session/end",
	},
	EnvProduction: {
		AuthorizationURL: "https://app.franceconnect.gouv.fr/api/v2/authorize",
		TokenURL:         "https://app.franceconnect.gouv.fr/api/v2/token",
		UserinfoURL:      "https://app.franceconnect.gouv.fr/api/v2/userinfo",
		JWKSURL:          "https://app.franceconnect.gouv.fr/api/v2/jwks",
		LogoutURL:        "https://app.franceconnect.gouv.fr/api/v2/session/end",
	},
}

// GetEndpoints returns the FranceConnect OIDC endpoints for the given environment string.
// Unknown environments fall back to sandbox.
func GetEndpoints(env string) Endpoints {
	e, ok := endpointMap[Environment(env)]
	if !ok {
		return endpointMap[EnvSandbox]
	}
	return e
}

// DefaultScopes contains the minimal scope set for identity data.
// FC requires each scope to be listed individually.
// "openid" is always required. Additional scopes require explicit user consent.
const DefaultScopes = "openid given_name family_name birthdate gender email"

// All optional identity scopes available from FranceConnect v2.
const (
	ScopeBirthplace        = "birthplace"
	ScopeBirthcountry      = "birthcountry"
	ScopePhone             = "phone"
	ScopeAddress           = "address"
	ScopePreferredUsername = "preferred_username"
)

// ClaimMapping maps FranceConnect userinfo claim keys to Clavex user fields.
// The `sub` is a per-SP pseudonymous identifier — store it as ExternalID.
type ClaimMapping struct {
	SubClaim       string
	EmailClaim     string
	FirstNameClaim string
	LastNameClaim  string
	BirthdateClaim string
	GenderClaim    string
}

// DefaultClaimMapping is the standard FranceConnect claim → user field mapping.
var DefaultClaimMapping = ClaimMapping{
	SubClaim:       "sub",
	EmailClaim:     "email",
	FirstNameClaim: "given_name",
	LastNameClaim:  "family_name",
	BirthdateClaim: "birthdate",
	GenderClaim:    "gender",
}

// FCUserInfo holds the normalised identity returned by FranceConnect.
type FCUserInfo struct {
	// Sub is the per-SP pseudonymous subject identifier.
	// This is the stable primary key for FC users — email can change.
	Sub          string
	Email        string
	FirstName    string
	LastName     string
	Birthdate    string
	Gender       string
	// Birthplace and Birthcountry are available when the "birthplace" and
	// "birthcountry" scopes are requested. They are empty when not consented.
	Birthplace   string
	Birthcountry string
}

// ParseUserInfo normalises raw FranceConnect userinfo claims into an FCUserInfo struct.
func ParseUserInfo(claims map[string]interface{}) *FCUserInfo {
	u := &FCUserInfo{}
	u.Sub, _ = claims["sub"].(string)
	u.Email, _ = claims["email"].(string)
	u.FirstName, _ = claims["given_name"].(string)
	u.LastName, _ = claims["family_name"].(string)
	u.Birthdate, _ = claims["birthdate"].(string)
	u.Gender, _ = claims["gender"].(string)
	u.Birthplace, _ = claims["birthplace"].(string)
	u.Birthcountry, _ = claims["birthcountry"].(string)
	return u
}

// BuildPKCEPair generates a PKCE S256 code_challenge from the verifier.
func BuildPKCEPair(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BuildAuthzURL constructs the full FranceConnect authorization URL.
// FC requires the `acr_values` parameter (eIDAS level): "eidas1" | "eidas2" | "eidas3".
// Default is "eidas1" (basic assurance).
func BuildAuthzURL(
	env string,
	clientID, redirectURI, state, nonce, codeVerifier string,
	acrValues string,
	addtlScopes ...string,
) (authzURL string, codeChallenge string) {
	eps := GetEndpoints(env)
	codeChallenge = BuildPKCEPair(codeVerifier)

	if acrValues == "" {
		acrValues = "eidas1"
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
	q.Set("acr_values", acrValues)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), codeChallenge
}

// SynthesiseEmail generates a deterministic synthetic email for FC users that
// don't share their real email. Uses the pseudonymous sub to avoid PII leakage.
func SynthesiseEmail(sub string) string {
	h := sha256.Sum256([]byte("fc:" + sub))
	hash := fmt.Sprintf("%x", h[:8])
	return hash + "@fc.clavex.invalid"
}

// EnvFromTokenURL infers the FC environment from a stored token endpoint URL.
func EnvFromTokenURL(tokenURL string) string {
	if containsInteg(tokenURL) {
		return "sandbox"
	}
	return "production"
}

func containsInteg(s string) bool {
	for i := 0; i < len(s)-4; i++ {
		if s[i:i+5] == "integ" {
			return true
		}
	}
	return false
}
