// Package federation implements OpenID Federation 1.0 for Clavex.
//
// Specifications:
//   - OpenID Federation 1.0: https://openid.net/specs/openid-federation-1_0.html
//   - OIDF OP profile:       §10 (openid_provider metadata claim)
//   - Entity Configuration:  §6  (entity-statement+jwt, typ header)
//   - Trust chain:           §9  (Intermediate/TA entity statements)
//
// Clavex acts as a Leaf OP in the federation. The trust chain is built by
// federation operators (e.g. IDEM-GARR, GÉANT) from the TA downward; this
// package covers only the OP-side obligations:
//
//  1. Publish a signed Entity Configuration at /.well-known/openid-federation
//  2. Expose federation metadata in the standard OIDC Discovery document
//  3. (Optional) Accept automatic/explicit client registration from federation RPs
package federation

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// ContentType is the MIME type for Entity Statement JWTs per OIDF §6.1.
const ContentType = "application/entity-statement+jwt"

// DefaultLifetime is the default validity window for an Entity Configuration
// JWT. IDEM-GARR recommends at least 24 h. Federations that require more
// frequent re-fetch typically mandate shorter windows via policy.
const DefaultLifetime = 24 * time.Hour

// ── Config ───────────────────────────────────────────────────────────────────

// Config holds per-tenant federation parameters derived from the server config.
type Config struct {
	// EntityID is the canonical identifier for this entity — the URI that
	// appears as both "iss" and "sub" in the Entity Configuration JWT.
	// Defaults to the OIDC issuer URL when empty.
	EntityID string

	// OrganizationName populates the federation_entity metadata claim.
	OrganizationName string

	// AuthorityHints is the ordered list of trust anchor / intermediate entity
	// IDs that federation clients use to build the trust chain upward.
	// For IDEM: []string{"https://registry.idem.garr.it"}
	// For GÉANT eduGAIN: []string{"https://federation.eduGAIN.org"}
	AuthorityHints []string

	// Lifetime overrides DefaultLifetime for the Entity Configuration JWT.
	// 0 means use DefaultLifetime.
	Lifetime time.Duration

	// Contacts is an optional list of email/URI contacts in federation metadata.
	Contacts []string

	// HomepageURI links to the OP operator's home page (federation_entity).
	HomepageURI string

	// LogoURI is the URL of a logo shown in federation UIs.
	LogoURI string
}

// ── Entity Configuration types ───────────────────────────────────────────────

// EntityConfiguration is the payload of an OIDF Entity Configuration JWT.
// The JWT is signed with the OP's federation signing key and published at
// GET /.well-known/openid-federation.
type EntityConfiguration struct {
	Issuer         string         `json:"iss"`
	Subject        string         `json:"sub"`
	IssuedAt       int64          `json:"iat"`
	ExpiresAt      int64          `json:"exp"`
	JWKS           json.RawMessage `json:"jwks"`
	Metadata       EntityMetadata `json:"metadata"`
	AuthorityHints []string       `json:"authority_hints,omitempty"`
}

// EntityMetadata is the "metadata" claim — a map from entity-type identifiers
// to their respective metadata objects.
type EntityMetadata struct {
	// OpenIDProvider contains the OP's federation-visible OIDC metadata (§10.1).
	OpenIDProvider *OPMetadata `json:"openid_provider,omitempty"`
	// FederationEntity contains organisational metadata visible to all entity types.
	FederationEntity *FedEntityMetadata `json:"federation_entity,omitempty"`
}

// OPMetadata mirrors the OIDC Discovery fields that OIDF requires an OP to
// publish inside the entity configuration's openid_provider claim (§10.1).
// Only fields that affect federation-level interop are mandatory here; the full
// set is served at /.well-known/openid-configuration.
type OPMetadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`

	// Federation-specific fields (OIDF §10.1)

	// ClientRegistrationTypesSupported declares the federation registration modes
	// this OP accepts. "automatic" = federation-based implicit registration;
	// "explicit" = OP stores a local entry for the RP after trust-chain validation.
	ClientRegistrationTypesSupported []string `json:"client_registration_types_supported"`

	// FederationRegistrationEndpoint is the OP endpoint where an RP can
	// request explicit (pre-registered) federation registration. Optional.
	FederationRegistrationEndpoint string `json:"federation_registration_endpoint,omitempty"`

	// RequestObjectSigningAlgValuesSupported declares the algorithms for JAR.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// RequestObjectEncryptionAlgValuesSupported / …EncValuesSupported declare the
	// JWE algorithms accepted for encrypted request objects (RFC 9101 §6.2). Only
	// populated when the OP publishes a request-object encryption key (use=enc).
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// PushedAuthorizationRequestEndpoint (RFC 9126) — advertised here so that
	// federation-level RPs can discover it without the Discovery endpoint.
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
}

// FedEntityMetadata is the federation_entity metadata claim (OIDF §4.8).
// It conveys human-readable and organisational information about the entity
// and is present in every entity type's entity configuration.
type FedEntityMetadata struct {
	OrganizationName string   `json:"organization_name,omitempty"`
	Contacts         []string `json:"contacts,omitempty"`
	LogoURI          string   `json:"logo_uri,omitempty"`
	HomepageURI      string   `json:"homepage_uri,omitempty"`
}

// ── JWT builder ──────────────────────────────────────────────────────────────

// Build constructs and signs an Entity Configuration JWT for the given issuer.
//
//   - cfg:        federation parameters (organisation, hints, lifetime)
//   - issuer:     OIDC issuer URL for this tenant (used as entity ID when cfg.EntityID is empty)
//   - privateKey: RSA private key used to sign the JWT (typically the OP's OIDC signing key)
//   - kid:        key ID embedded in the JWS protected header
//   - encJWK:     optional request-object encryption public JWK (use=enc) as a
//                 raw JSON object; when non-empty it is added to the published
//                 JWKS and the OP advertises encrypted-request-object support.
//
// The returned bytes are a compact JWS (three base64url segments separated by ".").
// The Content-Type for the HTTP response must be ContentType.
func Build(cfg Config, issuer string, privateKey *rsa.PrivateKey, kid string, encJWK []byte) ([]byte, error) {
	lifetime := cfg.Lifetime
	if lifetime == 0 {
		lifetime = DefaultLifetime
	}

	entityID := cfg.EntityID
	if entityID == "" {
		entityID = issuer
	}

	// Construct the federation signing JWKS (public key only — never the private key).
	pubJWK, err := jwk.FromRaw(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("federation: derive public JWK: %w", err)
	}
	_ = pubJWK.Set(jwk.KeyIDKey, kid)
	_ = pubJWK.Set(jwk.AlgorithmKey, "RS256")
	_ = pubJWK.Set(jwk.KeyUsageKey, "sig")

	sigJWKBytes, err := json.Marshal(pubJWK)
	if err != nil {
		return nil, fmt.Errorf("federation: marshal signing JWK: %w", err)
	}
	// The signing JWK plus the optional request-object encryption JWK (use=enc).
	jwksBytes := buildEntityJWKS(sigJWKBytes, encJWK)

	now := time.Now()
	ec := EntityConfiguration{
		Issuer:    entityID,
		Subject:   entityID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(lifetime).Unix(),
		JWKS:      json.RawMessage(jwksBytes),
		Metadata: EntityMetadata{
			OpenIDProvider: &OPMetadata{
				Issuer:                issuer,
				AuthorizationEndpoint: issuer + "/authorize",
				TokenEndpoint:         issuer + "/token",
				UserinfoEndpoint:      issuer + "/userinfo",
				JWKSURI:               issuer + "/.well-known/jwks.json",
				ResponseTypesSupported: []string{"code"},
				SubjectTypesSupported:  []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"PS256", "RS256"},
				ScopesSupported: []string{"openid", "profile", "email"},
				ClaimsSupported: []string{
					"sub", "iss", "aud", "exp", "iat",
					"given_name", "family_name", "email",
					"birthdate", "nationalities",
				},
				// OIDF §10.1 — declare both automatic and explicit registration.
				ClientRegistrationTypesSupported: []string{"automatic", "explicit"},
				// Explicit registration endpoint (RP-initiated trust chain submission).
				FederationRegistrationEndpoint: issuer + "/federation/register",
				// JAR (RFC 9101) — supported for FAPI2-style federation RPs.
				RequestObjectSigningAlgValuesSupported: []string{"RS256", "PS256", "ES256"},
				// PAR (RFC 9126)
				PushedAuthorizationRequestEndpoint: issuer + "/par",
			},
			FederationEntity: &FedEntityMetadata{
				OrganizationName: cfg.OrganizationName,
				Contacts:         cfg.Contacts,
				LogoURI:          cfg.LogoURI,
				HomepageURI:      cfg.HomepageURI,
			},
		},
		AuthorityHints: cfg.AuthorityHints,
	}

	// Advertise encrypted-request-object support only when a published enc key
	// exists (RFC 9101 §6.2). Values match the OP's EncKeySet capabilities.
	if len(encJWK) > 0 {
		ec.Metadata.OpenIDProvider.RequestObjectEncryptionAlgValuesSupported = []string{"RSA-OAEP-256"}
		ec.Metadata.OpenIDProvider.RequestObjectEncryptionEncValuesSupported = []string{"A256GCM"}
	}

	payload, err := json.Marshal(ec)
	if err != nil {
		return nil, fmt.Errorf("federation: marshal entity configuration: %w", err)
	}

	// OIDF §6.1: the "typ" header MUST be "entity-statement+jwt".
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	_ = hdrs.Set("typ", "entity-statement+jwt")

	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256, privateKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return nil, fmt.Errorf("federation: sign entity configuration: %w", err)
	}
	return signed, nil
}

// buildEntityJWKS assembles a JWKS document from the signing JWK and an optional
// encryption JWK (both raw JSON objects). Manual encoding preserves the encJWK's
// use=enc / alg fields verbatim.
func buildEntityJWKS(sigJWK, encJWK []byte) []byte {
	out := make([]byte, 0, len(sigJWK)+len(encJWK)+16)
	out = append(out, []byte(`{"keys":[`)...)
	out = append(out, sigJWK...)
	if len(encJWK) > 0 {
		out = append(out, ',')
		out = append(out, encJWK...)
	}
	out = append(out, []byte(`]}`)...)
	return out
}
