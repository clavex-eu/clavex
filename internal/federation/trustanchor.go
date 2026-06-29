package federation

// trustanchor.go — Trust Anchor Entity Configuration and Subordinate Statement builder.
//
// Specifications:
//   - OIDF 1.0 §6.4  Entity Configuration of a Trust Anchor
//   - OIDF 1.0 §7    Federation Endpoints
//   - OIDF 1.0 §7.3  Fetch and List endpoints
//   - OIDF 1.0 §9    Trust Chains
//
// When Clavex operates as a Trust Anchor it:
//   1. Publishes its own self-signed Entity Configuration (no authority_hints).
//   2. Serves a subordinate list at GET /federation/list.
//   3. Signs Entity Statements about registered subordinates at GET /federation/fetch.

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// TrustAnchorConfig holds parameters specific to the TA Entity Configuration.
// It extends the base Config with TA-specific federation endpoint URLs.
type TrustAnchorConfig struct {
	Config

	// EntityID is the TA's stable entity identifier URI.
	// This MUST be the canonical public URI of the TA, e.g.
	// "https://trust.consortium.eu" or "https://id.bank.example.com/federation".
	// All subordinate entity statements will carry this as "iss".
	EntityID string

	// BaseURL is the HTTP base from which the TA endpoints are derived,
	// e.g. "https://id.clavex.eu/acme-corp".
	// Endpoint URLs are constructed as BaseURL + "/federation/...".
	BaseURL string

	// SubordinateStatementLifetime is the default lifetime for entity statements
	// signed about subordinates. Defaults to 24 h.
	SubordinateStatementLifetime time.Duration

	// TrustMarkIssuerMap maps trust_mark_id → []issuer entity IDs.
	// Populated from the DB trust mark types.
	TrustMarkIssuerMap map[string][]string
}

// TAFedEntityMetadata extends FedEntityMetadata with the TA-specific endpoint
// claims defined in OIDF 1.0 §7.
type TAFedEntityMetadata struct {
	FedEntityMetadata

	// OIDF §7.3.2 — signed entity statements about subordinates.
	FederationFetchEndpoint string `json:"federation_fetch_endpoint,omitempty"`
	// OIDF §7.3.1 — list of immediate subordinate entity IDs.
	FederationListEndpoint string `json:"federation_list_endpoint,omitempty"`
	// OIDF §7.4 — request a trust mark.
	FederationTrustMarkEndpoint string `json:"federation_trust_mark_endpoint,omitempty"`
	// OIDF §7.5 — list subjects holding a given trust mark.
	FederationTrustMarkListEndpoint string `json:"federation_trust_mark_list_endpoint,omitempty"`
	// OIDF §7.6 — check trust mark active/revoked status.
	FederationTrustMarkStatusEndpoint string `json:"federation_trust_mark_status_endpoint,omitempty"`
	// TrustMarkIssuers maps trust_mark_id → list of authorised issuer entity IDs (OIDF §8.3).
	TrustMarkIssuers map[string][]string `json:"trust_mark_issuers,omitempty"`
}

// taEntityConfiguration mirrors EntityConfiguration but uses TAFedEntityMetadata
// for the federation_entity claim so TA endpoints are advertised.
type taEntityConfiguration struct {
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	IssuedAt  int64          `json:"iat"`
	ExpiresAt int64          `json:"exp"`
	JWKS      json.RawMessage `json:"jwks"`
	Metadata  taEntityMetadata `json:"metadata"`
	// NOTE: No authority_hints — this is a self-signed Trust Anchor root.
}

type taEntityMetadata struct {
	FederationEntity *TAFedEntityMetadata `json:"federation_entity,omitempty"`
}

// SubordinateStatement is the payload signed into a subordinate entity statement
// (OIDF §9.2). The TA signs it; the sub is the subordinate's entity ID.
type SubordinateStatement struct {
	Issuer         string          `json:"iss"`  // TA entity ID
	Subject        string          `json:"sub"`  // subordinate entity ID
	IssuedAt       int64           `json:"iat"`
	ExpiresAt      int64           `json:"exp"`
	JWKS           json.RawMessage `json:"jwks,omitempty"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
	MetadataPolicy json.RawMessage `json:"metadata_policy,omitempty"`
	TrustMarkIDs   []string        `json:"trust_mark_ids,omitempty"`
	TrustMarks     []json.RawMessage `json:"trust_marks,omitempty"`
	SourceEndpoint string          `json:"source_endpoint,omitempty"`
}

// BuildTAEntityConfig constructs and signs the Trust Anchor's own Entity
// Configuration JWT (OIDF §6.4). The result is a compact JWS with
// Content-Type: "application/entity-statement+jwt".
//
// Unlike a Leaf OP's Entity Configuration:
//   - No "authority_hints" — the TA is the root.
//   - federation_entity metadata contains TA-specific endpoint URIs.
//   - TrustMarkIssuers map is included when trust marks are configured.
func BuildTAEntityConfig(cfg TrustAnchorConfig, signer crypto.Signer, alg jwa.SignatureAlgorithm, kid string) ([]byte, error) {
	if alg == "" {
		alg = jwa.PS256
	}
	lifetime := cfg.Lifetime
	if lifetime == 0 {
		lifetime = DefaultLifetime
	}

	entityID := cfg.EntityID
	if entityID == "" {
		entityID = cfg.BaseURL
	}

	// ── Build the TA's federation signing JWKS (public key only) ─────────────
	pubJWK, err := jwk.PublicKeyOf(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("federation/ta: derive public JWK: %w", err)
	}
	_ = pubJWK.Set(jwk.KeyIDKey, kid)
	_ = pubJWK.Set(jwk.AlgorithmKey, alg.String())
	_ = pubJWK.Set(jwk.KeyUsageKey, "sig")

	jwksBytes, err := json.Marshal(map[string]any{"keys": []jwk.Key{pubJWK}})
	if err != nil {
		return nil, fmt.Errorf("federation/ta: marshal JWKS: %w", err)
	}

	// ── Build federation_entity metadata with TA endpoints ────────────────────
	base := cfg.BaseURL
	fedMeta := &TAFedEntityMetadata{
		FedEntityMetadata: FedEntityMetadata{
			OrganizationName: cfg.OrganizationName,
			Contacts:         cfg.Contacts,
			LogoURI:          cfg.LogoURI,
			HomepageURI:      cfg.HomepageURI,
		},
		FederationFetchEndpoint:           base + "/federation/fetch",
		FederationListEndpoint:            base + "/federation/list",
		FederationTrustMarkEndpoint:       base + "/federation/trust-mark",
		FederationTrustMarkListEndpoint:   base + "/federation/trust-mark/list",
		FederationTrustMarkStatusEndpoint: base + "/federation/trust-mark/status",
		TrustMarkIssuers:                  cfg.TrustMarkIssuerMap,
	}

	now := time.Now()
	ec := taEntityConfiguration{
		Issuer:    entityID,
		Subject:   entityID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(lifetime).Unix(),
		JWKS:      json.RawMessage(jwksBytes),
		Metadata:  taEntityMetadata{FederationEntity: fedMeta},
	}

	payload, err := json.Marshal(ec)
	if err != nil {
		return nil, fmt.Errorf("federation/ta: marshal entity config: %w", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	_ = hdrs.Set("typ", "entity-statement+jwt")

	signed, err := jws.Sign(payload, jws.WithKey(alg, signer, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return nil, fmt.Errorf("federation/ta: sign entity config: %w", err)
	}
	return signed, nil
}

// BuildSubordinateStatement signs an Entity Statement about a subordinate
// entity (OIDF §9.2). The TA is the issuer; the sub is the subordinate.
//
//   - taEntityID   — the TA's entity ID (goes in "iss")
//   - sub          — the subordinate's entity ID (goes in "sub")
//   - subJWKS      — the subordinate's JWKS as raw JSON (from DB or fetched EC)
//   - metadata     — entity-type metadata (raw JSON), may be nil
//   - metaPolicy   — OIDF §5 metadata policy (raw JSON), may be nil
//   - trustMarkIDs — trust_mark_ids granted to this subordinate
//   - lifetime     — validity duration; 0 → DefaultLifetime
//   - fetchEndpoint — source_endpoint (the TA fetch endpoint URL)
func BuildSubordinateStatement(
	taEntityID, sub string,
	subJWKS, metadata, metaPolicy json.RawMessage,
	trustMarkIDs []string,
	trustMarks []json.RawMessage,
	lifetime time.Duration,
	fetchEndpoint string,
	signer crypto.Signer,
	alg jwa.SignatureAlgorithm,
	kid string,
) ([]byte, error) {
	if alg == "" {
		alg = jwa.PS256
	}
	if lifetime == 0 {
		lifetime = DefaultLifetime
	}

	now := time.Now()
	stmt := SubordinateStatement{
		Issuer:         taEntityID,
		Subject:        sub,
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(lifetime).Unix(),
		JWKS:           subJWKS,
		Metadata:       metadata,
		MetadataPolicy: metaPolicy,
		TrustMarkIDs:   trustMarkIDs,
		TrustMarks:     trustMarks,
		SourceEndpoint: fetchEndpoint,
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("federation/ta: marshal subordinate statement: %w", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	_ = hdrs.Set("typ", "entity-statement+jwt")

	signed, err := jws.Sign(payload, jws.WithKey(alg, signer, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return nil, fmt.Errorf("federation/ta: sign subordinate statement: %w", err)
	}
	return signed, nil
}
