package oid4w

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
)

// CredentialIssuerMetadata is serialised at
//
//	GET /:org_slug/.well-known/openid-credential-issuer
//
// per the OID4VCI Final specification §10.2.
// Note: token_endpoint is NOT present here — it is advertised in the
// OAuth/OIDC Authorization Server metadata per OID4VCI Final §11.2.
type CredentialIssuerMetadata struct {
	CredentialIssuer           string   `json:"credential_issuer"`
	AuthorizationServers       []string `json:"authorization_servers,omitempty"`
	CredentialEndpoint         string   `json:"credential_endpoint"`
	BatchCredentialEndpoint    string   `json:"batch_credential_endpoint,omitempty"`
	DeferredCredentialEndpoint string   `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint       string   `json:"notification_endpoint,omitempty"`
	// NonceEndpoint is the URL of the nonce endpoint per OID4VCI Final Appendix A.
	// Wallets POST to this endpoint (no body required) to obtain a fresh c_nonce
	// that MUST be included in the key proof JWT sent to the credential endpoint.
	NonceEndpoint string `json:"nonce_endpoint,omitempty"`
	// CredentialResponseEncryption advertises JWE encryption support for credential
	// responses. OID4VCI Final §10.2: when present, wallets can request that
	// credential responses be returned as encrypted JWEs.
	CredentialResponseEncryption *CredentialResponseEncryptionMeta `json:"credential_response_encryption,omitempty"`
	// CredentialRequestEncryption advertises support for encrypted credential
	// requests (OID4VCI-1FINAL-8.2).  Its schema is different from
	// credential_response_encryption: it carries a jwks JWK Set with the
	// issuer's public key(s) that the wallet uses to encrypt the request, not
	// alg/enc value lists.
	CredentialRequestEncryption       *CredentialRequestEncryptionMeta        `json:"credential_request_encryption,omitempty"`
	// BatchCredentialIssuance advertises support for sending multiple proofs in a
	// single credential request (OID4VCI Final §11.2). batch_size is the max number
	// of proofs (and thus credentials) the issuer will accept per request.
	BatchCredentialIssuance           *BatchCredentialIssuanceMeta            `json:"batch_credential_issuance,omitempty"`
	DisplayName                       []CredentialIssuerDisplay               `json:"display,omitempty"`
	CredentialConfigurationsSupported map[string]*CredentialConfigurationMeta `json:"credential_configurations_supported"`
}

// BatchCredentialIssuanceMeta is the batch_credential_issuance object in issuer metadata
// (OID4VCI Final §11.2). BatchSize is the maximum number of proofs/credentials per request.
type BatchCredentialIssuanceMeta struct {
	BatchSize int `json:"batch_size"`
}

// CredentialIssuerDisplay holds human-readable issuer branding.
type CredentialIssuerDisplay struct {
	Name   string `json:"name"`
	Locale string `json:"locale,omitempty"`
	Logo   *struct {
		URI     string `json:"uri"`
		AltText string `json:"alt_text,omitempty"`
	} `json:"logo,omitempty"`
}

// CredentialConfigurationMeta describes a single credential type the issuer supports.
// Follows OID4VCI Final §11.2.3.
type CredentialConfigurationMeta struct {
	// Format is the credential format identifier.
	// "dc+sd-jwt" for SD-JWT-VC per OID4VCI Final §E.2.
	Format string `json:"format"`
	// VCT is the Verifiable Credential Type URI (mandatory for dc+sd-jwt format).
	VCT string `json:"vct,omitempty"`
	// DocType is the ISO 18013-5 document type (mandatory for mso_mdoc format).
	DocType string `json:"doctype,omitempty"`
	// Scope is the OAuth2 scope required to request this credential type.
	Scope string `json:"scope,omitempty"`
	// CryptographicBindingMethodsSupported lists supported holder key binding methods.
	CryptographicBindingMethodsSupported []string `json:"cryptographic_binding_methods_supported,omitempty"`
	// CredentialSigningAlgValuesSupported lists supported signing algorithms.
	CredentialSigningAlgValuesSupported []string `json:"credential_signing_alg_values_supported,omitempty"`
	// ProofTypesSupported lists supported proof types (OID4VCI Final §11.2.3).
	ProofTypesSupported map[string]*ProofTypeMeta `json:"proof_types_supported,omitempty"`
	Display             []CredentialDisplay       `json:"display,omitempty"`
	// Claims describes each claim that can appear in this credential type.
	// OID4VCI Final §11.2.3 / Appendix E.2.2.3: array of claim path objects.
	Claims []*ClaimEntry `json:"claims,omitempty"`
	// CredentialMetadata is the EUDI reference wallet (openid4vci-kt) wrapper that
	// bundles display and claims. The library requires this field to be present in
	// dc+sd-jwt credential configurations; without it the metadata deserialization
	// fails silently and the issuance flow is aborted before AS discovery.
	// This is an EUDI-specific extension, not part of OID4VCI Final §11.2.3.
	CredentialMetadata *EUDICredentialMetadata `json:"credential_metadata,omitempty"`
	// VPFormatsSupported is advertised when the issuer requires a VP before
	// issuing this credential (VPR / OID4VCI §X / HAIP profile).
	// Omitted when RequireVP is false.
	VPFormatsSupported map[string]any `json:"vp_formats_supported,omitempty"`
	// PresentationDefinition is the Presentation Exchange v2 object advertised
	// in the metadata so the wallet knows upfront what to prepare. Omitted when
	// RequireVP is false.
	PresentationDefinition map[string]any `json:"presentation_definition,omitempty"`
}

// EUDICredentialMetadata is the EUDI reference issuer wrapper object used inside
// credential_configurations_supported entries. The openid4vci-kt library (used by
// the EUDI reference wallet) requires this field to be present for dc+sd-jwt configs.
type EUDICredentialMetadata struct {
	Display []CredentialDisplay `json:"display,omitempty"`
	Claims  []*ClaimEntry       `json:"claims,omitempty"`
}

// ProofTypeMeta describes supported algorithms for a proof type (OID4VCI Final §11.2.3).
type ProofTypeMeta struct {
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported"`
	// KeyAttestationsRequired, when non-nil, signals that the issuer REQUIRES
	// a key attestation claim in every proof JWT (OID4VCI / HAIP §x.y).
	// The conformance suite skips key-attestation tests when this field is absent.
	KeyAttestationsRequired *KeyAttestationRequiredMeta `json:"key_attestations_required,omitempty"`
}

// KeyAttestationRequiredMeta describes what hardware/user-auth properties must
// be attested by the wallet's key attestation JWT.
// Per OID4VCI-1FINAL-12.2.2, key_attestation_jwks MUST be present when
// key_attestations_required is used (VCICheckKeyAttestationJwksIfKeyAttestationIsRequired).
type KeyAttestationRequiredMeta struct {
	// KeyStorage lists accepted key storage environments, e.g. "hardware_key".
	KeyStorage []string `json:"key_storage,omitempty"`
	// UserAuthentication lists accepted user-auth mechanisms, e.g. "system_pin".
	UserAuthentication []string `json:"user_authentication,omitempty"`
	// KeyAttestationJWKS is the inline JWK Set that advertises the trusted
	// wallet-attester public keys used to verify key attestation JWTs.
	// Required by the OIDF conformance suite check
	// VCICheckKeyAttestationJwksIfKeyAttestationIsRequired.
	// An empty keys array is valid — it signals that the issuer does not
	// restrict which wallet attester signs the attestation.
	KeyAttestationJWKS *KeyAttestationJWKSMeta `json:"key_attestation_jwks,omitempty"`
}

// KeyAttestationJWKSMeta is a minimal JWK Set structure used inside
// key_attestations_required to advertise trusted wallet-attester keys.
type KeyAttestationJWKSMeta struct {
	// Keys holds the JWK objects of trusted key attestation signers.
	// May be empty when the issuer trusts any wallet attester.
	Keys []interface{} `json:"keys"`
}

// CredentialResponseEncryptionMeta describes the credential response
// encryption capabilities of the issuer (OID4VCI Final §10.2).
// When present, wallets MAY (or MUST if encryption_required=true) request
// encrypted credential responses.
type CredentialResponseEncryptionMeta struct {
	// AlgValuesSupported is the list of supported JWE "alg" algorithms for
	// key agreement / key transport (e.g. "ECDH-ES", "ECDH-ES+A128KW").
	AlgValuesSupported []string `json:"alg_values_supported"`
	// EncValuesSupported is the list of supported JWE "enc" content-encryption
	// algorithms (e.g. "A256GCM", "A128CBC-HS256").
	EncValuesSupported []string `json:"enc_values_supported"`
	// EncryptionRequired indicates whether the issuer mandates encryption.
	EncryptionRequired bool `json:"encryption_required"`
}

// CredentialRequestEncryptionMeta describes the credential request encryption
// capabilities of the issuer (OID4VCI-1FINAL-8.2 / VCICheckCredentialRequestEncryptionSupported).
// Schema (credential_issuer_metadata-1_0.json) requires jwks + enc_values_supported +
// encryption_required; additionalProperties=false means alg_values_supported is NOT allowed.
type CredentialRequestEncryptionMeta struct {
	// JWKS holds the issuer's public key(s) that wallets use to encrypt requests.
	// Each key MUST carry an explicit alg field naming an asymmetric JWE algorithm
	// (e.g. "RSA-OAEP-256") — VCICheckCredentialRequestEncryptionSupported rejects
	// keys whose getAlgorithm() is nil.
	JWKS *KeyAttestationJWKSMeta `json:"jwks"`
	// EncValuesSupported is the list of supported JWE content-encryption algorithms.
	EncValuesSupported []string `json:"enc_values_supported"`
	// EncryptionRequired indicates whether the issuer mandates request encryption.
	EncryptionRequired bool `json:"encryption_required"`
}

// CredentialDisplay holds human-readable credential type metadata.
type CredentialDisplay struct {
	Name            string `json:"name"`
	Locale          string `json:"locale,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// ClaimEntry describes a single claim in a credential configuration per
// OID4VCI Final Appendix E.2.2.3 (dc+sd-jwt). The path field is a non-empty
// array of strings identifying the claim in the issued Credential JSON.
type ClaimEntry struct {
	Path      []string            `json:"path"`
	Mandatory bool                `json:"mandatory,omitempty"`
	ValueType string              `json:"value_type,omitempty"`
	Display   []CredentialDisplay `json:"display,omitempty"`
}

// ClaimMeta is retained for potential future use but is no longer emitted
// in the credential issuer metadata (superseded by ClaimEntry for dc+sd-jwt).
type ClaimMeta struct {
	Mandatory bool                `json:"mandatory,omitempty"`
	ValueType string              `json:"value_type,omitempty"`
	Display   []CredentialDisplay `json:"display,omitempty"`
}

// CredentialConfigID derives a dot-free identifier for use as a
// CredentialConfigID derives the credential_configurations_supported map key
// from a VCT string. Two rules apply:
//
//  1. URL-based VCTs (have scheme + host): sanitise the full path, replacing
//     dots and slashes with underscores. Using only path.Base("…/v1") caused
//     collisions between all credential types whose path ends in the same segment.
//
//  2. Bare namespace identifiers (e.g. eu.europa.ec.eudi.pid.1): return verbatim.
//     EUDIW and IT-Wallet wallets look for this exact string as the map key.
// buildKeyAttestationsRequired returns a non-nil KeyAttestationRequiredMeta
// only when required is true.  Returning nil omits key_attestations_required
// from the JSON metadata entirely, which is the correct default for standard
// wallet compatibility (EUDI reference wallet aborts silently when it sees this
// field and cannot produce an attestation signed by the issuer's key).
func buildKeyAttestationsRequired(required bool) *KeyAttestationRequiredMeta {
	if !required {
		return nil
	}
	return &KeyAttestationRequiredMeta{
		KeyAttestationJWKS: &KeyAttestationJWKSMeta{
			Keys: []interface{}{},
		},
	}
}

func CredentialConfigID(vct string) string {
	if u, err := url.Parse(vct); err == nil && u.Scheme != "" && u.Host != "" {
		p := strings.TrimLeft(u.Path, "/")
		p = strings.ReplaceAll(p, ".", "_")
		p = strings.ReplaceAll(p, "/", "_")
		if p != "" {
			return p
		}
	}
	// Bare identifier — return as-is (dots are part of the standard name).
	return vct
}

// ── SD-JWT VC Type Metadata (draft-ietf-oauth-sd-jwt-vc §6) ────────────────────
//
// A credential's `vct`, when an HTTPS URL, MUST be dereferenceable to a Type
// Metadata document describing the type (name, claims, display). The OIDF
// conformance suite fetches it (VCIFetchSdJwtVcTypeMetadata) from the vct URL.

// TypeMetadata is an SD-JWT VC Type Metadata document.
type TypeMetadata struct {
	VCT         string                `json:"vct"`
	Name        string                `json:"name,omitempty"`
	Description string                `json:"description,omitempty"`
	Display     []TypeMetadataDisplay `json:"display,omitempty"`
	Claims      []TypeMetadataClaim   `json:"claims,omitempty"`
}

// TypeMetadataDisplay is one localised display entry for the credential type.
// The SD-JWT VC Type Metadata schema keys language by "locale" (not "lang").
type TypeMetadataDisplay struct {
	Locale      string `json:"locale"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// TypeMetadataClaim describes one claim of the credential type.
type TypeMetadataClaim struct {
	Path    []string                   `json:"path"`
	Display []TypeMetadataClaimDisplay `json:"display,omitempty"`
	// SD is the selective-disclosure disposition: "always" | "allowed" | "never".
	SD string `json:"sd,omitempty"`
}

// TypeMetadataClaimDisplay is one localised label for a claim.
type TypeMetadataClaimDisplay struct {
	Locale string `json:"locale"`
	Label  string `json:"label,omitempty"`
}

// BuildTypeMetadata constructs the SD-JWT VC Type Metadata document for a
// credential configuration, mirroring the name/claims published in the issuer
// metadata so the two are consistent.
func BuildTypeMetadata(cfg models.CredentialConfig) *TypeMetadata {
	tm := &TypeMetadata{
		VCT:     cfg.VCT,
		Name:    cfg.DisplayName,
		Display: []TypeMetadataDisplay{{Locale: "en", Name: cfg.DisplayName}},
	}
	if cfg.Description != nil {
		tm.Description = *cfg.Description
		tm.Display[0].Description = *cfg.Description
	}
	// Claims with selective-disclosure disposition matching the config.
	sd := "allowed"
	if !cfg.SelectiveDisclosure {
		sd = "never"
	}
	for claimName := range cfg.ClaimsMapping {
		tm.Claims = append(tm.Claims, TypeMetadataClaim{
			Path: []string{claimName},
			SD:   sd,
		})
	}
	return tm
}

// buildCredentialRequestEncryption returns the credential_request_encryption metadata
// only when conformanceMode is true. See BuildIssuerMetadata for the rationale.
func buildCredentialRequestEncryption(conformanceMode bool) *CredentialRequestEncryptionMeta {
	if !conformanceMode {
		return nil
	}
	return &CredentialRequestEncryptionMeta{
		JWKS:               &KeyAttestationJWKSMeta{Keys: []interface{}{}},
		EncValuesSupported: []string{"A256GCM", "A128CBC-HS256", "A256CBC-HS512"},
		EncryptionRequired: false,
	}
}

// BuildIssuerMetadata constructs the CredentialIssuerMetadata for an organisation.
// Follows OID4VCI Final specification §10.2 and §11.2.
// conformanceMode=true adds credential_request_encryption required by the OIDF
// conformance suite; leave false for standard wallet compatibility.
func BuildIssuerMetadata(baseURL, orgSlug string, configs []models.CredentialConfig, conformanceMode bool) *CredentialIssuerMetadata {
	issuerURL := fmt.Sprintf("%s/%s", baseURL, orgSlug)

	supported := make(map[string]*CredentialConfigurationMeta, len(configs))
	for _, cfg := range configs {
		if !cfg.IsActive {
			continue
		}
		// For mso_mdoc credential configs, build the metadata using the mso_mdoc format.
		if cfg.CredentialFormat == "mso_mdoc" {
			ns := cfg.VCT // namespace == docType for custom; standard ones handled in handler
			_ = ns
			msoMeta := &CredentialConfigurationMeta{
				Format:                               "mso_mdoc",
				DocType:                              cfg.VCT,
				Scope:                                CredentialConfigID(cfg.VCT),
				Display:                              []CredentialDisplay{{Name: cfg.DisplayName, Locale: "en"}},
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]*ProofTypeMeta{
					"jwt": {
						ProofSigningAlgValuesSupported: []string{"ES256"},
						// Advertise key_attestations_required only when the config
						// opts in (cfg.RequireKeyAttestation = true), same as the
						// dc+sd-jwt branch below.
						KeyAttestationsRequired: buildKeyAttestationsRequired(cfg.RequireKeyAttestation),
					},
				},
			}
			supported[CredentialConfigID(cfg.VCT)] = msoMeta
			continue
		}
		meta := &CredentialConfigurationMeta{
			Format: "dc+sd-jwt",
			// VCT is mandatory for dc+sd-jwt (OID4VCI Final §E.2.2).
			VCT: cfg.VCT,
			// Scope is required by HAIP §4.1: "The Credential Issuer MUST include a
			// scope for every Credential Configuration."  We derive it from the
			// credential configuration ID (the last path segment of the VCT URI).
			Scope:                                CredentialConfigID(cfg.VCT),
			CryptographicBindingMethodsSupported: []string{"jwk"},
			// proof_types_supported is mandatory in OID4VCI Final (§11.2.3).
			// VCIGenerateJwtProof.java in the OIDF suite only supports EC P-256 proofs
			// (it unconditionally calls ECKey.parse on every key in client_jwks).
			// ES256 must therefore be in the list; the conformance-oid4vci-wallet
			// client is registered with an EC P-256 key so the suite will find and use it.
			ProofTypesSupported: map[string]*ProofTypeMeta{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256", "PS256", "RS256"},
					// key_attestations_required is only advertised when the credential
					// config explicitly opts in (cfg.RequireKeyAttestation = true).
					// Standard wallets (e.g. EUDI reference wallet) abort silently when
					// they encounter this field and cannot satisfy the requirement.
					// Enable only for HAIP conformance testing or high-security issuance
					// scenarios that genuinely require wallet key attestation (HAIP §4.4).
					KeyAttestationsRequired: buildKeyAttestationsRequired(cfg.RequireKeyAttestation),
				},
			},
			Display: []CredentialDisplay{
				{Name: cfg.DisplayName, Locale: "en"},
			},
		}
		if cfg.Description != nil {
			_ = *cfg.Description
		}
		// Build claims metadata from the mapping keys.
		// OID4VCI Final Appendix E.2.2.3: claims is an array of path objects.
		if len(cfg.ClaimsMapping) > 0 {
			meta.Claims = make([]*ClaimEntry, 0, len(cfg.ClaimsMapping))
			for claimName := range cfg.ClaimsMapping {
				meta.Claims = append(meta.Claims, &ClaimEntry{
					Path: []string{claimName},
				})
			}
		}
		// Populate credential_metadata wrapper required by the EUDI reference wallet
		// (openid4vci-kt). The library's SdJwtVcCredential data class has credentialMetadata
		// as a non-nullable field; its absence causes silent deserialization failure.
		meta.CredentialMetadata = &EUDICredentialMetadata{
			Display: meta.Display,
			Claims:  meta.Claims,
		}
		// If this credential type requires a VP from the wallet, advertise the
		// supported VP formats and the presentation definition so wallets can
		// prepare the right credential upfront (OID4VCI / HAIP VPR).
		if cfg.RequireVP {
			meta.VPFormatsSupported = map[string]any{
				"vc+sd-jwt": map[string]any{
					"sd-jwt_alg_values": []string{"PS256", "RS256", "ES256"},
					"kb-jwt_alg_values": []string{"PS256", "RS256", "ES256"},
				},
			}
			if len(cfg.PresentationDefinitionVPR) > 0 {
				meta.PresentationDefinition = cfg.PresentationDefinitionVPR
			}
		}
		supported[CredentialConfigID(cfg.VCT)] = meta
	}

	// batch_credential_endpoint is intentionally omitted: the OID4VCI 1.0
	// credential issuer metadata JSON schema validated by the OIDF conformance
	// suite does not include this field (CheckForUnexpectedParametersInCredentialIssuerMetadata
	// flags it as an unknown property).  The batch credential endpoint still
	// functions at /:org_slug/oid4vci/batch-credential; it is just not advertised
	// in the discovery document.
	// Both credential_response_encryption and credential_request_encryption are
	// emitted together only in conformance mode. OID4VCI-1FINAL-8.2 /
	// VCIEnsureCredentialRequestEncryptionWhenResponseEncryptionOptional requires
	// that when credential_response_encryption is declared (even optional),
	// credential_request_encryption MUST also be present. Emitting only the former
	// triggers the warning. In production both are omitted to avoid the EUDI iOS
	// wallet (eudi-lib-ios-openid4vci-swift) JWEBuilderError that occurs when
	// credential_request_encryption is present.
	var encResponseMeta *CredentialResponseEncryptionMeta
	if conformanceMode {
		encResponseMeta = &CredentialResponseEncryptionMeta{
			AlgValuesSupported: []string{"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"},
			EncValuesSupported: []string{"A256GCM", "A128CBC-HS256", "A256CBC-HS512"},
			EncryptionRequired: false,
		}
	}
	return &CredentialIssuerMetadata{
		CredentialIssuer: issuerURL,
		// OID4VCI Final §11.2: when absent wallets must default to [credential_issuer],
		// but the EUDI reference wallet SDK (openid4vci-kt) treats the absent field as
		// a parse failure and silently aborts the issuance flow without ever attempting
		// AS discovery. Explicitly set it to [issuerURL] so the wallet can discover the
		// token endpoint via /.well-known/oauth-authorization-server/<org_slug>.
		AuthorizationServers:              []string{issuerURL},
		CredentialEndpoint:                fmt.Sprintf("%s/oid4vci/credential", issuerURL),
		DeferredCredentialEndpoint:        fmt.Sprintf("%s/oid4vci/deferred-credential", issuerURL),
		NotificationEndpoint:              fmt.Sprintf("%s/oid4vci/notification", issuerURL),
		NonceEndpoint:                     fmt.Sprintf("%s/oid4vci/nonce", issuerURL),
		CredentialResponseEncryption:      encResponseMeta,
		CredentialRequestEncryption:       buildCredentialRequestEncryption(conformanceMode),
		BatchCredentialIssuance:           &BatchCredentialIssuanceMeta{BatchSize: 3},
		CredentialConfigurationsSupported: supported,
	}
}
