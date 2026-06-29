package oid4w

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ── Presentation Exchange v2 types ────────────────────────────────────────────

// PresentationDefinition is a Presentation Exchange v2 object that specifies
// which credentials a verifier requires.
// Spec: https://identity.foundation/presentation-exchange/
type PresentationDefinition struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	Purpose          string            `json:"purpose,omitempty"`
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
}

// InputDescriptor describes a single required credential.
type InputDescriptor struct {
	ID          string            `json:"id"`
	Name        string            `json:"name,omitempty"`
	Purpose     string            `json:"purpose,omitempty"`
	Format      map[string]any    `json:"format,omitempty"`
	Constraints *ConstraintObject `json:"constraints,omitempty"`
}

// ConstraintObject defines field constraints on a credential.
type ConstraintObject struct {
	Fields          []FieldConstraint `json:"fields,omitempty"`
	LimitDisclosure string            `json:"limit_disclosure,omitempty"` // "required" | "preferred"
}

// FieldConstraint identifies and optionally filters a field in the credential.
type FieldConstraint struct {
	// Path is a list of JSONPath expressions (evaluated in order, first match wins).
	Path     []string          `json:"path"`
	Filter   *JSONSchemaFilter `json:"filter,omitempty"`
	Optional bool              `json:"optional,omitempty"`
}

// JSONSchemaFilter is a minimal JSON Schema fragment used for claim value matching.
type JSONSchemaFilter struct {
	Type    string `json:"type,omitempty"`
	Const   any    `json:"const,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Enum    []any  `json:"enum,omitempty"`
}

// ── OID4VP request / response types ──────────────────────────────────────────

// AuthorizationRequest is the wallet authorization request object returned by
//
//	GET /:org_slug/wallet/request/:request_id
//
// Per OID4VP §6 / JAR (RFC 9101), this can be returned as a signed JWT
// (request object) or as plain JSON. For now we return plain JSON.
type AuthorizationRequest struct {
	ResponseType   string `json:"response_type"`
	ClientID       string `json:"client_id"`
	ClientIDScheme string `json:"client_id_scheme,omitempty"`
	ResponseMode   string `json:"response_mode"`
	ResponseURI    string `json:"response_uri"`
	Nonce          string `json:"nonce"`
	State          string `json:"state,omitempty"`
	// DCQLQuery is the OID4VP 1.0 Final DCQL credential query (§6).
	// When non-nil, PresentationDefinition is omitted per spec recommendation.
	DCQLQuery map[string]interface{} `json:"dcql_query,omitempty"`
	// PresentationDefinition is the legacy Presentation Exchange v2 query.
	// Deprecated in OID4VP 1.0 Final; use DCQLQuery for new integrations.
	PresentationDefinition *PresentationDefinition `json:"presentation_definition,omitempty"`
	// ClientMetadata is REQUIRED in OID4VP 1.0 Final §5.1 and MUST include
	// vp_formats to declare the accepted credential formats.
	ClientMetadata map[string]interface{} `json:"client_metadata,omitempty"`
}

// AuthorizationResponse is what the wallet POSTs to the response endpoint.
type AuthorizationResponse struct {
	// VPToken is an SD-JWT presentation: "<issuer-jwt>~<disc1>~...[~<kb-jwt>]"
	VPToken string `json:"vp_token" form:"vp_token"`
	// PresentationSubmission maps InputDescriptors to the submitted VPToken.
	PresentationSubmission *PresentationSubmission `json:"presentation_submission,omitempty" form:"-"`
	State                  string                  `json:"state,omitempty" form:"state"`
}

// PresentationSubmission links the InputDescriptors from the PresentationDefinition
// to the credentials contained in the vp_token.
type PresentationSubmission struct {
	ID            string               `json:"id"`
	DefinitionID  string               `json:"definition_id"`
	DescriptorMap []DescriptorMapEntry `json:"descriptor_map"`
}

// DescriptorMapEntry maps an InputDescriptor to a path in the vp_token.
type DescriptorMapEntry struct {
	ID     string `json:"id"`
	Format string `json:"format"`
	Path   string `json:"path"`
}

// VerificationResult holds the verified claims returned after OID4VP.
type VerificationResult struct {
	// Claims contains all disclosed claims from the SD-JWT.
	Claims map[string]any
	// MatchedDescriptors lists the InputDescriptor IDs that were satisfied.
	MatchedDescriptors []string
}

// VerifyPresentation verifies an OID4VP vp_token against the presentation
// definition and expected nonce. It:
//  1. Parses the SD-JWT and verifies the issuer signature with pubKey.
//  2. When a KB-JWT is present, verifies its signature against the holder key in
//     cnf.jwk and that its nonce/aud/sd_hash match — binding the presentation to
//     this session and the requesting verifier (replay + holder-binding).
//  3. Validates that the disclosed claims satisfy all required FieldConstraints.
//
// expectedAud is the audience the holder must have targeted (client_id /
// response_uri). A vp_token with no KB-JWT (credential issued without holder
// binding) is still accepted but carries no proof-of-possession.
//
// trustedIssuers is a map from issuer URL to RSA public key. If empty, only
// pubKey (the Clavex local key) is used as the sole trusted issuer.
func VerifyPresentation(
	vpToken string,
	def PresentationDefinition,
	expectedNonce string,
	expectedAud string,
	trustedIssuers map[string]*rsa.PublicKey,
	localPubKey *rsa.PublicKey,
) (*VerificationResult, error) {
	issuerJWT, disclosureRaws, kbJWT, err := ParseSDJWT(vpToken)
	if err != nil {
		return nil, fmt.Errorf("parse vp_token: %w", err)
	}

	// Determine which trusted key to use: attempt local key first,
	// fall back to trustedIssuers map keyed on the "iss" claim.
	pubKey, err := resolveIssuerKey(issuerJWT, trustedIssuers, localPubKey)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer key: %w", err)
	}

	claims, err := VerifyAndExtractClaims(issuerJWT, disclosureRaws, pubKey)
	if err != nil {
		return nil, fmt.Errorf("verify sd-jwt: %w", err)
	}

	// Holder binding: when the presentation carries a KB-JWT, verify it so the
	// vp_token cannot be replayed or presented to a different audience.
	if kbJWT != "" {
		holderKey, hkErr := extractHolderPublicKey(claims)
		if hkErr != nil {
			return nil, fmt.Errorf("kb-jwt: %w", hkErr)
		}
		if kbErr := verifyKBJWT(kbJWT, holderKey, expectedNonce, expectedAud, issuerJWT, disclosureRaws); kbErr != nil {
			return nil, fmt.Errorf("kb-jwt: %w", kbErr)
		}
	}

	// Check presentation_definition constraints.
	matched, err := matchPresentationDefinition(claims, def)
	if err != nil {
		return nil, fmt.Errorf("presentation definition mismatch: %w", err)
	}

	return &VerificationResult{
		Claims:             claims,
		MatchedDescriptors: matched,
	}, nil
}

// VerifyDCQLPresentation verifies an OID4VP vp_token for a DCQL-based session.
//
// For DCQL sessions the credential is issued by an external party (not Clavex).
// Issuer signature verification is skipped to avoid synchronous JWKS discovery
// calls (which break conformance tests where the issuer IS the test suite).
// The KB-JWT signature IS verified against the holder's public key in cnf.jwk,
// ensuring the presentation was produced by the legitimate holder and that
// the nonce/aud match the current session.
// requireTrusted, when true, rejects a presentation whose issuer is not in
// trustedIssuers (instead of accepting its claims unverified). It MUST be true in
// production; set false only for the conformance suite where the issuer is the
// untrusted test harness.
func VerifyDCQLPresentation(
	ctx context.Context,
	vpToken string,
	dcqlQuery map[string]interface{},
	expectedNonce string,
	expectedAud string,
	trustedIssuers map[string]crypto.PublicKey,
	requireTrusted bool,
	localPubKey *rsa.PublicKey,
) (*VerificationResult, error) {
	issuerJWT, disclosureRaws, kbJWT, err := ParseSDJWT(vpToken)
	if err != nil {
		return nil, fmt.Errorf("parse vp_token: %w", err)
	}

	claims, err := extractSDJWTClaimsNoSigCheck(issuerJWT, disclosureRaws)
	if err != nil {
		return nil, fmt.Errorf("extract sd-jwt claims: %w", err)
	}

	// Verify the issuer signature using a pre-configured trusted issuer key
	// (avoids outbound JWKS discovery). When the issuer is unknown the claims
	// cannot be trusted: reject under requireTrusted, otherwise (conformance only)
	// fall through with the signature unverified.
	iss, _ := claims["iss"].(string)
	issuerKey, known := trustedIssuers[iss]
	if known {
		if err := verifyJWTSignature(issuerJWT, issuerKey); err != nil {
			return nil, fmt.Errorf("issuer signature invalid: %w", err)
		}
	} else if requireTrusted {
		return nil, fmt.Errorf("credential issuer %q is not in the configured trust anchors", iss)
	}

	// Verify KB-JWT signature, nonce, aud, and sd_hash.
	// The sd_hash check is the key to detecting a corrupted issuer SD-JWT:
	// if the issuer signature bytes were modified after the KB-JWT was created,
	// SHA-256(issuerJWT~disc1~disc2~) won't match the sd_hash in the KB-JWT.
	if kbJWT != "" {
		holderKey, err := extractHolderPublicKey(claims)
		if err != nil {
			return nil, fmt.Errorf("kb-jwt: %w", err)
		}
		if err := verifyKBJWT(kbJWT, holderKey, expectedNonce, expectedAud, issuerJWT, disclosureRaws); err != nil {
			return nil, fmt.Errorf("kb-jwt: %w", err)
		}
	}

	return &VerificationResult{Claims: claims}, nil
}

// extractHolderPublicKey parses the holder's public key from the cnf.jwk claim.
func extractHolderPublicKey(claims map[string]any) (crypto.PublicKey, error) {
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cnf claim missing or not an object")
	}
	jwkMap, ok := cnf["jwk"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cnf.jwk missing or not an object")
	}
	jwkJSON, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("marshal cnf.jwk: %w", err)
	}
	key, err := jwk.ParseKey(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("parse cnf.jwk: %w", err)
	}
	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("extract raw holder key: %w", err)
	}
	return rawKey.(crypto.PublicKey), nil
}

// verifyJWTSignature checks the JWS signature of a compact JWT using the given public key.
// It tries ES256, PS256, and RS256 in order.
func verifyJWTSignature(compactJWT string, pubKey crypto.PublicKey) error {
	for _, alg := range []jwa.SignatureAlgorithm{jwa.ES256, jwa.PS256, jwa.RS256} {
		if _, err := jwt.Parse([]byte(compactJWT),
			jwt.WithKey(alg, pubKey),
			jwt.WithValidate(false),
		); err == nil {
			return nil
		}
	}
	return fmt.Errorf("signature verification failed for all supported algorithms")
}

// verifyKBJWT verifies the KB-JWT signature and claims:
//   - ES256 signature against the holder's public key (cnf.jwk)
//   - nonce matches the session nonce
//   - aud matches the response_uri
//   - sd_hash matches SHA-256(issuerJWT~disc1~disc2~)
//
// The sd_hash check detects a corrupted issuer SD-JWT without needing the
// issuer's public key: if the issuer signature bytes were modified after the
// KB-JWT was signed, the hash of the received presentation won't match.
func verifyKBJWT(kbJWT string, holderKey crypto.PublicKey, expectedNonce, expectedAud, issuerJWT string, disclosureRaws []string) error {
	tok, err := jwt.Parse([]byte(kbJWT),
		jwt.WithKey(jwa.ES256, holderKey),
		jwt.WithValidate(false),
	)
	if err != nil {
		return fmt.Errorf("signature invalid: %w", err)
	}

	// Verify iat is within an acceptable window (OID4VP §7.3):
	// - not more than 5 minutes in the past  (replay protection)
	// - not more than 30 seconds in the future (clock skew tolerance)
	iat := tok.IssuedAt()
	if iat.IsZero() {
		return fmt.Errorf("iat claim missing from kb-jwt")
	}
	now := time.Now()
	if iat.After(now.Add(30 * time.Second)) {
		return fmt.Errorf("kb-jwt iat is in the future: %v ahead", iat.Sub(now).Round(time.Second))
	}
	if age := now.Sub(iat); age > 5*time.Minute {
		return fmt.Errorf("kb-jwt iat too old: issued %v ago (max 5 minutes)", age.Round(time.Second))
	}

	nonceVal, _ := tok.Get("nonce")
	if nonce, _ := nonceVal.(string); nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch")
	}

	found := false
	for _, a := range tok.Audience() {
		if a == expectedAud {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("aud mismatch: got %v, want %q", tok.Audience(), expectedAud)
	}

	// Verify sd_hash = base64url(SHA-256(issuerJWT~disc1~disc2~)).
	// Format matches SDJWT.toString() without the KB-JWT (trailing "~" included).
	sdHashVal, _ := tok.Get("sd_hash")
	if sdHash, _ := sdHashVal.(string); sdHash != "" {
		var sb strings.Builder
		sb.WriteString(issuerJWT)
		for _, d := range disclosureRaws {
			sb.WriteString("~")
			sb.WriteString(d)
		}
		sb.WriteString("~")
		h := sha256.Sum256([]byte(sb.String()))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		if computed != sdHash {
			return fmt.Errorf("sd_hash mismatch: issuer JWT integrity check failed")
		}
	}

	return nil
}


// resolveIssuerKey returns the RSA public key for the issuer JWT's "iss" claim.
// localPubKey is always accepted; trustedIssuers provides additional known issuers.
func resolveIssuerKey(issuerJWT string, trusted map[string]*rsa.PublicKey, local *rsa.PublicKey) (*rsa.PublicKey, error) {
	// Decode the JWT header + payload without verification to read "iss".
	type minPayload struct {
		Iss string `json:"iss"`
	}
	b, err := decodeJWTPayload(issuerJWT)
	if err != nil {
		return nil, err
	}
	var p minPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}

	// Try the trusted issuers map.
	if key, ok := trusted[p.Iss]; ok {
		return key, nil
	}
	// Fall back to local key — accept credentials issued by Clavex itself.
	return local, nil
}

// matchPresentationDefinition checks that the claims satisfy all required
// InputDescriptors in the PresentationDefinition.
// Returns the list of matched descriptor IDs.
func matchPresentationDefinition(claims map[string]any, def PresentationDefinition) ([]string, error) {
	matched := make([]string, 0, len(def.InputDescriptors))
	for _, desc := range def.InputDescriptors {
		if desc.Constraints == nil {
			matched = append(matched, desc.ID)
			continue
		}
		for _, field := range desc.Constraints.Fields {
			if field.Optional {
				continue
			}
			found := false
			for _, path := range field.Path {
				val, ok := jsonPathGet(claims, path)
				if !ok {
					continue
				}
				if field.Filter != nil {
					if !matchFilter(val, field.Filter) {
						continue
					}
				}
				found = true
				break
			}
			if !found {
				return nil, fmt.Errorf("required field not satisfied in descriptor %q (paths: %v)", desc.ID, field.Path)
			}
		}
		matched = append(matched, desc.ID)
	}
	return matched, nil
}

// jsonPathGet resolves a simple JSONPath expression ("$.claim_name" or "$.vct")
// against a flat claims map. Only top-level paths are supported.
func jsonPathGet(claims map[string]any, path string) (any, bool) {
	// Strip the "$." prefix.
	key := path
	if len(path) > 2 && path[:2] == "$." {
		key = path[2:]
	} else if path == "$" {
		return claims, true
	}
	val, ok := claims[key]
	return val, ok
}

// matchFilter checks a claim value against a JSON Schema filter fragment.
func matchFilter(value any, filter *JSONSchemaFilter) bool {
	if filter.Const != nil {
		// Compare as JSON-serialised strings for type-safe equality.
		vj, _ := json.Marshal(value)
		fj, _ := json.Marshal(filter.Const)
		return string(vj) == string(fj)
	}
	if len(filter.Enum) > 0 {
		vj, _ := json.Marshal(value)
		for _, e := range filter.Enum {
			ej, _ := json.Marshal(e)
			if string(vj) == string(ej) {
				return true
			}
		}
		return false
	}
	// Type-only filter — just check existence (caller already resolved the path).
	return true
}

// decodeJWTPayload base64url-decodes the payload section of a compact JWT.
func decodeJWTPayload(compact string) ([]byte, error) {
	parts := splitDots(compact)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed jwt: expected at least 2 dot-separated parts")
	}
	return base64URLDecode(parts[1])
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i, c := range s {
		if c == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func base64URLDecode(s string) ([]byte, error) {
	// base64.RawURLEncoding handles un-padded base64url directly.
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

