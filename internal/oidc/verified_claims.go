package oidc

import (
	"encoding/json"
)

// IDAMetadata is stored in user.Metadata["_ida"] by each IdP callback
// at JIT-provision time. It holds the verification evidence that the OP
// can assert under the OpenID Connect for Identity Assurance 1.0 spec.
//
// Trust framework identifiers follow the OIDF eKYC-IDA WG registry:
//
//	eidas        — EU eIDAS notified eID system (covers CIE, SPID, eIDAS node)
//	it_spid      — Italian SPID (eIDAS-notified, substantial/high)
//	it_cie       — Italian CIE (eIDAS-notified, high)
//	de_bund      — German BundID (eIDAS-notified)
//	fr_idv       — French FranceConnect (national eIDAS-notified scheme)
//	nl_id        — Dutch DigiD (eIDAS-notified)
//	es_clave     — Spanish Cl@ve (eIDAS-notified)
type IDAMetadata struct {
	TrustFramework   string      `json:"trust_framework"`
	AssuranceLevel   string      `json:"assurance_level,omitempty"`
	VerificationTime string      `json:"time,omitempty"`
	Evidence         []Evidence  `json:"evidence,omitempty"`
}

// Evidence is a single item in the IDA verification evidence array.
// Type must be one of: "document", "electronic_record", "vouch",
// "electronic_signature" per the IDA-verified-claims schema.
type Evidence struct {
	Type   string          `json:"type"`
	Record *EvidenceRecord `json:"record,omitempty"`
}

// EvidenceRecord holds the source details for an "electronic_record" evidence item.
type EvidenceRecord struct {
	Type   string          `json:"type"`
	Source *RecordSource   `json:"source,omitempty"`
}

// RecordSource identifies the authoritative source of an electronic record.
type RecordSource struct {
	Name        string `json:"name,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
}

// IDAMetaKey is the key inside user.Metadata where IDA evidence is stored.
const IDAMetaKey = "_ida"

// idaMetaKey is kept for internal use to avoid breaking other internal callers.
const idaMetaKey = IDAMetaKey

// ExtractIDAMetadata parses the IDA evidence stored in user.Metadata["_ida"].
// Returns nil when no IDA data is present or the stored value is malformed.
func ExtractIDAMetadata(userMeta map[string]interface{}) *IDAMetadata {
	if userMeta == nil {
		return nil
	}
	raw, ok := userMeta[idaMetaKey]
	if !ok {
		return nil
	}
	// Support both map[string]interface{} (in-memory) and pre-marshalled JSON.
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var m IDAMetadata
	if err := json.Unmarshal(b, &m); err != nil || m.TrustFramework == "" {
		return nil
	}
	return &m
}

// IDAMetadataToMap converts an IDAMetadata to a map[string]interface{} suitable
// for storage in user.Metadata["_ida"].
func IDAMetadataToMap(m IDAMetadata) map[string]interface{} {
	b, _ := json.Marshal(m)
	var out map[string]interface{}
	_ = json.Unmarshal(b, &out)
	return out
}

// BuildVerifiedClaims constructs the verified_claims value to be included in a
// UserInfo or ID Token response per OpenID Connect for Identity Assurance 1.0.
//
// userMeta is the User.Metadata map. profileClaims is the map of standard OIDC
// profile claims already resolved for the user (given_name, family_name, etc.).
//
// reqVerifiedClaims is the requested verified_claims value from the claims
// parameter (may be nil, meaning "include everything"). If a non-nil request is
// provided the function filters the returned claims to only those present in the
// request, and omits the whole object when the trust_framework constraint cannot
// be satisfied.
//
// Returns nil when no IDA evidence is available.
func BuildVerifiedClaims(
	userMeta map[string]interface{},
	profileClaims map[string]any,
	reqVerifiedClaims json.RawMessage,
) map[string]any {
	ida := ExtractIDAMetadata(userMeta)
	if ida == nil {
		return nil
	}

	// If a request specifies trust_framework constraints, enforce them.
	if reqVerifiedClaims != nil {
		if !satisfiesTrustFrameworkConstraint(ida.TrustFramework, reqVerifiedClaims) {
			return nil
		}
	}

	verification := map[string]any{
		"trust_framework": ida.TrustFramework,
	}
	if ida.AssuranceLevel != "" {
		verification["assurance_level"] = ida.AssuranceLevel
	}
	if ida.VerificationTime != "" {
		verification["time"] = ida.VerificationTime
	}
	if len(ida.Evidence) > 0 {
		verification["evidence"] = ida.Evidence
	}

	// Determine which claims to include in verified_claims.claims.
	// If a request specifies certain claims, include only those; otherwise
	// include all available profile claims.
	requestedClaimNames := parseRequestedVerifiedClaimNames(reqVerifiedClaims)

	claims := map[string]any{}
	for k, v := range profileClaims {
		if k == "sub" || k == "email" || k == "email_verified" ||
			k == "groups" || k == "roles" || k == "updated_at" {
			continue // non-verified standard claims
		}
		if len(requestedClaimNames) > 0 {
			if _, wanted := requestedClaimNames[k]; !wanted {
				continue
			}
		}
		claims[k] = v
	}
	if len(claims) == 0 {
		return nil
	}

	return map[string]any{
		"verification": verification,
		"claims":       claims,
	}
}

// satisfiesTrustFrameworkConstraint returns true when the OP's trust_framework
// matches any value/values constraint in the requested verified_claims object.
// Returns true (pass-through) when no constraint is present.
func satisfiesTrustFrameworkConstraint(trustFramework string, rawReq json.RawMessage) bool {
	if rawReq == nil {
		return true
	}
	var req struct {
		Verification struct {
			TrustFramework *struct {
				Value  *string  `json:"value"`
				Values []string `json:"values"`
			} `json:"trust_framework"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(rawReq, &req); err != nil {
		return true // malformed request — don't reject
	}
	tf := req.Verification.TrustFramework
	if tf == nil {
		return true // no constraint
	}
	if tf.Value != nil && *tf.Value != trustFramework {
		return false
	}
	if len(tf.Values) > 0 {
		for _, v := range tf.Values {
			if v == trustFramework {
				return true
			}
		}
		return false
	}
	return true
}

// parseRequestedVerifiedClaimNames extracts the set of claim names requested in
// verified_claims.claims from a raw claims request value. Returns an empty map
// (not nil) when the request contains no verified_claims.claims sub-element,
// signalling "return all available claims".
func parseRequestedVerifiedClaimNames(rawReq json.RawMessage) map[string]struct{} {
	out := map[string]struct{}{}
	if rawReq == nil {
		return out
	}
	var req struct {
		Claims map[string]json.RawMessage `json:"claims"`
	}
	if err := json.Unmarshal(rawReq, &req); err != nil || req.Claims == nil {
		return out
	}
	for k := range req.Claims {
		out[k] = struct{}{}
	}
	return out
}
