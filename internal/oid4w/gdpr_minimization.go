package oid4w

// gdpr_minimization.go — GDPR Article 5(1)(c) data minimization enforcement.
//
// When a verifier registers an OID4VP presentation request (DCQL or
// Presentation Exchange), Clavex evaluates the requested claims against a
// privacy-impact ruleset.  Claims are classified as:
//
//   - Low sensitivity: age_over_18, place_of_birth_country, gender_code
//   - Medium sensitivity: given_name, family_name, date_of_birth, nationality
//   - High sensitivity: fiscal_code / tax_id, address, phone_number, email,
//                       face_image, document_number, iris_template
//
// Art.5(1)(c) (data minimisation) states that personal data must be adequate,
// relevant and limited to what is necessary in relation to the purpose.
//
// The check is non-blocking by default: the verifier receives a 201 response
// that includes a "gdpr_warnings" array.  When the verifier has a CISO webhook
// configured, Clavex asynchronously notifies the security team.

import (
	"fmt"
	"strings"
)

// ClaimSensitivity enumerates privacy-impact levels per GDPR Recitals 51-54
// and Art.4(1) (definition of personal data / special categories).
type ClaimSensitivity int

const (
	SensitivityLow    ClaimSensitivity = iota // pseudonymous / aggregate
	SensitivityMedium                         // ordinary personal data
	SensitivityHigh                           // strongly identifying / special category
)

// GDPRWarning is a single data-minimization finding returned to the verifier.
type GDPRWarning struct {
	// ClaimPath is the DCQL/JSONPath expression that triggered the warning.
	ClaimPath string `json:"claim_path"`
	// Sensitivity is the privacy-impact level of the claim.
	Sensitivity string `json:"sensitivity"` // "low"|"medium"|"high"
	// Article is the GDPR provision that applies.
	Article string `json:"article"`
	// Message is a human-readable description of the issue.
	Message string `json:"message"`
	// Alternative is a privacy-preserving claim that may satisfy the same purpose.
	// Empty when no alternative exists.
	Alternative string `json:"alternative,omitempty"`
}

// ── Claim catalogue ───────────────────────────────────────────────────────────

type claimRule struct {
	sensitivity ClaimSensitivity
	article     string
	message     string
	alternative string // empty = no known alternative
}

// sensitiveClaimRules maps canonical claim names (lower-case, normalised) to
// their privacy-impact rule.  JSONPath leaf names are extracted and matched
// against this map.
var sensitiveClaimRules = map[string]claimRule{
	// ── High sensitivity ─────────────────────────────────────────────────────
	"tax_id": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Fiscal / tax identifier is a unique national identifier that enables " +
			"cross-context tracking and is unnecessary for most verification purposes.",
		"age_over_18 or age_over_{N} derived claim",
	},
	"fiscal_code": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Italian codice fiscale is a full national identifier. " +
			"Request only the derived attribute needed for the use case.",
		"age_over_18",
	},
	"codice_fiscale": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Italian codice fiscale is a full national identifier. " +
			"Request only the derived attribute needed for the use case.",
		"age_over_18",
	},
	"document_number": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Document number uniquely identifies a physical document and enables tracking. " +
			"Use a derived proof of identity instead where possible.",
		"",
	},
	"face_image": {
		SensitivityHigh,
		"Art.9(1)",
		"Biometric data (face image) is a special category under GDPR Art.9. " +
			"Collection requires explicit consent and a legal basis under Art.9(2).",
		"",
	},
	"portrait": {
		SensitivityHigh,
		"Art.9(1)",
		"Biometric portrait is a special category under GDPR Art.9.",
		"",
	},
	"fingerprint_template": {
		SensitivityHigh,
		"Art.9(1)",
		"Fingerprint biometric data is a special category under GDPR Art.9.",
		"",
	},
	"iris_template": {
		SensitivityHigh,
		"Art.9(1)",
		"Iris biometric data is a special category under GDPR Art.9.",
		"",
	},
	"phone_number": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Phone number is a direct contact identifier. Request only if strictly required.",
		"",
	},
	"resident_address": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Full residential address is highly sensitive and rarely necessary. " +
			"Consider requesting only the country or postal-code prefix.",
		"address_country or place_of_birth",
	},
	"address": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Full address is highly sensitive. Consider requesting only the country or postal-code prefix.",
		"address_country",
	},
	"email": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Email address is a unique contact identifier. Request only if strictly required for the purpose.",
		"",
	},
	"email_address": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Email address is a unique contact identifier.",
		"",
	},
	"social_security_number": {
		SensitivityHigh,
		"Art.5(1)(c)",
		"Social security number is a full national identifier enabling cross-context tracking.",
		"age_over_18 or relevant derived attribute",
	},
	"health_id": {
		SensitivityHigh,
		"Art.9(1)",
		"Health identifier may expose health-related data, a special category under GDPR Art.9.",
		"",
	},

	// ── Medium sensitivity ───────────────────────────────────────────────────
	"family_name": {
		SensitivityMedium,
		"Art.5(1)(c)",
		"Full family name combined with other attributes may uniquely identify an individual. " +
			"Verify that the full name is necessary for the stated purpose.",
		"",
	},
	"given_name": {
		SensitivityMedium,
		"Art.5(1)(c)",
		"Given name is personal data. Verify that identity by name is necessary for this purpose.",
		"",
	},
	"date_of_birth": {
		SensitivityMedium,
		"Art.5(1)(c)",
		"Full date of birth is more specific than many use cases require. " +
			"Consider the derived claim age_over_18 or age_over_{N} instead.",
		"age_over_18",
	},
	"birth_date": {
		SensitivityMedium,
		"Art.5(1)(c)",
		"Full birth date is more specific than many use cases require. " +
			"Consider the derived claim age_over_18 instead.",
		"age_over_18",
	},
	"nationality": {
		SensitivityMedium,
		"Art.5(1)(c)",
		"Nationality can expose ethnic origin, a special category under Art.9. " +
			"Collect only if strictly necessary.",
		"",
	},
	"place_of_birth": {
		SensitivityMedium,
		"Art.5(1)(c)",
		"Place of birth may reveal ethnic or national origin. Collect only if necessary.",
		"place_of_birth_country",
	},
	"personal_number": {
		SensitivityMedium,
		"Art.5(1)(c)",
		"Personal number is a national identifier. Verify it is needed for this purpose.",
		"",
	},
}

// ── Public API ────────────────────────────────────────────────────────────────

// CheckDCQLMinimization analyses a DCQL query map and returns any data-
// minimization warnings.  The query is the value of the "credentials" map as
// described in OID4VP 1.0 Final §6.
func CheckDCQLMinimization(dcqlQuery map[string]interface{}) []GDPRWarning {
	if dcqlQuery == nil {
		return nil
	}
	var warnings []GDPRWarning

	// DCQL format: {"credentials": {"<id>": {"format":..., "claims": [...]}}}
	creds, _ := dcqlQuery["credentials"].(map[string]interface{})
	for credID, credRaw := range creds {
		credMap, _ := credRaw.(map[string]interface{})

		// DCQL §6.2: claims array contains {"path": [...], "values": [...]} objects.
		claimsRaw, _ := credMap["claims"].([]interface{})
		for _, claimRaw := range claimsRaw {
			claimObj, _ := claimRaw.(map[string]interface{})
			pathRaw, _ := claimObj["path"].([]interface{})
			for _, p := range pathRaw {
				if leaf, ok := p.(string); ok {
					if w, found := checkLeaf(leaf, fmt.Sprintf("credentials.%s.claims", credID)); found {
						warnings = append(warnings, w)
					}
				}
			}
		}
	}
	return warnings
}

// CheckPDMinimization analyses a Presentation Exchange v2 PresentationDefinition
// and returns any data-minimization warnings.
func CheckPDMinimization(pd *PresentationDefinition) []GDPRWarning {
	if pd == nil {
		return nil
	}
	var warnings []GDPRWarning
	for _, desc := range pd.InputDescriptors {
		if desc.Constraints == nil {
			continue
		}
		for _, field := range desc.Constraints.Fields {
			for _, path := range field.Path {
				// JSONPath: extract leaf name from expressions like "$.date_of_birth"
				leaf := jsonPathLeaf(path)
				if w, found := checkLeaf(leaf, fmt.Sprintf("input_descriptors[%s]", desc.ID)); found {
					warnings = append(warnings, w)
				}
			}
		}
	}
	return warnings
}

// CheckRawPDMinimization is a convenience wrapper for Presentation Definitions
// that have already been decoded into a map (e.g. from a DB JSONB column).
func CheckRawPDMinimization(raw map[string]interface{}) []GDPRWarning {
	if raw == nil {
		return nil
	}
	return CheckPDMinimization(parsePDFromMap(raw))
}

// parsePDFromMap converts a raw map into a typed PresentationDefinition so that
// CheckPDMinimization can be reused without a JSON round-trip.
func parsePDFromMap(raw map[string]interface{}) *PresentationDefinition {
	id, _ := raw["id"].(string)
	pd := &PresentationDefinition{ID: id}
	descsRaw, _ := raw["input_descriptors"].([]interface{})
	for _, dRaw := range descsRaw {
		dMap, _ := dRaw.(map[string]interface{})
		descID, _ := dMap["id"].(string)
		desc := InputDescriptor{ID: descID}
		if constraintsRaw, ok := dMap["constraints"].(map[string]interface{}); ok {
			co := &ConstraintObject{}
			fieldsRaw, _ := constraintsRaw["fields"].([]interface{})
			for _, fRaw := range fieldsRaw {
				fMap, _ := fRaw.(map[string]interface{})
				var fc FieldConstraint
				if paths, ok := fMap["path"].([]interface{}); ok {
					for _, p := range paths {
						if s, ok := p.(string); ok {
							fc.Path = append(fc.Path, s)
						}
					}
				}
				co.Fields = append(co.Fields, fc)
			}
			desc.Constraints = co
		}
		pd.InputDescriptors = append(pd.InputDescriptors, desc)
	}
	return pd
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// checkLeaf looks up the normalised leaf name in the claim catalogue.
// Returns (warning, true) when a rule matches.
func checkLeaf(leaf, location string) (GDPRWarning, bool) {
	key := strings.ToLower(strings.TrimSpace(leaf))
	// Strip leading $ / array notation from JSONPath.
	key = strings.TrimPrefix(key, "$")
	key = strings.TrimPrefix(key, ".")
	key = strings.Trim(key, "[]'\"")

	rule, ok := sensitiveClaimRules[key]
	if !ok {
		return GDPRWarning{}, false
	}

	var sensStr string
	switch rule.sensitivity {
	case SensitivityHigh:
		sensStr = "high"
	case SensitivityMedium:
		sensStr = "medium"
	default:
		sensStr = "low"
	}

	return GDPRWarning{
		ClaimPath:   location + "." + leaf,
		Sensitivity: sensStr,
		Article:     rule.article,
		Message:     rule.message,
		Alternative: rule.alternative,
	}, true
}

// jsonPathLeaf extracts the final attribute name from a JSONPath expression.
// "$.date_of_birth"  → "date_of_birth"
// "$['family_name']" → "family_name"
func jsonPathLeaf(path string) string {
	// Strip leading $.
	s := strings.TrimPrefix(path, "$.")
	s = strings.TrimPrefix(s, "$")
	// Handle bracket notation: $['fiscal_code'] → fiscal_code.
	if strings.HasPrefix(s, "['") && strings.HasSuffix(s, "']") {
		s = s[2 : len(s)-2]
	}
	// Take only the last segment after the last dot.
	if idx := strings.LastIndex(s, "."); idx >= 0 {
		s = s[idx+1:]
	}
	return s
}
