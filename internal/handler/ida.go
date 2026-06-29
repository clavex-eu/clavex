package handler

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
)

// storeIDAMetadata asynchronously merges IDA (Identity Assurance) evidence
// into the user's metadata. Called from IdP callbacks after JIT provisioning
// or on every successful login to keep assurance data current.
//
// This implements OpenID Connect for Identity Assurance 1.0 §5 — the OP
// stores the verification evidence so it can be included in userinfo and
// ID token responses when requested via the claims parameter.
func storeIDAMetadata(users *repository.UserRepository, userID uuid.UUID, m oidc.IDAMetadata) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		patch := map[string]interface{}{
			oidc.IDAMetaKey: oidc.IDAMetadataToMap(m),
		}
		_ = users.MergeMetadata(ctx, userID, patch)
	}()
}

// ── Per-IdP IDA metadata builders ────────────────────────────────────────────
// Each function produces an IDAMetadata value using the trust_framework
// identifiers maintained by the OIDF eKYC-IDA WG:
//   https://openid.net/wg/ekyc-ida/identifiers/

// spidIDAMetadata returns IDA evidence for an Italian SPID login.
// evidence: electronic_record of type "population_register" (Italian ANPR).
func spidIDAMetadata(fiscalNumber, assuranceLevel string) oidc.IDAMetadata {
	return oidc.IDAMetadata{
		TrustFramework: "it_spid",
		AssuranceLevel: assuranceLevel,
		Evidence: []oidc.Evidence{{
			Type: "electronic_record",
			Record: &oidc.EvidenceRecord{
				Type: "population_register",
				Source: &oidc.RecordSource{
					Name:        "ANPR",
					Country:     "Italia",
					CountryCode: "ITA",
				},
			},
		}},
	}
}

// cieIDAMetadata returns IDA evidence for an Italian CIE login.
// CIE is always eIDAS High; evidence is the chip-enabled identity card.
func cieIDAMetadata() oidc.IDAMetadata {
	return oidc.IDAMetadata{
		TrustFramework: "it_cie",
		AssuranceLevel: "high",
		Evidence: []oidc.Evidence{{
			Type: "electronic_record",
			Record: &oidc.EvidenceRecord{
				Type: "ecard",
				Source: &oidc.RecordSource{
					Name:        "Ministero dell'Interno",
					Country:     "Italia",
					CountryCode: "ITA",
				},
			},
		}},
	}
}

// eidasIDAMetadata maps an eIDAS LoA URI to an IDA assurance_level value.
// trust_framework is always "eidas" for eIDAS-notified systems.
func eidasIDAMetadata(loaURI, countryCode string) oidc.IDAMetadata {
	level := "low"
	switch loaURI {
	case "http://eidas.europa.eu/LoA/high":
		level = "high"
	case "http://eidas.europa.eu/LoA/substantial":
		level = "substantial"
	}
	return oidc.IDAMetadata{
		TrustFramework: "eidas",
		AssuranceLevel: level,
		Evidence: []oidc.Evidence{{
			Type: "electronic_record",
			Record: &oidc.EvidenceRecord{
				Type: "ecard",
				Source: &oidc.RecordSource{
					CountryCode: countryCode,
				},
			},
		}},
	}
}

// bundIDOIDCIDAMetadata returns IDA evidence for a BundID (OIDC) login.
// assuranceLevel is the acr_values string used in the request (may be a BundID LoA URI).
func bundIDOIDCIDAMetadata(assuranceLevel string) oidc.IDAMetadata {
	level := "substantial"
	if assuranceLevel != "" && (assuranceLevel == "https://www.authenticationlevel.bund.de/ns/eID/internet" ||
		assuranceLevel == "high") {
		level = "high"
	}
	return oidc.IDAMetadata{
		TrustFramework: "de_bund",
		AssuranceLevel: level,
		Evidence: []oidc.Evidence{{
			Type: "electronic_record",
			Record: &oidc.EvidenceRecord{
				Type: "population_register",
				Source: &oidc.RecordSource{
					Name:        "Bundesrepublik Deutschland",
					CountryCode: "DEU",
				},
			},
		}},
	}
}

// bundIDSAMLIDAMetadata returns IDA evidence for a BundID (SAML) login.
// loaStr is the LoA attribute from the BundID SAML assertion (eIDAS LoA URI or "low"/"substantial"/"high").
func bundIDSAMLIDAMetadata(loaStr string) oidc.IDAMetadata {
	level := "substantial"
	switch loaStr {
	case "http://eidas.europa.eu/LoA/high",
		"https://www.authenticationlevel.bund.de/ns/eID/internet",
		"high":
		level = "high"
	case "http://eidas.europa.eu/LoA/low",
		"https://www.authenticationlevel.bund.de/ns/eID/low",
		"low":
		level = "low"
	}
	return oidc.IDAMetadata{
		TrustFramework: "de_bund",
		AssuranceLevel: level,
		Evidence: []oidc.Evidence{{
			Type: "electronic_record",
			Record: &oidc.EvidenceRecord{
				Type: "population_register",
				Source: &oidc.RecordSource{
					Name:        "Bundesrepublik Deutschland",
					CountryCode: "DEU",
				},
			},
		}},
	}
}

// franceConnectIDAMetadata returns IDA evidence for a FranceConnect login.
func franceConnectIDAMetadata() oidc.IDAMetadata {
	return oidc.IDAMetadata{
		TrustFramework: "fr_idv",
		AssuranceLevel: "substantial",
		Evidence: []oidc.Evidence{{
			Type: "electronic_record",
			Record: &oidc.EvidenceRecord{
				Type: "population_register",
				Source: &oidc.RecordSource{
					Name:        "Direction interministérielle du numérique",
					CountryCode: "FRA",
				},
			},
		}},
	}
}

// digiDIDAMetadata returns IDA evidence for a DigiD login.
func digiDIDAMetadata() oidc.IDAMetadata {
	return oidc.IDAMetadata{
		TrustFramework: "nl_id",
		AssuranceLevel: "substantial",
		Evidence: []oidc.Evidence{{
			Type: "electronic_record",
			Record: &oidc.EvidenceRecord{
				Type: "population_register",
				Source: &oidc.RecordSource{
					Name:        "Rijksdienst voor Identiteitsgegevens",
					CountryCode: "NLD",
				},
			},
		}},
	}
}

// claveIDAMetadata returns IDA evidence for a Cl@ve login.
func claveIDAMetadata() oidc.IDAMetadata {
	return oidc.IDAMetadata{
		TrustFramework: "es_clave",
		AssuranceLevel: "substantial",
		Evidence: []oidc.Evidence{{
			Type: "electronic_record",
			Record: &oidc.EvidenceRecord{
				Type: "population_register",
				Source: &oidc.RecordSource{
					Name:        "Secretaría de Estado de Digitalización e IA",
					CountryCode: "ESP",
				},
			},
		}},
	}
}

// itsmeIDAMetadata returns IDA evidence for an itsme login.
// acrValues is the acr_values used in the request.
func itsmeIDAMetadata(acrValues string) oidc.IDAMetadata {
	level := "substantial"
	if acrValues == "http://eidas.europa.eu/LoA/high" || acrValues == "high" {
		level = "high"
	}
	return oidc.IDAMetadata{
		TrustFramework: "eidas",
		AssuranceLevel: level,
		Evidence: []oidc.Evidence{{
			Type: "electronic_record",
			Record: &oidc.EvidenceRecord{
				Type: "ecard",
				Source: &oidc.RecordSource{
					Name:        "itsme",
					CountryCode: "BEL",
				},
			},
		}},
	}
}
