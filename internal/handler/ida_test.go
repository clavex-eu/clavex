package handler

import (
	"testing"

	"github.com/clavex-eu/clavex/internal/oidc"
)

// ── SPID ──────────────────────────────────────────────────────────────────────

func TestSPIDIDAMetadata_TrustFramework(t *testing.T) {
	m := spidIDAMetadata("TINIT-RSSMRA80A01H501U", "substantial")
	if m.TrustFramework != "it_spid" {
		t.Errorf("trust_framework: want it_spid, got %q", m.TrustFramework)
	}
}

func TestSPIDIDAMetadata_AssuranceLevels(t *testing.T) {
	for _, lvl := range []string{"low", "substantial", "high"} {
		m := spidIDAMetadata("TINIT-XYZ", lvl)
		if m.AssuranceLevel != lvl {
			t.Errorf("assurance_level: want %q, got %q", lvl, m.AssuranceLevel)
		}
	}
}

func TestSPIDIDAMetadata_EvidenceType(t *testing.T) {
	m := spidIDAMetadata("TINIT-XYZ", "substantial")
	assertSingleEvidence(t, m, "electronic_record", "population_register", "ITA")
}

// ── CIE ───────────────────────────────────────────────────────────────────────

func TestCIEIDAMetadata_TrustFramework(t *testing.T) {
	m := cieIDAMetadata()
	if m.TrustFramework != "it_cie" {
		t.Errorf("trust_framework: want it_cie, got %q", m.TrustFramework)
	}
}

func TestCIEIDAMetadata_AlwaysHigh(t *testing.T) {
	m := cieIDAMetadata()
	if m.AssuranceLevel != "high" {
		t.Errorf("assurance_level: want high, got %q", m.AssuranceLevel)
	}
}

func TestCIEIDAMetadata_EvidenceType(t *testing.T) {
	m := cieIDAMetadata()
	assertSingleEvidence(t, m, "electronic_record", "ecard", "ITA")
}

// ── eIDAS ─────────────────────────────────────────────────────────────────────

func TestEIDASIDAMetadata_TrustFramework(t *testing.T) {
	m := eidasIDAMetadata("http://eidas.europa.eu/LoA/substantial", "DEU")
	if m.TrustFramework != "eidas" {
		t.Errorf("trust_framework: want eidas, got %q", m.TrustFramework)
	}
}

func TestEIDASIDAMetadata_LoAHigh(t *testing.T) {
	m := eidasIDAMetadata("http://eidas.europa.eu/LoA/high", "FRA")
	if m.AssuranceLevel != "high" {
		t.Errorf("assurance_level: want high, got %q", m.AssuranceLevel)
	}
}

func TestEIDASIDAMetadata_LoASubstantial(t *testing.T) {
	m := eidasIDAMetadata("http://eidas.europa.eu/LoA/substantial", "ESP")
	if m.AssuranceLevel != "substantial" {
		t.Errorf("assurance_level: want substantial, got %q", m.AssuranceLevel)
	}
}

func TestEIDASIDAMetadata_LoAUnknownDefaultsLow(t *testing.T) {
	m := eidasIDAMetadata("http://eidas.europa.eu/LoA/unknown", "NLD")
	if m.AssuranceLevel != "low" {
		t.Errorf("assurance_level: want low for unknown LoA, got %q", m.AssuranceLevel)
	}
}

func TestEIDASIDAMetadata_CountryCodeInEvidence(t *testing.T) {
	m := eidasIDAMetadata("http://eidas.europa.eu/LoA/high", "BEL")
	if len(m.Evidence) == 0 || m.Evidence[0].Record == nil || m.Evidence[0].Record.Source == nil {
		t.Fatal("expected evidence with record source")
	}
	if m.Evidence[0].Record.Source.CountryCode != "BEL" {
		t.Errorf("country_code: want BEL, got %q", m.Evidence[0].Record.Source.CountryCode)
	}
}

// ── BundID OIDC ───────────────────────────────────────────────────────────────

func TestBundIDOIDCIDAMetadata_TrustFramework(t *testing.T) {
	m := bundIDOIDCIDAMetadata("")
	if m.TrustFramework != "de_bund" {
		t.Errorf("trust_framework: want de_bund, got %q", m.TrustFramework)
	}
}

func TestBundIDOIDCIDAMetadata_DefaultSubstantial(t *testing.T) {
	m := bundIDOIDCIDAMetadata("")
	if m.AssuranceLevel != "substantial" {
		t.Errorf("assurance_level: want substantial, got %q", m.AssuranceLevel)
	}
}

func TestBundIDOIDCIDAMetadata_HighLoA(t *testing.T) {
	m := bundIDOIDCIDAMetadata("https://www.authenticationlevel.bund.de/ns/eID/internet")
	if m.AssuranceLevel != "high" {
		t.Errorf("assurance_level: want high, got %q", m.AssuranceLevel)
	}
}

func TestBundIDOIDCIDAMetadata_HighShorthand(t *testing.T) {
	m := bundIDOIDCIDAMetadata("high")
	if m.AssuranceLevel != "high" {
		t.Errorf("assurance_level: want high for 'high' shorthand, got %q", m.AssuranceLevel)
	}
}

func TestBundIDOIDCIDAMetadata_EvidenceCountryCode(t *testing.T) {
	m := bundIDOIDCIDAMetadata("")
	if len(m.Evidence) == 0 || m.Evidence[0].Record == nil || m.Evidence[0].Record.Source == nil {
		t.Fatal("expected evidence with record source")
	}
	if m.Evidence[0].Record.Source.CountryCode != "DEU" {
		t.Errorf("country_code: want DEU, got %q", m.Evidence[0].Record.Source.CountryCode)
	}
}

// ── BundID SAML ───────────────────────────────────────────────────────────────

func TestBundIDSAMLIDAMetadata_DefaultSubstantial(t *testing.T) {
	m := bundIDSAMLIDAMetadata("substantial")
	if m.AssuranceLevel != "substantial" {
		t.Errorf("assurance_level: want substantial, got %q", m.AssuranceLevel)
	}
}

func TestBundIDSAMLIDAMetadata_HighEIDASLoA(t *testing.T) {
	m := bundIDSAMLIDAMetadata("http://eidas.europa.eu/LoA/high")
	if m.AssuranceLevel != "high" {
		t.Errorf("assurance_level: want high, got %q", m.AssuranceLevel)
	}
}

func TestBundIDSAMLIDAMetadata_HighBundIDLoA(t *testing.T) {
	m := bundIDSAMLIDAMetadata("https://www.authenticationlevel.bund.de/ns/eID/internet")
	if m.AssuranceLevel != "high" {
		t.Errorf("assurance_level: want high for BundID eID URI, got %q", m.AssuranceLevel)
	}
}

func TestBundIDSAMLIDAMetadata_HighShorthand(t *testing.T) {
	m := bundIDSAMLIDAMetadata("high")
	if m.AssuranceLevel != "high" {
		t.Errorf("assurance_level: want high, got %q", m.AssuranceLevel)
	}
}

func TestBundIDSAMLIDAMetadata_LowLoA(t *testing.T) {
	m := bundIDSAMLIDAMetadata("low")
	if m.AssuranceLevel != "low" {
		t.Errorf("assurance_level: want low, got %q", m.AssuranceLevel)
	}
}

func TestBundIDSAMLIDAMetadata_LowEIDASLoA(t *testing.T) {
	m := bundIDSAMLIDAMetadata("http://eidas.europa.eu/LoA/low")
	if m.AssuranceLevel != "low" {
		t.Errorf("assurance_level: want low, got %q", m.AssuranceLevel)
	}
}

func TestBundIDSAMLIDAMetadata_UnknownDefaultsSubstantial(t *testing.T) {
	m := bundIDSAMLIDAMetadata("unknown-value")
	if m.AssuranceLevel != "substantial" {
		t.Errorf("assurance_level: want substantial for unknown value, got %q", m.AssuranceLevel)
	}
}

func TestBundIDSAMLIDAMetadata_TrustFramework(t *testing.T) {
	m := bundIDSAMLIDAMetadata("")
	if m.TrustFramework != "de_bund" {
		t.Errorf("trust_framework: want de_bund, got %q", m.TrustFramework)
	}
}

// ── FranceConnect ─────────────────────────────────────────────────────────────

func TestFranceConnectIDAMetadata_TrustFramework(t *testing.T) {
	m := franceConnectIDAMetadata()
	if m.TrustFramework != "fr_idv" {
		t.Errorf("trust_framework: want fr_idv, got %q", m.TrustFramework)
	}
}

func TestFranceConnectIDAMetadata_SubstantialLevel(t *testing.T) {
	m := franceConnectIDAMetadata()
	if m.AssuranceLevel != "substantial" {
		t.Errorf("assurance_level: want substantial, got %q", m.AssuranceLevel)
	}
}

func TestFranceConnectIDAMetadata_EvidenceCountryCode(t *testing.T) {
	m := franceConnectIDAMetadata()
	assertSingleEvidence(t, m, "electronic_record", "population_register", "FRA")
}

// ── DigiD ─────────────────────────────────────────────────────────────────────

func TestDigiDIDAMetadata_TrustFramework(t *testing.T) {
	m := digiDIDAMetadata()
	if m.TrustFramework != "nl_id" {
		t.Errorf("trust_framework: want nl_id, got %q", m.TrustFramework)
	}
}

func TestDigiDIDAMetadata_SubstantialLevel(t *testing.T) {
	m := digiDIDAMetadata()
	if m.AssuranceLevel != "substantial" {
		t.Errorf("assurance_level: want substantial, got %q", m.AssuranceLevel)
	}
}

func TestDigiDIDAMetadata_EvidenceCountryCode(t *testing.T) {
	m := digiDIDAMetadata()
	assertSingleEvidence(t, m, "electronic_record", "population_register", "NLD")
}

// ── Cl@ve ─────────────────────────────────────────────────────────────────────

func TestClaveIDAMetadata_TrustFramework(t *testing.T) {
	m := claveIDAMetadata()
	if m.TrustFramework != "es_clave" {
		t.Errorf("trust_framework: want es_clave, got %q", m.TrustFramework)
	}
}

func TestClaveIDAMetadata_SubstantialLevel(t *testing.T) {
	m := claveIDAMetadata()
	if m.AssuranceLevel != "substantial" {
		t.Errorf("assurance_level: want substantial, got %q", m.AssuranceLevel)
	}
}

func TestClaveIDAMetadata_EvidenceCountryCode(t *testing.T) {
	m := claveIDAMetadata()
	assertSingleEvidence(t, m, "electronic_record", "population_register", "ESP")
}

// ── itsme ─────────────────────────────────────────────────────────────────────

func TestItsmeIDAMetadata_TrustFramework(t *testing.T) {
	m := itsmeIDAMetadata("")
	if m.TrustFramework != "eidas" {
		t.Errorf("trust_framework: want eidas, got %q", m.TrustFramework)
	}
}

func TestItsmeIDAMetadata_DefaultSubstantial(t *testing.T) {
	m := itsmeIDAMetadata("")
	if m.AssuranceLevel != "substantial" {
		t.Errorf("assurance_level: want substantial, got %q", m.AssuranceLevel)
	}
}

func TestItsmeIDAMetadata_HighEIDASLoA(t *testing.T) {
	m := itsmeIDAMetadata("http://eidas.europa.eu/LoA/high")
	if m.AssuranceLevel != "high" {
		t.Errorf("assurance_level: want high, got %q", m.AssuranceLevel)
	}
}

func TestItsmeIDAMetadata_HighShorthand(t *testing.T) {
	m := itsmeIDAMetadata("high")
	if m.AssuranceLevel != "high" {
		t.Errorf("assurance_level: want high for 'high' shorthand, got %q", m.AssuranceLevel)
	}
}

func TestItsmeIDAMetadata_EvidenceCountryCode(t *testing.T) {
	m := itsmeIDAMetadata("")
	assertSingleEvidence(t, m, "electronic_record", "ecard", "BEL")
}

// ── Common invariants across all builders ────────────────────────────────────

func TestAllBuilders_NonEmptyTrustFramework(t *testing.T) {
	builders := []struct {
		name string
		fn   func() oidc.IDAMetadata
	}{
		{"cie", cieIDAMetadata},
		{"franceconnect", franceConnectIDAMetadata},
		{"digid", digiDIDAMetadata},
		{"clave", claveIDAMetadata},
	}
	for _, b := range builders {
		m := b.fn()
		if m.TrustFramework == "" {
			t.Errorf("%s: trust_framework must not be empty", b.name)
		}
		if m.AssuranceLevel == "" {
			t.Errorf("%s: assurance_level must not be empty", b.name)
		}
		if len(m.Evidence) == 0 {
			t.Errorf("%s: evidence must not be empty", b.name)
		}
	}
}

func TestAllBuilders_EvidenceHasRecord(t *testing.T) {
	all := []oidc.IDAMetadata{
		spidIDAMetadata("TINIT-X", "substantial"),
		cieIDAMetadata(),
		eidasIDAMetadata("http://eidas.europa.eu/LoA/high", "DEU"),
		bundIDOIDCIDAMetadata(""),
		bundIDSAMLIDAMetadata(""),
		franceConnectIDAMetadata(),
		digiDIDAMetadata(),
		claveIDAMetadata(),
		itsmeIDAMetadata(""),
	}
	for i, m := range all {
		if len(m.Evidence) == 0 {
			t.Errorf("builder[%d] has no evidence", i)
			continue
		}
		ev := m.Evidence[0]
		if ev.Type == "" {
			t.Errorf("builder[%d] evidence[0].type is empty", i)
		}
		if ev.Record == nil {
			t.Errorf("builder[%d] evidence[0].record is nil", i)
		}
	}
}

// ── helper ────────────────────────────────────────────────────────────────────

// assertSingleEvidence checks that m has exactly one evidence item with the
// expected type, record type, and country code.
func assertSingleEvidence(t *testing.T, m oidc.IDAMetadata, evidenceType, recordType, countryCode string) {
	t.Helper()
	if len(m.Evidence) != 1 {
		t.Fatalf("evidence length: want 1, got %d", len(m.Evidence))
	}
	ev := m.Evidence[0]
	if ev.Type != evidenceType {
		t.Errorf("evidence.type: want %q, got %q", evidenceType, ev.Type)
	}
	if ev.Record == nil {
		t.Fatal("evidence.record is nil")
	}
	if ev.Record.Type != recordType {
		t.Errorf("evidence.record.type: want %q, got %q", recordType, ev.Record.Type)
	}
	if ev.Record.Source == nil {
		t.Fatal("evidence.record.source is nil")
	}
	if ev.Record.Source.CountryCode != countryCode {
		t.Errorf("evidence.record.source.country_code: want %q, got %q", countryCode, ev.Record.Source.CountryCode)
	}
}
