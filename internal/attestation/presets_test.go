package attestation_test

import (
	"testing"

	"github.com/clavex-eu/clavex/internal/attestation"
)

func TestBuiltInPresetsNotEmpty(t *testing.T) {
	if len(attestation.BuiltInPresets) == 0 {
		t.Fatal("BuiltInPresets must not be empty")
	}
}

func TestGetPreset_KnownNames(t *testing.T) {
	for _, name := range []string{"hardware-key-only", "phishing-resistant", "fido2-certified"} {
		p := attestation.GetPreset(name)
		if p == nil {
			t.Errorf("GetPreset(%q) returned nil", name)
			continue
		}
		if p.Name != name {
			t.Errorf("GetPreset(%q).Name = %q, want %q", name, p.Name, name)
		}
		if p.Policy == nil {
			t.Errorf("GetPreset(%q).Policy is nil", name)
		}
		if p.DisplayName == "" {
			t.Errorf("GetPreset(%q).DisplayName is empty", name)
		}
		if p.Description == "" {
			t.Errorf("GetPreset(%q).Description is empty", name)
		}
	}
}

func TestGetPreset_Unknown(t *testing.T) {
	if p := attestation.GetPreset("nonexistent"); p != nil {
		t.Errorf("GetPreset(nonexistent) should return nil, got %+v", p)
	}
}

func TestHardwareKeyOnlyPreset_Policy(t *testing.T) {
	p := attestation.GetPreset("hardware-key-only")
	if p == nil {
		t.Fatal("hardware-key-only preset not found")
	}
	pol := p.Policy
	if !pol.Enabled {
		t.Error("hardware-key-only policy must be enabled")
	}
	if !pol.RequireAttestation {
		t.Error("hardware-key-only policy must require attestation")
	}
	if !pol.RequireMDSCertification {
		t.Error("hardware-key-only policy must require MDS certification")
	}
	if pol.MinCertificationLevel != "L2" {
		t.Errorf("hardware-key-only MinCertificationLevel = %q, want L2", pol.MinCertificationLevel)
	}
	if !pol.ExcludeRevokedAuthenticators {
		t.Error("hardware-key-only policy must exclude revoked authenticators")
	}
	// Must allow only usb and nfc transports (blocks "internal" / "hybrid")
	wantTransports := map[string]bool{"usb": true, "nfc": true}
	if len(pol.AllowedTransports) != 2 {
		t.Errorf("hardware-key-only AllowedTransports = %v, want [usb nfc]", pol.AllowedTransports)
	}
	for _, tr := range pol.AllowedTransports {
		if !wantTransports[tr] {
			t.Errorf("hardware-key-only unexpected transport %q", tr)
		}
	}
}

func TestHardwareKeyOnlyPreset_BlocksInternalTransport(t *testing.T) {
	p := attestation.GetPreset("hardware-key-only")
	if p == nil {
		t.Fatal("hardware-key-only preset not found")
	}
	// "internal" (Face ID, Windows Hello, Touch ID) must not be in AllowedTransports.
	for _, tr := range p.Policy.AllowedTransports {
		if tr == "internal" || tr == "hybrid" {
			t.Errorf("hardware-key-only policy must not include transport %q", tr)
		}
	}
}

func TestPhishingResistantPreset_Policy(t *testing.T) {
	p := attestation.GetPreset("phishing-resistant")
	if p == nil {
		t.Fatal("phishing-resistant preset not found")
	}
	pol := p.Policy
	if !pol.Enabled {
		t.Error("phishing-resistant policy must be enabled")
	}
	if !pol.RequireAttestation {
		t.Error("phishing-resistant policy must require attestation")
	}
	if !pol.RequireMDSCertification {
		t.Error("phishing-resistant policy must require MDS certification")
	}
	if pol.MinCertificationLevel != "L1" {
		t.Errorf("phishing-resistant MinCertificationLevel = %q, want L1", pol.MinCertificationLevel)
	}
	// AllowedTransports must be empty (any transport accepted)
	if len(pol.AllowedTransports) != 0 {
		t.Errorf("phishing-resistant AllowedTransports should be empty (any transport), got %v", pol.AllowedTransports)
	}
}

func TestFIDO2CertifiedPreset_Policy(t *testing.T) {
	p := attestation.GetPreset("fido2-certified")
	if p == nil {
		t.Fatal("fido2-certified preset not found")
	}
	pol := p.Policy
	if !pol.Enabled {
		t.Error("fido2-certified policy must be enabled")
	}
	if pol.MinCertificationLevel != "L1" {
		t.Errorf("fido2-certified MinCertificationLevel = %q, want L1", pol.MinCertificationLevel)
	}
}

func TestPresets_NoDuplicateNames(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range attestation.BuiltInPresets {
		if seen[p.Name] {
			t.Errorf("duplicate preset name: %q", p.Name)
		}
		seen[p.Name] = true
	}
}
