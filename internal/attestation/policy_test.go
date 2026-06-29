package attestation_test

import (
	"errors"
	"testing"

	"github.com/clavex-eu/clavex/internal/attestation"
	"github.com/go-webauthn/webauthn/protocol"
	walib "github.com/go-webauthn/webauthn/webauthn"
)

// makeCredential builds a minimal *walib.Credential for testing.
func makeCredential(format string, aaguidHex []byte, transports ...string) *walib.Credential {
	ts := make([]protocol.AuthenticatorTransport, len(transports))
	for i, t := range transports {
		ts[i] = protocol.AuthenticatorTransport(t)
	}
	return &walib.Credential{
		AttestationFormat: format,
		Authenticator: walib.Authenticator{
			AAGUID: aaguidHex,
		},
		Transport: ts,
	}
}

// appleAAGUID is a well-known Apple platform AAGUID (16 bytes).
var appleAAGUID = []byte{0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcc, 0x8a, 0xde, 0x60, 0x11, 0x77, 0xb8, 0xb3, 0xf6}

// yubiKeyAAGUID — YubiKey 5 NFC AAGUID.
var yubiKeyAAGUID = []byte{0x2f, 0xc0, 0x57, 0x9f, 0x81, 0x13, 0x47, 0xea, 0xb1, 0x16, 0xbb, 0x5a, 0x8d, 0xb9, 0x20, 0x2a}

func TestPolicy_Disabled(t *testing.T) {
	p := &attestation.Policy{Enabled: false, RequireAttestation: true}
	cred := makeCredential("none", make([]byte, 16))
	if err := p.EnforceCredential(cred); err != nil {
		t.Errorf("disabled policy should never reject, got: %v", err)
	}
}

func TestPolicy_NilPolicy(t *testing.T) {
	var p *attestation.Policy
	cred := makeCredential("none", make([]byte, 16))
	if err := p.EnforceCredential(cred); err != nil {
		t.Errorf("nil policy should never reject, got: %v", err)
	}
}

func TestPolicy_RequireAttestation_Accepts(t *testing.T) {
	p := &attestation.Policy{Enabled: true, RequireAttestation: true}
	cred := makeCredential("apple", appleAAGUID, "internal")
	if err := p.EnforceCredential(cred); err != nil {
		t.Errorf("expected acceptance for attested credential, got: %v", err)
	}
}

func TestPolicy_RequireAttestation_RejectsNone(t *testing.T) {
	p := &attestation.Policy{Enabled: true, RequireAttestation: true}
	cred := makeCredential("none", make([]byte, 16))
	err := p.EnforceCredential(cred)
	if err == nil {
		t.Fatal("expected rejection for format=none, got nil")
	}
	var pv *attestation.PolicyViolation
	if !errors.As(err, &pv) {
		t.Errorf("expected PolicyViolation, got %T: %v", err, err)
	}
	if !errors.Is(err, attestation.ErrPolicyViolation) {
		t.Errorf("expected ErrPolicyViolation in chain, got: %v", err)
	}
}

func TestPolicy_AllowedFormats_Accepts(t *testing.T) {
	p := &attestation.Policy{Enabled: true, AllowedFormats: []string{"apple", "packed"}}
	cred := makeCredential("apple", appleAAGUID, "internal")
	if err := p.EnforceCredential(cred); err != nil {
		t.Errorf("apple format should be allowed, got: %v", err)
	}
}

func TestPolicy_AllowedFormats_Rejects(t *testing.T) {
	p := &attestation.Policy{Enabled: true, AllowedFormats: []string{"apple", "packed"}}
	cred := makeCredential("tpm", yubiKeyAAGUID, "usb")
	err := p.EnforceCredential(cred)
	if err == nil {
		t.Fatal("expected rejection for disallowed format tpm")
	}
	var pv *attestation.PolicyViolation
	if !errors.As(err, &pv) {
		t.Errorf("expected PolicyViolation, got %T", err)
	}
}

func TestPolicy_AllowedAAGUIDs_Accepts(t *testing.T) {
	p := &attestation.Policy{
		Enabled:        true,
		AllowedAAGUIDs: []string{"fbfc3007-154e-4ecc-8ade-601177b8b3f6"},
	}
	cred := makeCredential("apple", appleAAGUID, "internal")
	if err := p.EnforceCredential(cred); err != nil {
		t.Errorf("apple AAGUID should be allowed, got: %v", err)
	}
}

func TestPolicy_AllowedAAGUIDs_Rejects(t *testing.T) {
	p := &attestation.Policy{
		Enabled:        true,
		AllowedAAGUIDs: []string{"fbfc3007-154e-4ecc-8ade-601177b8b3f6"},
	}
	cred := makeCredential("packed", yubiKeyAAGUID, "usb")
	err := p.EnforceCredential(cred)
	if err == nil {
		t.Fatal("expected rejection for unlisted AAGUID")
	}
	var pv *attestation.PolicyViolation
	if !errors.As(err, &pv) {
		t.Errorf("expected PolicyViolation, got %T", err)
	}
}

func TestPolicy_AllowedTransports_Accepts(t *testing.T) {
	p := &attestation.Policy{Enabled: true, AllowedTransports: []string{"internal", "hybrid"}}
	cred := makeCredential("apple", appleAAGUID, "internal")
	if err := p.EnforceCredential(cred); err != nil {
		t.Errorf("internal transport should be allowed, got: %v", err)
	}
}

func TestPolicy_AllowedTransports_AcceptsAnyMatch(t *testing.T) {
	// Credential has multiple transports; only one needs to match.
	p := &attestation.Policy{Enabled: true, AllowedTransports: []string{"hybrid"}}
	cred := makeCredential("packed", appleAAGUID, "internal", "hybrid")
	if err := p.EnforceCredential(cred); err != nil {
		t.Errorf("credential with hybrid transport should be allowed, got: %v", err)
	}
}

func TestPolicy_AllowedTransports_Rejects(t *testing.T) {
	p := &attestation.Policy{Enabled: true, AllowedTransports: []string{"internal"}}
	cred := makeCredential("packed", yubiKeyAAGUID, "usb", "nfc")
	err := p.EnforceCredential(cred)
	if err == nil {
		t.Fatal("expected rejection for disallowed transport")
	}
}

func TestPolicy_EmptyLists_AcceptAll(t *testing.T) {
	p := &attestation.Policy{
		Enabled:           true,
		AllowedFormats:    []string{},
		AllowedAAGUIDs:    []string{},
		AllowedTransports: []string{},
	}
	cred := makeCredential("tpm", yubiKeyAAGUID, "usb")
	if err := p.EnforceCredential(cred); err != nil {
		t.Errorf("empty allow-lists should accept anything, got: %v", err)
	}
}

func TestPolicy_CombinedRules_Rejects(t *testing.T) {
	p := &attestation.Policy{
		Enabled:           true,
		RequireAttestation: true,
		AllowedFormats:    []string{"apple"},
		AllowedAAGUIDs:    []string{"fbfc3007-154e-4ecc-8ade-601177b8b3f6"},
		AllowedTransports: []string{"internal"},
	}
	// Wrong format — should be rejected.
	cred := makeCredential("packed", appleAAGUID, "internal")
	if err := p.EnforceCredential(cred); err == nil {
		t.Error("packed format should be rejected when only apple is allowed")
	}
}

func TestExtractMetadata_Apple(t *testing.T) {
	cred := makeCredential("apple", appleAAGUID, "internal")
	aaguid, format, transports := attestation.ExtractMetadata(cred)

	wantAAGUID := "fbfc3007-154e-4ecc-8ade-601177b8b3f6"
	if aaguid != wantAAGUID {
		t.Errorf("AAGUID: want %q, got %q", wantAAGUID, aaguid)
	}
	if format != "apple" {
		t.Errorf("format: want %q, got %q", "apple", format)
	}
	if len(transports) != 1 || transports[0] != "internal" {
		t.Errorf("transports: want [internal], got %v", transports)
	}
}

func TestExtractMetadata_NilAAGUID(t *testing.T) {
	cred := makeCredential("none", nil)
	aaguid, format, _ := attestation.ExtractMetadata(cred)
	if aaguid != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("nil AAGUID should return zero UUID, got %q", aaguid)
	}
	if format != "none" {
		t.Errorf("empty format should be normalised to none, got %q", format)
	}
}
