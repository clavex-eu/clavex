package attestation

// Preset is a named attestation policy template for common zero-trust scenarios.
// Presets let administrators apply a fully-configured Policy with a single API
// call, without needing to know AAGUID values or transport identifiers.
type Preset struct {
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	Description string  `json:"description"`
	Policy      *Policy `json:"policy"`
}

// BuiltInPresets is the ordered catalogue of built-in attestation policy presets.
var BuiltInPresets = []*Preset{
	hardwareKeyOnlyPreset(),
	phishingResistantPreset(),
	fido2CertifiedPreset(),
}

// GetPreset looks up a preset by name. Returns nil if not found.
func GetPreset(name string) *Preset {
	for _, p := range BuiltInPresets {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// hardwareKeyOnlyPreset requires a physical USB/NFC FIDO2 security key.
//
// Accepted: YubiKey 5/5C/5Ci, FIDO2 USB/NFC keys, Titan Key (USB/NFC).
// Rejected: Face ID, Touch ID, Windows Hello, Google Password Manager,
//
//	Android biometrics, hybrid (Bluetooth) passkeys.
func hardwareKeyOnlyPreset() *Preset {
	return &Preset{
		Name:        "hardware-key-only",
		DisplayName: "Physical security key only",
		Description: "Requires a physical USB or NFC hardware security key " +
			"(e.g. YubiKey, FIDO2 token). Blocks platform passkeys such as Face ID, " +
			"Windows Hello, Touch ID, and Google Password Manager. " +
			"Enforces FIDO2 L2+ MDS3 certification and excludes revoked authenticators.",
		Policy: &Policy{
			Enabled:                     true,
			RequireAttestation:          true,
			AllowedFormats:              []string{"fido-u2f", "packed", "tpm"},
			AllowedAAGUIDs:              []string{},
			AllowedTransports:           []string{"usb", "nfc"},
			RequireMDSCertification:     true,
			MinCertificationLevel:       "L2",
			ExcludeRevokedAuthenticators: true,
		},
	}
}

// phishingResistantPreset accepts any FIDO2 credential (hardware or managed
// platform) but requires device attestation and MDS3 L1+ certification.
//
// Accepted: hardware keys, Face ID (Apple), Windows Hello (TPM), managed Android.
// Rejected: unattested passkeys, consumer cloud-sync credentials without MDS3.
func phishingResistantPreset() *Preset {
	return &Preset{
		Name:        "phishing-resistant",
		DisplayName: "Phishing-resistant (hardware + managed platforms)",
		Description: "Accepts any FIDO2 credential including hardware keys and managed " +
			"platform authenticators (Face ID, Windows Hello), but requires device " +
			"attestation and FIDO2 L1+ MDS3 certification. " +
			"Blocks unatested passkeys and consumer cloud-sync credentials.",
		Policy: &Policy{
			Enabled:                     true,
			RequireAttestation:          true,
			AllowedFormats:              []string{"packed", "tpm", "android-key", "apple", "fido-u2f"},
			AllowedAAGUIDs:              []string{},
			AllowedTransports:           []string{},
			RequireMDSCertification:     true,
			MinCertificationLevel:       "L1",
			ExcludeRevokedAuthenticators: true,
		},
	}
}

// fido2CertifiedPreset requires any FIDO2 L1 certified authenticator without
// transport restrictions. Suitable for mixed-device enterprise environments.
func fido2CertifiedPreset() *Preset {
	return &Preset{
		Name:        "fido2-certified",
		DisplayName: "FIDO2 certified (any transport)",
		Description: "Accepts any FIDO2 L1+ certified authenticator regardless of transport. " +
			"Suitable for mixed-device environments where some users have hardware keys " +
			"and others use platform biometrics on managed devices.",
		Policy: &Policy{
			Enabled:                     true,
			RequireAttestation:          true,
			AllowedFormats:              []string{},
			AllowedAAGUIDs:              []string{},
			AllowedTransports:           []string{},
			RequireMDSCertification:     true,
			MinCertificationLevel:       "L1",
			ExcludeRevokedAuthenticators: true,
		},
	}
}
