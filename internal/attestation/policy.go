// Package attestation implements WebAuthn attestation policy enforcement for
// enterprise zero-trust passkey enrollment.
//
// When an org configures an AttestationPolicy, every passkey/WebAuthn
// registration is checked against that policy before the credential is
// persisted.  Registrations that violate the policy are rejected with
// a 422 Unprocessable Entity and the credential is never stored.
//
// # Policy fields
//
//   - Enabled           — master switch; when false the policy is skipped
//   - RequireAttestation — when true, credentials with format="none" are rejected
//   - AllowedFormats     — if non-empty, only listed formats are accepted
//                          (e.g. ["packed","tpm","apple","android-key"])
//   - AllowedAAGUIDs     — if non-empty, only credentials whose AAGUID (UUID v4)
//                          appears in the list are accepted
//   - AllowedTransports  — if non-empty, only credentials advertising at least
//                          one of the listed transports are accepted
//                          (e.g. ["internal","hybrid"])
//
// # AAGUID notes
//
// The AAGUID (16-byte authenticator model identifier) is extracted from the
// attestation authData by the go-webauthn library and exposed as
// Credential.Authenticator.AAGUID ([]byte).  We store it in the DB as a
// standard UUID string (lowercase hex with hyphens) which is the canonical
// form used by the FIDO Alliance MDS3 metadata.
//
// Common well-known AAGUIDs (non-exhaustive):
//
//	Apple Touch ID / Face ID platform:
//	  "fbfc3007-154e-4ecc-8ade-601177b8b3f6"   — Face ID
//	  "dd4ec289-e01d-41c9-bb89-70fa845d4bf2"   — Touch ID / iCloud Keychain
//
//	Google Password Manager:
//	  "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"
//
//	Windows Hello:
//	  "9ddd1817-af5a-4672-a2b9-3e3dd95000a9"
//
//	YubiKey 5 FIDO2 (security key):
//	  "2fc0579f-8113-47ea-b116-bb5a8db9202a"
//
//	Android Authenticator with Google credentials:
//	  "b93fd961-f2e6-462f-b122-82002247de78"
package attestation

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	walib "github.com/go-webauthn/webauthn/webauthn"
)

// ErrPolicyViolation is returned when a credential fails the attestation policy.
// The Reason field carries a human-readable description safe to return to clients.
var ErrPolicyViolation = errors.New("attestation policy violation")

// PolicyViolation wraps ErrPolicyViolation with a specific reason.
type PolicyViolation struct {
	Reason string
}

func (e *PolicyViolation) Error() string { return "attestation policy violation: " + e.Reason }
func (e *PolicyViolation) Unwrap() error  { return ErrPolicyViolation }

// Policy holds the per-org attestation enforcement rules.
// A zero-value Policy (all fields at default) performs no checks.
type Policy struct {
	// Enabled is the master switch. When false, all checks are skipped.
	Enabled bool `json:"enabled"`

	// RequireAttestation rejects credentials with AttestationFormat == "none".
	// Enable this when the org must verify hardware authenticity.
	RequireAttestation bool `json:"require_attestation"`

	// AllowedFormats is an optional allow-list of attestation statement formats.
	// Values: "packed", "tpm", "android-key", "android-safetynet", "fido-u2f",
	//         "apple", "none".
	// Empty = any format is accepted (subject to RequireAttestation).
	AllowedFormats []string `json:"allowed_formats,omitempty"`

	// AllowedAAGUIDs is an optional allow-list of authenticator model UUIDs.
	// Values must be lowercase UUID strings (e.g. "fbfc3007-154e-4ecc-8ade-601177b8b3f6").
	// Empty = any AAGUID is accepted.
	AllowedAAGUIDs []string `json:"allowed_aaguids,omitempty"`

	// AllowedTransports is an optional allow-list of authenticator transport types.
	// The credential must advertise at least one matching transport.
	// Values: "internal", "usb", "nfc", "ble", "hybrid", "smart-card".
	// Empty = any transport is accepted.
	AllowedTransports []string `json:"allowed_transports,omitempty"`

	// RequireMDSCertification requires the authenticator to appear in the local
	// FIDO MDS3 catalog (i.e. be a known, certified device). When combined with
	// MinCertificationLevel this provides "FIDO2 L2+ only" enforcement without
	// a manual AAGUID allow-list.
	//
	// When true, authenticators NOT in the MDS3 catalog are rejected, even if
	// they are listed in AllowedAAGUIDs.
	RequireMDSCertification bool `json:"require_mds_certification,omitempty"`

	// MinCertificationLevel is the minimum FIDO certification level required.
	// Valid values: "L1", "L1+", "L1p", "L2", "L2+", "L3", "L3+". Empty = no minimum.
	// Implies RequireMDSCertification = true when set.
	MinCertificationLevel string `json:"min_certification_level,omitempty"`

	// ExcludeRevokedAuthenticators rejects authenticators whose MDS3 status
	// includes "REVOKED" or "USER_VERIFICATION_BYPASS".
	// Requires the local MDS3 catalog to be populated.
	ExcludeRevokedAuthenticators bool `json:"exclude_revoked_authenticators,omitempty"`
}

// EnforceCredential checks credential against the policy.
// Returns nil if the credential is accepted, or a *PolicyViolation if rejected.
// Safe to call with a nil or zero-value Policy (returns nil immediately).
func (p *Policy) EnforceCredential(credential *walib.Credential) error {
	if p == nil || !p.Enabled {
		return nil
	}

	format := credential.AttestationFormat

	// ── RequireAttestation ───────────────────────────────────────────────────
	if p.RequireAttestation && (format == "" || format == "none") {
		return &PolicyViolation{
			Reason: "attestation is required; authenticator must provide a verifiable attestation statement",
		}
	}

	// ── AllowedFormats ───────────────────────────────────────────────────────
	if len(p.AllowedFormats) > 0 && format != "" && format != "none" {
		if !containsString(p.AllowedFormats, format) {
			return &PolicyViolation{
				Reason: fmt.Sprintf("attestation format %q is not permitted by policy (allowed: %s)",
					format, strings.Join(p.AllowedFormats, ", ")),
			}
		}
	}

	// ── AllowedAAGUIDs ───────────────────────────────────────────────────────
	if len(p.AllowedAAGUIDs) > 0 {
		aaguidStr := aaguidToString(credential.Authenticator.AAGUID)
		if !containsString(p.AllowedAAGUIDs, aaguidStr) {
			return &PolicyViolation{
				Reason: fmt.Sprintf("authenticator model %q is not on the approved device list", aaguidStr),
			}
		}
	}

	// ── AllowedTransports ────────────────────────────────────────────────────
	if len(p.AllowedTransports) > 0 {
		matched := false
		for _, t := range credential.Transport {
			if containsString(p.AllowedTransports, string(t)) {
				matched = true
				break
			}
		}
		if !matched {
			transports := make([]string, len(credential.Transport))
			for i, t := range credential.Transport {
				transports[i] = string(t)
			}
			return &PolicyViolation{
				Reason: fmt.Sprintf("authenticator transport(s) [%s] are not permitted by policy (allowed: %s)",
					strings.Join(transports, ", "),
					strings.Join(p.AllowedTransports, ", ")),
			}
		}
	}

	return nil
}

// ── MDS-aware enforcement ─────────────────────────────────────────────────────

// MDSEntry is the minimal interface the attestation package needs from the MDS
// repository. Using an interface avoids a circular import.
type MDSEntry interface {
	GetCertificationLevel() string // "L1", "L2", "L2+", "L3", "L3+", or ""
	GetStatusReports() []string    // raw status strings, e.g. ["FIDO_CERTIFIED_L2", "REVOKED"]
}

// MDSEntryData is the concrete struct used when calling EnforceWithMDS
// from the WebAuthn registration handler.
type MDSEntryData struct {
	CertLevel     string
	StatusStrings []string
}

func (d *MDSEntryData) GetCertificationLevel() string { return d.CertLevel }
func (d *MDSEntryData) GetStatusReports() []string    { return d.StatusStrings }

// certLevelPriority maps level strings to a sortable integer for comparison.
var certLevelPriority = map[string]int{
	"L1":  1,
	"L1p": 2,
	"L1+": 3,
	"L2":  4,
	"L2+": 5,
	"L3":  6,
	"L3+": 7,
}

// EnforceWithMDS extends EnforceCredential with MDS3-catalog checks.
//
// mdsEntry is the MDS3 record for this authenticator's AAGUID.
// It may be nil if the authenticator is not in the catalog.
//
// Checks performed (in addition to the base EnforceCredential checks):
//  1. RequireMDSCertification — rejects unknown (not-in-catalog) devices.
//  2. MinCertificationLevel   — rejects devices below the required level.
//  3. ExcludeRevokedAuthenticators — rejects REVOKED / USER_VERIFICATION_BYPASS.
func (p *Policy) EnforceWithMDS(credential *walib.Credential, mdsEntry MDSEntry) error {
	// Run base checks first (format, AAGUID allowlist, transport).
	if err := p.EnforceCredential(credential); err != nil {
		return err
	}
	if p == nil || !p.Enabled {
		return nil
	}

	// Treat MinCertificationLevel as an implicit require.
	requireMDS := p.RequireMDSCertification || p.MinCertificationLevel != "" || p.ExcludeRevokedAuthenticators

	if !requireMDS {
		return nil
	}

	if mdsEntry == nil {
		if requireMDS {
			aaguidStr := aaguidToString(credential.Authenticator.AAGUID)
			return &PolicyViolation{
				Reason: fmt.Sprintf("authenticator %q is not in the FIDO MDS3 catalog; only certified devices are permitted", aaguidStr),
			}
		}
		return nil
	}

	// ── MinCertificationLevel ────────────────────────────────────────────────
	if p.MinCertificationLevel != "" {
		minPriority := certLevelPriority[p.MinCertificationLevel]
		actualLevel := mdsEntry.GetCertificationLevel()
		actualPriority := certLevelPriority[actualLevel] // 0 if unknown/uncertified
		if actualPriority < minPriority {
			aaguidStr := aaguidToString(credential.Authenticator.AAGUID)
			return &PolicyViolation{
				Reason: fmt.Sprintf(
					"authenticator %q has certification level %q which is below the required minimum %q",
					aaguidStr, actualLevel, p.MinCertificationLevel,
				),
			}
		}
	}

	// ── ExcludeRevokedAuthenticators ─────────────────────────────────────────
	if p.ExcludeRevokedAuthenticators {
		for _, sr := range mdsEntry.GetStatusReports() {
			switch sr {
			case "REVOKED", "USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE",
				"USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE":
				aaguidStr := aaguidToString(credential.Authenticator.AAGUID)
				return &PolicyViolation{
					Reason: fmt.Sprintf("authenticator %q has a security advisory (%s) and is not permitted", aaguidStr, sr),
				}
			}
		}
	}

	return nil
}

// ExtractMetadata returns the AAGUID (as UUID string), attestation format,
// and transport list from a credential for storage and audit purposes.
func ExtractMetadata(credential *walib.Credential) (aaguid, format string, transports []string) {
	aaguid = aaguidToString(credential.Authenticator.AAGUID)
	format = credential.AttestationFormat
	if format == "" {
		format = "none"
	}
	transports = make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}
	return aaguid, format, transports
}

// aaguidToString converts a 16-byte AAGUID to a lowercase UUID string.
// If the slice is nil or not 16 bytes, returns the zero UUID.
func aaguidToString(b []byte) string {
	if len(b) != 16 {
		return "00000000-0000-0000-0000-000000000000"
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
