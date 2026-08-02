package devicepki

import (
	"fmt"
	"math/big"
	"strings"
)

// FormatSerial renders a certificate serial number in the canonical
// colon-separated hex form (the same convention Vault's API uses, e.g.
// "17:36:7c:...:ff"). Callers must use THIS formatter — not whatever Vault's
// sign response happens to return as a string — for anything stored in
// device_certificates.serial_number, so that a serial derived from the
// certificate actually presented over TLS at renewal time (via
// cert.SerialNumber, a *big.Int) always matches byte-for-byte regardless of
// any quirks in Vault's own string representation.
func FormatSerial(sn *big.Int) string {
	b := sn.Bytes()
	if len(b) == 0 {
		return "00"
	}
	parts := make([]string, len(b))
	for i, by := range b {
		parts[i] = fmt.Sprintf("%02x", by)
	}
	return strings.Join(parts, ":")
}

// ParseCN splits the external Subject CN contract "<deviceID>@<tenantID>"
// (fixed by the external MQTT broker's client-auth contract) back into its
// parts.
func ParseCN(cn string) (deviceExternalID, tenantID string, ok bool) {
	return strings.Cut(cn, "@")
}
