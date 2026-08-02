package devicepki

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatSerial(t *testing.T) {
	cases := []struct {
		name string
		in   *big.Int
		want string
	}{
		{"zero", big.NewInt(0), "00"},
		{"single byte", big.NewInt(0xab), "ab"},
		{"multi byte", big.NewInt(0x1736), "17:36"},
		{"large", new(big.Int).SetBytes([]byte{0x17, 0x36, 0x7c, 0x00, 0xff}), "17:36:7c:00:ff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, FormatSerial(tc.in))
		})
	}
}

func TestFormatSerial_Deterministic(t *testing.T) {
	sn := big.NewInt(123456789)
	assert.Equal(t, FormatSerial(sn), FormatSerial(sn), "same serial must always format identically")
}

func TestParseCN(t *testing.T) {
	cases := []struct {
		name       string
		cn         string
		wantDevice string
		wantTenant string
		wantOK     bool
	}{
		{"well formed", "device-123@org-abc", "device-123", "org-abc", true},
		{"tenant contains dashes/uuid", "fleet-sensor-01@11111111-2222-3333-4444-555555555555",
			"fleet-sensor-01", "11111111-2222-3333-4444-555555555555", true},
		{"no separator", "device-only", "device-only", "", false},
		{"empty", "", "", "", false},
		{"only separator", "@", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device, tenant, ok := ParseCN(tc.cn)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantDevice, device)
			assert.Equal(t, tc.wantTenant, tenant)
		})
	}
}
