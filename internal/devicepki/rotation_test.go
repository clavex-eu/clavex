package devicepki

import "testing"

func TestBaseMount(t *testing.T) {
	cases := map[string]string{
		"pki-device":               "pki-device",
		"pki-device-rot-abc12345":  "pki-device",
		"pki-device-prod":          "pki-device-prod",
		"pki-device-prod-rot-dead": "pki-device-prod",
		"pki-device-rot-1-rot-2":   "pki-device", // strips at first -rot-, stays bounded
	}
	for in, want := range cases {
		if got := baseMount(in); got != want {
			t.Errorf("baseMount(%q) = %q, want %q", in, got, want)
		}
	}
}
