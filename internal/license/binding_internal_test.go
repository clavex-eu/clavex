package license

import "testing"

func TestLicenseBindingOK(t *testing.T) {
	const local = "11111111-1111-1111-1111-111111111111"
	tests := []struct {
		name   string
		licSub string
		want   bool
	}{
		{"unbound empty sub runs anywhere", "", true},
		{"wildcard site license runs anywhere", "*", true},
		{"matching installation id", local, true},
		{"different installation id rejected", "22222222-2222-2222-2222-222222222222", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := licenseBindingOK(tt.licSub, local); got != tt.want {
				t.Errorf("licenseBindingOK(%q, %q) = %v, want %v", tt.licSub, local, got, tt.want)
			}
		})
	}
}
