package domainverify

import "testing"

func TestMatches(t *testing.T) {
	cases := []struct {
		resolved, target string
		want             bool
	}{
		{"ingress.cloud.clavex.eu.", "ingress.cloud.clavex.eu", true},   // trailing dot
		{"INGRESS.CLOUD.CLAVEX.EU", "ingress.cloud.clavex.eu", true},    // case-insensitive
		{"lb.ingress.cloud.clavex.eu", "ingress.cloud.clavex.eu", true}, // chained subdomain
		{"evil.com", "ingress.cloud.clavex.eu", false},
		{"", "ingress.cloud.clavex.eu", false},
		{"ingress.cloud.clavex.eu", "", false},
		{"xingress.cloud.clavex.eu", "ingress.cloud.clavex.eu", false}, // not a subdomain boundary
	}
	for _, tc := range cases {
		if got := Matches(tc.resolved, tc.target); got != tc.want {
			t.Errorf("Matches(%q,%q)=%v want %v", tc.resolved, tc.target, got, tc.want)
		}
	}
}
