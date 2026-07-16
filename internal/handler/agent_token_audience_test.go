package handler

import "testing"

func TestAudiencePermitted(t *testing.T) {
	issuer := "https://acme.clavex.eu"
	allowed := []string{"sts.amazonaws.com", "api://AzureADTokenExchange"}

	cases := []struct {
		name      string
		requested string
		want      bool
	}{
		{"empty request defaults to issuer", "", true},
		{"issuer itself always allowed", issuer, true},
		{"allow-listed AWS audience", "sts.amazonaws.com", true},
		{"allow-listed Azure audience", "api://AzureADTokenExchange", true},
		{"non-allow-listed audience rejected", "https://evil.example", false},
		{"GCP audience not yet approved for this org", "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/prov", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := audiencePermitted(tc.requested, issuer, allowed)
			if got != tc.want {
				t.Errorf("audiencePermitted(%q, %q, %v) = %v, want %v", tc.requested, issuer, allowed, got, tc.want)
			}
		})
	}
}

func TestAudiencePermitted_EmptyAllowlist(t *testing.T) {
	issuer := "https://acme.clavex.eu"
	if !audiencePermitted("", issuer, nil) {
		t.Error("empty request must default to issuer even with a nil allowlist")
	}
	if !audiencePermitted(issuer, issuer, nil) {
		t.Error("issuer itself must always be permitted even with a nil allowlist")
	}
	if audiencePermitted("sts.amazonaws.com", issuer, nil) {
		t.Error("no audience beyond the issuer should be permitted with an empty allowlist")
	}
}
