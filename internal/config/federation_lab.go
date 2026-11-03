package config

import (
	"fmt"
	"net/url"
)

func (f FederationConfig) ValidateLab() error {
	if f.ConformanceTrustAnchor == "" {
		return nil
	}
	u, err := url.Parse(f.ConformanceTrustAnchor)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/test/a/clavex-openid-federation-op/trust-anchor" {
		return fmt.Errorf("conformance Federation trust anchor must be an HTTPS suite origin with /test/a/clavex-openid-federation-op/trust-anchor")
	}
	return nil
}

// ForTenant returns a copy. A local test trust anchor requires both explicit
// installation configuration and the existing conformance tenant's test mode.
func (f FederationConfig) ForTenant(slug string, conformance bool) FederationConfig {
	if f.ConformanceTrustAnchor != "" && slug == "conformance" && conformance {
		f.TrustAnchors = []string{f.ConformanceTrustAnchor}
		f.AuthorityHints = []string{f.ConformanceTrustAnchor}
		f.TrustAnchorMode = false
		f.TrustAnchorEntityID = ""
	}
	return f
}
