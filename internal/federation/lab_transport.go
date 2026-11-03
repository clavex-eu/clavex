package federation

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/safehttp"
)

// A laboratory opt-in permits private routing only to this exact suite origin
// and test alias. TLS verification stays enabled, including on redirects.
type labTransport struct {
	origin *url.URL
	inner  http.RoundTripper
}

func (t labTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.origin == nil || r.URL.Scheme != "https" || r.URL.Host != t.origin.Host || r.URL.User != nil || !strings.HasPrefix(path.Clean(r.URL.Path), "/test/a/clavex-openid-federation-op/") {
		return nil, fmt.Errorf("federation laboratory request is outside the configured suite alias")
	}
	return t.inner.RoundTrip(r)
}

func NewTenantResolver(fc config.FederationConfig, slug string, conformance bool) *Resolver {
	selected := fc.ForTenant(slug, conformance)
	r := NewResolver(selected.TrustAnchors)
	if fc.ConformanceTrustAnchor != "" && slug == "conformance" && conformance {
		if fc.ValidateLab() != nil {
			r.trustAnchors = map[string]struct{}{}
			return r
		}
		origin, _ := url.Parse(fc.ConformanceTrustAnchor)
		client := safehttp.Client(10*time.Second, true)
		client.Transport = labTransport{origin: origin, inner: client.Transport}
		r.hc = client
	}
	return r
}
