package federation

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/stretchr/testify/require"
)

func TestLabTransportConfinesPrivateRoutingAndRedirectsToSingleAlias(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/test/a/clavex-openid-federation-op/redirect" {
			http.Redirect(w, r, "/private", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	origin, err := url.Parse(server.URL)
	require.NoError(t, err)
	client := server.Client()
	client.Transport = labTransport{origin: origin, inner: client.Transport}
	r, err := client.Get(server.URL + "/test/a/clavex-openid-federation-op/trust-anchor/jwks")
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, r.Body)
	require.NoError(t, err)
	require.NoError(t, r.Body.Close())
	for _, path := range []string{"/private", "/test/a/another/jwks", "/test/a/clavex-openid-federation-op/../private", "/test/a/clavex-openid-federation-op/redirect"} {
		r, err = client.Get(server.URL + path)
		if r != nil {
			require.NoError(t, r.Body.Close())
		}
		require.Error(t, err, path)
	}
	require.Equal(t, 2, requests, "only the authorised request and its redirect origin were contacted")
	fc := config.FederationConfig{Enabled: true, TrustAnchors: []string{"https://production.example"}, ConformanceTrustAnchor: server.URL + "/test/a/clavex-openid-federation-op/trust-anchor"}
	lab := NewTenantResolver(fc, "conformance", true)
	_, ok := lab.hc.Transport.(labTransport)
	require.True(t, ok)
	response, tlsErr := lab.hc.Get(server.URL + "/test/a/clavex-openid-federation-op/trust-anchor/jwks")
	if response != nil {
		require.NoError(t, response.Body.Close())
	}
	require.Error(t, tlsErr, "explicit laboratory routing must still reject an untrusted TLS certificate")
	for _, scope := range []struct {
		slug string
		mode bool
	}{{"real", true}, {"conformance", false}} {
		resolver := NewTenantResolver(fc, scope.slug, scope.mode)
		_, ok = resolver.hc.Transport.(labTransport)
		require.False(t, ok)
		require.Contains(t, resolver.trustAnchors, "https://production.example")
	}
}
