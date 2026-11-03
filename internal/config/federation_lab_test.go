package config

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFederationLabTrustIsExplicitAndConfinedToConformanceTenant(t *testing.T) {
	global := FederationConfig{Enabled: true, TrustAnchors: []string{"https://production.example"}, AuthorityHints: []string{"https://production.example"}, TrustAnchorMode: true, ConformanceTrustAnchor: "https://suite.example/test/a/lab/trust-anchor"}
	for _, test := range []struct {
		slug string
		mode bool
	}{{"real", true}, {"real", false}, {"conformance", false}} {
		require.Equal(t, global, global.ForTenant(test.slug, test.mode))
	}
	lab := global.ForTenant("conformance", true)
	require.Equal(t, []string{global.ConformanceTrustAnchor}, lab.TrustAnchors)
	require.Equal(t, lab.TrustAnchors, lab.AuthorityHints)
	require.False(t, lab.TrustAnchorMode)
	require.Equal(t, []string{"https://production.example"}, global.TrustAnchors)
	global.ConformanceTrustAnchor = ""
	require.Equal(t, global, global.ForTenant("conformance", true))
}
