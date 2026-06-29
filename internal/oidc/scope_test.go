package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterScope(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		allowed   []string
		want      string
	}{
		{"empty allowed = allow-all", "openid profile custom", nil, "openid profile custom"},
		{"empty allowed slice = allow-all", "openid", []string{}, "openid"},
		{"subset preserved in request order", "profile openid", []string{"openid", "profile", "email"}, "profile openid"},
		{"extras dropped", "openid admin write", []string{"openid", "read"}, "openid"},
		{"disjoint yields empty", "admin write", []string{"openid", "read"}, ""},
		{"empty request yields empty", "", []string{"openid"}, ""},
		{"duplicate requested kept (both allowed)", "openid openid", []string{"openid"}, "openid openid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FilterScope(tt.requested, tt.allowed))
		})
	}
}

func TestAudiencePermitted(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		clientID  string
		allowed   []string
		want      bool
	}{
		{"empty request always ok", "", "c1", nil, true},
		{"self always ok", "c1", "c1", nil, true},
		{"allow-listed ok", "https://api", "c1", []string{"https://api"}, true},
		{"not listed rejected", "https://victim", "c1", []string{"https://api"}, false},
		{"empty allow-list + foreign rejected", "https://victim", "c1", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, audiencePermitted(tt.requested, tt.clientID, tt.allowed))
		})
	}
}

func TestParseTrustedIDToken_RoundTrip(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := UserClaims{UserID: "11111111-1111-1111-1111-111111111111", OrgID: "o1", Email: "e@e.com"}
	idt, err := tc.IssueIDToken("client", "n", uc)
	require.NoError(t, err)

	tok, err := tc.ParseTrustedIDToken(idt)
	require.NoError(t, err)
	assert.Equal(t, uc.UserID, tok.Subject())
}

func TestParseTrustedIDToken_RejectsWrongIssuer(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := UserClaims{UserID: "u1", OrgID: "o1", Email: "e@e.com"}
	idt, err := tc.IssueIDToken("client", "n", uc)
	require.NoError(t, err)

	// Same signing key, different expected issuer → must reject.
	other := *tc
	other.Issuer = "https://clavex.example.com/other-org"
	_, err = other.ParseTrustedIDToken(idt)
	require.Error(t, err)
}

func TestParseTrustedIDToken_RejectsForeignSignature(t *testing.T) {
	tc := newTestTokenConfig(t)
	uc := UserClaims{UserID: "u1", OrgID: "o1", Email: "e@e.com"}
	idt, err := tc.IssueIDToken("client", "n", uc)
	require.NoError(t, err)

	// Different key set (same issuer string) → signature must fail.
	foreign := newTestTokenConfig(t)
	_, err = foreign.ParseTrustedIDToken(idt)
	require.Error(t, err)
}
