package oidc

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── BuildJARMResponse ─────────────────────────────────────────────────────────

func TestBuildJARMResponse_Claims(t *testing.T) {
	ks := newTestKeySet(t)
	issuer := "https://clavex.example.com/acme"
	clientID := "client-xyz"
	code := "auth-code-abc123"
	state := "random-state"

	jarmJWT, err := BuildJARMResponse(ks, issuer, clientID, code, state)
	require.NoError(t, err)
	require.NotEmpty(t, jarmJWT)

	// Should be three dot-separated segments (compact serialisation)
	parts := strings.Split(jarmJWT, ".")
	assert.Len(t, parts, 3, "JARM JWT must be compact-serialised (3 segments)")

	// Parse and verify with the public key
	tok, err := jwt.Parse([]byte(jarmJWT),
		jwt.WithKey(jwa.PS256, ks.PublicKey()),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(clientID),
		jwt.WithValidate(true),
	)
	require.NoError(t, err)

	// Check standard claims
	assert.Equal(t, issuer, tok.Issuer())
	assert.Equal(t, []string{clientID}, tok.Audience())
	assert.True(t, tok.Expiration().After(time.Now()), "exp must be in the future")
	assert.True(t, tok.Expiration().Before(time.Now().Add(JARMResponseTTL+time.Second)), "exp must be within TTL")

	// Check authorization response claims
	gotCode, ok := tok.Get("code")
	require.True(t, ok, "code claim must be present")
	assert.Equal(t, code, gotCode)

	gotState, ok := tok.Get("state")
	require.True(t, ok, "state claim must be present")
	assert.Equal(t, state, gotState)
}

func TestBuildJARMResponse_NoState(t *testing.T) {
	ks := newTestKeySet(t)
	jarmJWT, err := BuildJARMResponse(ks, "https://issuer.example", "client1", "code1", "")
	require.NoError(t, err)

	tok, err := jwt.Parse([]byte(jarmJWT),
		jwt.WithKey(jwa.PS256, ks.PublicKey()),
		jwt.WithValidate(true),
	)
	require.NoError(t, err)

	_, hasState := tok.Get("state")
	assert.False(t, hasState, "state claim must be absent when state is empty")
}

func TestBuildJARMResponse_SignedPS256(t *testing.T) {
	ks := newTestKeySet(t)
	jarmJWT, err := BuildJARMResponse(ks, "https://issuer.example", "client1", "code1", "s1")
	require.NoError(t, err)

	// Verify fails with a different key (wrong key → invalid signature)
	other := newTestKeySet(t)
	_, err = jwt.Parse([]byte(jarmJWT),
		jwt.WithKey(jwa.PS256, other.PublicKey()),
		jwt.WithValidate(true),
	)
	assert.Error(t, err, "JWT signed by a different key must fail verification")
}

// ── BuildJARMRedirectURL ──────────────────────────────────────────────────────

func TestBuildJARMRedirectURL_QueryJWT(t *testing.T) {
	jarmJWT := "header.payload.sig"
	redirectURI := "https://rp.example.com/callback"

	dest, err := BuildJARMRedirectURL(jarmJWT, redirectURI, "query.jwt")
	require.NoError(t, err)

	u, err := url.Parse(dest)
	require.NoError(t, err)
	assert.Equal(t, jarmJWT, u.Query().Get("response"), "response query param must equal the JARM JWT")
	assert.Empty(t, u.Fragment, "fragment must be empty for query.jwt mode")
}

func TestBuildJARMRedirectURL_JWT_MapsToQueryJWT(t *testing.T) {
	jarmJWT := "header.payload.sig"
	redirectURI := "https://rp.example.com/cb"

	dest, err := BuildJARMRedirectURL(jarmJWT, redirectURI, "jwt")
	require.NoError(t, err)

	u, _ := url.Parse(dest)
	assert.Equal(t, jarmJWT, u.Query().Get("response"), "jwt mode should use query param")
}

func TestBuildJARMRedirectURL_FragmentJWT(t *testing.T) {
	jarmJWT := "header.payload.sig"
	redirectURI := "https://rp.example.com/cb"

	dest, err := BuildJARMRedirectURL(jarmJWT, redirectURI, "fragment.jwt")
	require.NoError(t, err)

	u, _ := url.Parse(dest)
	assert.Empty(t, u.RawQuery, "query must be empty for fragment.jwt mode")
	assert.Contains(t, u.Fragment, "response=", "fragment must contain response param")
}

func TestBuildJARMRedirectURL_PreservesExistingQueryParams(t *testing.T) {
	jarmJWT := "header.payload.sig"
	redirectURI := "https://rp.example.com/cb?existing=1"

	dest, err := BuildJARMRedirectURL(jarmJWT, redirectURI, "query.jwt")
	require.NoError(t, err)

	u, _ := url.Parse(dest)
	assert.Equal(t, "1", u.Query().Get("existing"), "existing query params must be preserved")
	assert.Equal(t, jarmJWT, u.Query().Get("response"))
}

// ── IsJARMMode ────────────────────────────────────────────────────────────────

func TestIsJARMMode(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"query", false},
		{"", false},
		{"jwt", true},
		{"query.jwt", true},
		{"fragment.jwt", true},
		{"form_post", false},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			assert.Equal(t, tt.want, IsJARMMode(tt.mode))
		})
	}
}

// ── normaliseResponseMode ─────────────────────────────────────────────────────

func TestNormaliseResponseMode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "query"},
		{"query", "query"},
		{"jwt", "query.jwt"}, // shorthand → normalised
		{"query.jwt", "query.jwt"},
		{"fragment.jwt", "fragment.jwt"},
		{"form_post", "form_post"}, // unsupported, passed through for rejection
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, normaliseResponseMode(tt.input))
		})
	}
}
