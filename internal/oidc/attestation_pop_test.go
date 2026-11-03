package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"
)

type popReplayCache struct {
	*mapJTICache
	ttl time.Duration
}

func (c *popReplayCache) CheckAndSet(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	c.ttl = ttl
	return c.mapJTICache.CheckAndSet(ctx, key, ttl)
}

func TestAttestationPopOptionalExpirationAndFreshness(t *testing.T) {
	provider, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	instance, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := jwk.FromRaw(&provider.PublicKey)
	require.NoError(t, err)
	keys := jwk.NewSet()
	require.NoError(t, keys.AddKey(pub))
	instancePub, err := jwk.FromRaw(&instance.PublicKey)
	require.NoError(t, err)
	sign := func(claims map[string]any, typ string, key *ecdsa.PrivateKey) string {
		raw, e := json.Marshal(claims)
		require.NoError(t, e)
		headers := jws.NewHeaders()
		require.NoError(t, headers.Set(jws.TypeKey, typ))
		signed, e := jws.Sign(raw, jws.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(headers)))
		require.NoError(t, e)
		return string(signed)
	}
	now := time.Now()
	attest := sign(map[string]any{"iss": "https://provider.example", "sub": caClientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": instancePub}}, "oauth-client-attestation+jwt", provider)
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"without exp", func(map[string]any) {}, true},
		{"with exp", func(c map[string]any) { c["exp"] = now.Add(time.Minute).Unix() }, true},
		{"stale iat", func(c map[string]any) { c["iat"] = now.Add(-6 * time.Minute).Unix() }, false},
		{"future iat", func(c map[string]any) { c["iat"] = now.Add(time.Minute).Unix() }, false},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }, false},
		{"missing jti", func(c map[string]any) { delete(c, "jti") }, false},
		{"oversized jti", func(c map[string]any) { c["jti"] = string(make([]byte, 513)) }, false},
		{"expired exp", func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }, false},
		{"wrong audience", func(c map[string]any) { c["aud"] = "https://other.example" }, false},
		{"wrong client", func(c map[string]any) { c["iss"] = "other-client" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"iss": caClientID, "aud": caIssuer, "iat": now.Unix(), "jti": uuid.NewString()}
			tc.change(claims)
			assertion := attest + "~" + sign(claims, "oauth-client-attestation-pop+jwt", instance)
			cache := &popReplayCache{mapJTICache: newMapJTICache()}
			validate := func() (string, error) {
				return oidc.ValidateAttestationAssertionJWT(context.Background(), assertion, keys, caTokenEndpoint, caIssuer, caClientID, cache)
			}
			jkt, e := validate()
			if !tc.valid {
				require.Error(t, e)
				return
			}
			require.NoError(t, e)
			require.NotEmpty(t, jkt)
			require.Greater(t, cache.ttl, time.Duration(0))
			require.LessOrEqual(t, cache.ttl, 5*time.Minute+30*time.Second)
			_, e = validate()
			require.ErrorContains(t, e, "jti already used")
			_, e = oidc.ValidateAttestationAssertionJWT(context.Background(), assertion, keys, caTokenEndpoint, caIssuer, caClientID, unavailableClientJTICache{})
			require.ErrorIs(t, e, oidc.ErrClientReplayUnavailable)
			wrongKey := attest + "~" + sign(claims, "oauth-client-attestation-pop+jwt", provider)
			_, e = oidc.ValidateAttestationAssertionJWT(context.Background(), wrongKey, keys, caTokenEndpoint, caIssuer, caClientID, newMapJTICache())
			require.Error(t, e)
		})
	}
}
