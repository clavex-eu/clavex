package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

func TestConformanceAttestersPublishOnlyPublicKeys(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	keys := jwk.NewSet()
	require.NoError(t, keys.AddKey(key))
	plan := map[string]any{"vci": map[string]any{"client_attestation_issuer": "https://issuer.example/conformance", "key_attestation_jwks": keys}}
	encoded, err := json.Marshal(plan)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "plan.json")
	require.NoError(t, os.WriteFile(path, encoded, 0600))
	result, err := conformanceAttesters(path)
	require.NoError(t, err)
	var entries []struct {
		Issuer string          `json:"issuer"`
		JWKS   json.RawMessage `json:"jwks"`
	}
	require.NoError(t, json.Unmarshal(result, &entries))
	require.Len(t, entries, 1)
	public, err := jwk.Parse(entries[0].JWKS)
	require.NoError(t, err)
	pub, _ := public.Key(0)
	private, err := jwk.IsPrivateKey(pub)
	require.NoError(t, err)
	require.False(t, private)
	require.Equal(t, "https://issuer.example/conformance", entries[0].Issuer)
	for _, bad := range []string{`{}`, `{"vci":{"client_attestation_issuer":"https://issuer.example","key_attestation_jwks":{"keys":[]}}}`, `invalid`} {
		require.NoError(t, os.WriteFile(path, []byte(bad), 0600))
		_, err = conformanceAttesters(path)
		require.Error(t, err)
	}
}
