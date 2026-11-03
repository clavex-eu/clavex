package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

func TestPrepareCreatesDistinctPrivateFixtureKeysWithoutReplacingExistingMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "keys.json")
	require.NoError(t, prepare(path))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Zero(t, info.Mode().Perm()&0o077)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var bundle map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &bundle))
	require.Len(t, bundle, 3)
	seen := map[string]bool{}
	for _, value := range bundle {
		keys, err := jwk.Parse(value)
		require.NoError(t, err)
		require.Equal(t, 1, keys.Len())
		key, _ := keys.Key(0)
		require.NoError(t, key.Validate())
		require.False(t, seen[key.KeyID()])
		seen[key.KeyID()] = true
		var private any
		require.NoError(t, key.Raw(&private))
		require.NotNil(t, private)
	}
	require.ErrorContains(t, prepare(path), "refusing to replace")
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, raw, after)
}
