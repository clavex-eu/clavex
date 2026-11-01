package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOID4VCIMetadataSigningEnvironmentBindings(t *testing.T) {
	t.Setenv("CLAVEX_DEV", "true")
	t.Setenv("CLAVEX_OID4VCI_WALLET_VAULT_PROFILES_FILE", "/test/wallet-vault.json")
	t.Setenv("CLAVEX_OID4VCI_METADATA_CERT_FILE", "/test/metadata-chain.pem")
	t.Setenv("CLAVEX_OID4VCI_METADATA_KEY_FILE", "/test/metadata-key.pem")
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("dev: true\n"), 0600))
	cfg, err := LoadFrom(path)
	require.NoError(t, err)
	require.Equal(t, "/test/wallet-vault.json", cfg.OID4VCI.WalletVaultProfilesFile)
	require.Equal(t, "/test/metadata-chain.pem", cfg.OID4VCI.MetadataCertFile)
	require.Equal(t, "/test/metadata-key.pem", cfg.OID4VCI.MetadataKeyFile)
}
