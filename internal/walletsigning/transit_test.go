package walletsigning

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestTransitPinnedVersionAndSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, mode := range []string{"valid", "wrong-version", "wrong-key", "failure", "redirect", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			redirected := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected++; w.WriteHeader(500) }))
			defer target.Close()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/v1/transit/sign/mdoc", r.URL.Path)
				require.Equal(t, "tenant-token", r.Header.Get("X-Vault-Token"))
				require.Equal(t, "ns", r.Header.Get("X-Vault-Namespace"))
				var body struct {
					Input     string `json:"input"`
					Prehashed bool   `json:"prehashed"`
					Hash      string `json:"hash_algorithm"`
					Encoding  string `json:"marshaling_algorithm"` //nolint:misspell // Exact Vault API field.
					Version   int    `json:"key_version"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				require.True(t, body.Prehashed)
				require.Equal(t, "sha2-256", body.Hash)
				require.Equal(t, "asn1", body.Encoding)
				require.Equal(t, 2, body.Version)
				digest, err := base64.StdEncoding.DecodeString(body.Input)
				require.NoError(t, err)
				require.Len(t, digest, 32)
				switch mode {
				case "failure":
					w.WriteHeader(403)
					return
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
					return
				case "malformed":
					_, _ = w.Write([]byte(`{"data":{"signature":"secret-error"}}`))
					return
				}
				signingKey := key
				version := 2
				if mode == "wrong-version" {
					version = 3
				}
				if mode == "wrong-key" {
					signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)
				}
				sig, err := ecdsa.SignASN1(rand.Reader, signingKey, digest)
				require.NoError(t, err)
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": fmt.Sprintf("vault:v%d:%s", version, base64.StdEncoding.EncodeToString(sig))}}))
			}))
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			signer := &transitSigner{profile: TransitProfile{Address: server.URL, Mount: "transit", Key: "mdoc", Version: 2, Namespace: "ns"}, token: "tenant-token", public: &key.PublicKey, client: client}
			digest := sha256.Sum256([]byte("credential"))
			sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if mode == "valid" {
				require.NoError(t, err)
				require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig))
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "tenant-token")
				require.NotContains(t, err.Error(), "secret-error")
			}
			require.Zero(t, redirected)
			_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA384)
			require.Error(t, err)
		})
	}
}

func TestRegistryTenantIsolationAndRemotePolicy(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	org := uuid.New()
	requests := 0
	exportable := false
	backup := false
	derived := false
	version := "2"
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "/v1/transit/keys/mdoc", r.URL.Path)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"type": "ecdsa-p256", "exportable": exportable, "allow_plaintext_backup": backup, "derived": derived, "keys": map[string]any{version: map[string]string{"public_key": pub}}}}))
	}))
	defer server.Close()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "tls-ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600))
	profile := TransitProfile{ID: "tenant-mdoc", Label: "Tenant mdoc", OrgID: org, Address: server.URL, CAFile: caPath, TokenEnv: "CLAVEX_TEST_VAULT_TOKEN", Mount: "transit", Key: "mdoc", Version: 2}
	raw, err := json.Marshal([]TransitProfile{profile})
	require.NoError(t, err)
	path := filepath.Join(dir, "profiles.json")
	require.NoError(t, os.WriteFile(path, raw, 0600))
	registry := LoadRegistry(path)
	require.NoError(t, registry.err)
	t.Setenv(profile.TokenEnv, "secret-not-returned")
	require.Empty(t, registry.Choices(uuid.New()))
	require.Len(t, registry.Choices(org), 1)
	_, err = registry.Resolve(uuid.New(), profile.ID, &key.PublicKey)
	require.Error(t, err)
	require.Zero(t, requests)
	signer, err := registry.Resolve(org, profile.ID, &key.PublicKey)
	require.NoError(t, err)
	require.True(t, key.PublicKey.Equal(signer.Public()))
	require.Equal(t, 1, requests)
	_, err = registry.Resolve(org, profile.ID, &other.PublicKey)
	require.Error(t, err)
	exportable = true
	_, err = registry.Resolve(org, profile.ID, &key.PublicKey)
	require.Error(t, err)
	exportable = false
	backup = true
	_, err = registry.Resolve(org, profile.ID, &key.PublicKey)
	require.Error(t, err)
	backup = false
	derived = true
	_, err = registry.Resolve(org, profile.ID, &key.PublicKey)
	require.Error(t, err)
	derived = false
	version = "3"
	_, err = registry.Resolve(org, profile.ID, &key.PublicKey)
	require.Error(t, err)
}

func TestRegistryInvalidConfigurationFailsClosed(t *testing.T) {
	for _, raw := range []string{`[{"unknown":"field"}]`, `[] {}`, `[{"id":"../escape"}]`, `not json`} {
		path := filepath.Join(t.TempDir(), "profiles.json")
		require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
		r := LoadRegistry(path)
		require.Error(t, r.err)
		require.Empty(t, r.Choices(uuid.New()))
		_, err := r.Resolve(uuid.New(), "x", nil)
		require.Error(t, err)
	}
}
