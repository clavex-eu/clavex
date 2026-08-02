package vaultpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── pure functions ───────────────────────────────────────────────────────────

func TestHasCapability(t *testing.T) {
	cases := []struct {
		caps []string
		want string
		ok   bool
	}{
		{[]string{"create", "read"}, "create", true},
		{[]string{"read", "delete"}, "delete", true},
		{[]string{"root"}, "create", true}, // root implies all
		{[]string{"sudo"}, "delete", true}, // sudo implies all
		{[]string{"read"}, "create", false},
		{[]string{"deny"}, "delete", false},
		{nil, "create", false},
	}
	for _, tc := range cases {
		if got := HasCapability(tc.caps, tc.want); got != tc.ok {
			t.Errorf("HasCapability(%v, %q) = %v, want %v", tc.caps, tc.want, got, tc.ok)
		}
	}
}

func genTestCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestFingerprintSHA256(t *testing.T) {
	certPEM := genTestCertPEM(t)

	fp1, err := FingerprintSHA256(certPEM)
	require.NoError(t, err)
	assert.Contains(t, fp1, "SHA256:")

	fp2, err := FingerprintSHA256(certPEM)
	require.NoError(t, err)
	assert.Equal(t, fp1, fp2, "same cert must always fingerprint identically")
}

func TestFingerprintSHA256_InvalidPEM(t *testing.T) {
	_, err := FingerprintSHA256("not a pem certificate")
	assert.Error(t, err)
}

// ── HTTP wire-format tests against a fake Vault ─────────────────────────────

func newFakeVault(t *testing.T, handler http.HandlerFunc) (addr, token string, srv *httptest.Server) {
	t.Helper()
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	SetHTTPClient(srv.Client(), true) // relaxed SSRF guard so httptest's 127.0.0.1 is reachable
	t.Cleanup(func() { SetHTTPClient(nil, false) })
	return srv.URL, "test-token", srv
}

func requireVaultToken(t *testing.T, r *http.Request, want string) {
	t.Helper()
	assert.Equal(t, want, r.Header.Get("X-Vault-Token"))
}

func TestEnablePKIMount(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		requireVaultToken(t, r, "test-token")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})

	err := EnablePKIMount(context.Background(), addr, "pki-device-org1", token)
	require.NoError(t, err)
	assert.Equal(t, "/v1/sys/mounts/pki-device-org1", gotPath)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "pki", gotBody["type"])
}

func TestEnablePKIMount_ErrorStatus(t *testing.T) {
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["mount already exists"]}`))
	})
	err := EnablePKIMount(context.Background(), addr, "pki-device-org1", token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mount already exists")
}

func TestGenerateRootCA(t *testing.T) {
	wantCert := genTestCertPEM(t)
	var gotPath string
	var gotBody map[string]any
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"certificate": wantCert},
		})
	})

	got, err := GenerateRootCA(context.Background(), addr, "pki-device-org1", token, "Clavex Device CA - org1", 315360000)
	require.NoError(t, err)
	assert.Equal(t, wantCert, got)
	assert.Equal(t, "/v1/pki-device-org1/root/generate/internal", gotPath)
	assert.Equal(t, "Clavex Device CA - org1", gotBody["common_name"])
	assert.Equal(t, "315360000s", gotBody["ttl"])
}

func TestGenerateRootCA_FallsBackToFetchOn204(t *testing.T) {
	wantCert := genTestCertPEM(t)
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// GET .../ca/pem
		_, _ = w.Write([]byte(wantCert))
	})

	got, err := GenerateRootCA(context.Background(), addr, "pki-device-org1", token, "cn", 3600)
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(wantCert), got) // FetchCACertificate trims the raw response body
}

func TestFetchCACertificate(t *testing.T) {
	wantCert := genTestCertPEM(t)
	var gotPath string
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(wantCert))
	})

	got, err := FetchCACertificate(context.Background(), addr, "pki-device-org1", token)
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(wantCert), got)
	assert.Equal(t, "/v1/pki-device-org1/ca/pem", gotPath)
}

func TestFetchCACertificate_ErrorStatus(t *testing.T) {
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := FetchCACertificate(context.Background(), addr, "pki-device-org1", token)
	assert.Error(t, err)
}

func TestConfigureDeviceRole(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})

	err := ConfigureDeviceRole(context.Background(), addr, "pki-device-org1", "device", token, 604800)
	require.NoError(t, err)
	assert.Equal(t, "/v1/pki-device-org1/roles/device", gotPath)
	// The critical, non-negotiable role config: CN is "<deviceID>@<tenantID>",
	// not a DNS hostname, so any_name must be allowed and hostname enforcement
	// disabled, and the only usable EKU must be ClientAuth.
	assert.Equal(t, true, gotBody["allow_any_name"])
	assert.Equal(t, false, gotBody["enforce_hostnames"])
	assert.Equal(t, true, gotBody["client_flag"])
	assert.Equal(t, false, gotBody["server_flag"])
	assert.Equal(t, "604800s", gotBody["ttl"])
	ekus, ok := gotBody["ext_key_usage"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"ClientAuth"}, ekus)
}

func TestConfigureDeviceRole_DefaultsTTLWhenZero(t *testing.T) {
	var gotBody map[string]any
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	err := ConfigureDeviceRole(context.Background(), addr, "m", "r", token, 0)
	require.NoError(t, err)
	assert.Equal(t, "604800s", gotBody["ttl"])
}

func TestSignCSR(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate":   "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
				"issuing_ca":    "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
				"serial_number": "17:36:7c:00:ff",
				"expiration":    time.Now().Add(time.Hour).Unix(),
			},
		})
	})

	result, err := SignCSR(context.Background(), addr, "pki-device-org1", "device", token, "csr-pem", "device-1@org-1", 604800)
	require.NoError(t, err)
	assert.Equal(t, "/v1/pki-device-org1/sign/device", gotPath)
	assert.Equal(t, "csr-pem", gotBody["csr"])
	assert.Equal(t, "device-1@org-1", gotBody["common_name"])
	assert.Contains(t, result.CertificatePEM, "leaf")
	assert.Contains(t, result.IssuingCAPEM, "ca")
	assert.Equal(t, "17:36:7c:00:ff", result.SerialNumber)
}

func TestSignCSR_MissingCertificateInResponse(t *testing.T) {
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
	})
	_, err := SignCSR(context.Background(), addr, "m", "r", token, "csr", "cn", 3600)
	assert.Error(t, err)
}

func TestSignCSR_ErrorStatus(t *testing.T) {
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["common_name not allowed by this role"]}`))
	})
	_, err := SignCSR(context.Background(), addr, "m", "r", token, "csr", "cn", 3600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "common_name not allowed")
}

func TestRevokeCertificate(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	})
	err := RevokeCertificate(context.Background(), addr, "pki-device-org1", token, "17:36:7c:00:ff")
	require.NoError(t, err)
	assert.Equal(t, "/v1/pki-device-org1/revoke", gotPath)
	assert.Equal(t, "17:36:7c:00:ff", gotBody["serial_number"])
}

func TestDisableMount(t *testing.T) {
	var gotPath, gotMethod string
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusNoContent)
	})
	err := DisableMount(context.Background(), addr, "pki-device-org1-rot-abc123", token)
	require.NoError(t, err)
	assert.Equal(t, "/v1/sys/mounts/pki-device-org1-rot-abc123", gotPath)
	assert.Equal(t, http.MethodDelete, gotMethod)
}

func TestCheckCapabilities(t *testing.T) {
	var gotBody map[string]any
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"capabilities": []string{"create", "read"}},
		})
	})
	caps, err := CheckCapabilities(context.Background(), addr, token, "sys/mounts/pki-device-org1")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"create", "read"}, caps)
	paths, ok := gotBody["paths"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"sys/mounts/pki-device-org1"}, paths)
}

func TestCheckCapabilities_ErrorStatus(t *testing.T) {
	addr, token, _ := newFakeVault(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := CheckCapabilities(context.Background(), addr, token, "sys/mounts/x")
	assert.Error(t, err)
}
