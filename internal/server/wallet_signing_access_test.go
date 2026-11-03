package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestWalletSignerRoutesRequireInstallationSuperadmin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "signer.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600))
	keys, err := oidc.LoadKeySet(path)
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Auth.AdminSecret = "isolated-admin-secret-long-enough-for-tests"
	srv := New(cfg, nil, nil, keys)
	org := uuid.NewString()
	for _, prefix := range []string{"/api/v1/organizations/", "/api/v1/superadmin/organizations/"} {
		for _, endpoint := range []struct{ method, path string }{{"GET", "/issuers"}, {"GET", "/vault-signers"}, {"POST", "/issuers"}, {"POST", "/issuers/generate"}, {"DELETE", "/issuers/" + uuid.NewString()}} {
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": uuid.NewString(), "org_id": org, "is_admin": true, "is_super_admin": false, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(cfg.Auth.AdminSecret))
			require.NoError(t, err)
			req := httptest.NewRequest(endpoint.method, prefix+org+"/mdoc"+endpoint.path, strings.NewReader(`{}`))
			req.Host = "" // Host routing is outside this authorisation test.
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.echo.ServeHTTP(rec, req)
			require.Equal(t, http.StatusForbidden, rec.Code, endpoint.method+" "+prefix+endpoint.path+" "+rec.Body.String())
			require.Contains(t, rec.Body.String(), "superadmin access required")
		}
	}
	// A superadmin may select an organisation different from their login tenant.
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": uuid.NewString(), "org_id": uuid.NewString(), "is_admin": true, "is_super_admin": true, "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(cfg.Auth.AdminSecret))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/superadmin/organizations/"+org+"/mdoc/vault-signers", nil)
	req.Host = "" // Host routing is outside this authorisation test.
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.echo.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.JSONEq(t, "[]", rec.Body.String())
}
