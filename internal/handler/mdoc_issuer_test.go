package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secretcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/walletsigning"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func mdocAdminRequest(t *testing.T, org uuid.UUID, handle echo.HandlerFunc, method string, body any) (*httptest.ResponseRecorder, error) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(method, "/", bytes.NewReader(raw))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("org_id")
	ctx.SetParamValues(org.String())
	return rec, handle(ctx)
}

func TestMdocImportRejectsUnsafeMaterialBeforeDatabase(t *testing.T) {
	handler := NewMdocIssuerHandler(nil).WithSigningStorage(secretcrypto.NewEncryptor("test"), walletsigning.LoadRegistry(""))
	for _, body := range []map[string]any{
		{"display_name": "test", "doc_type": mdoc.DocTypeEuPid, "ds_certificate_pem": "not a cert", "ds_private_key_pem": "secret"},
		{"display_name": "test", "doc_type": mdoc.DocTypeEuPid, "ds_certificate_pem": "cert", "ds_private_key_pem": "secret", "vault_signer_ref": "foreign"},
		{"display_name": "test", "doc_type": mdoc.DocTypeEuPid, "ds_certificate_pem": "cert"},
	} {
		_, err := mdocAdminRequest(t, uuid.New(), handler.Create, http.MethodPost, body)
		var httpErr *echo.HTTPError
		require.ErrorAs(t, err, &httpErr)
		require.Equal(t, http.StatusBadRequest, httpErr.Code)
		require.NotContains(t, httpErr.Message, "secret")
	}
}

func TestMdocPublicViewNeverReturnsKeyMaterial(t *testing.T) {
	rec := &models.OrgMdocIssuer{ID: uuid.New(), DSCertificatePEM: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----", DSPrivateKeyPEM: func() *string { s := "private-secret"; return &s }()}
	raw, err := json.Marshal(mdocPublicView(rec))
	require.NoError(t, err)
	require.NotContains(t, string(raw), "secret")
	require.NotContains(t, string(raw), "PRIVATE KEY")
	require.Contains(t, string(raw), `"certificate_error":true`)
}

func TestMdocAdminEncryptedImportAndExplicitReplacement(t *testing.T) {
	f := vciFixture(t)
	enc := secretcrypto.NewEncryptor("isolated-wallet-test-master-secret")
	handler := NewMdocIssuerHandler(f.pool).WithSigningStorage(enc, walletsigning.LoadRegistry(""))
	chainPath, keyPath := testWalletCertificateFiles(t)
	chain, err := os.ReadFile(chainPath)
	require.NoError(t, err)
	leaf, rest := pem.Decode(chain)
	require.NotNil(t, leaf)
	key, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	body := map[string]any{"display_name": "Test DS", "doc_type": mdoc.DocTypeEuPid, "ds_certificate_pem": string(pem.EncodeToMemory(leaf)), "iaca_certificate_pem": string(rest), "ds_private_key_pem": string(key), "validity_hours": 720}
	rec, err := mdocAdminRequest(t, f.org.ID, handler.Create, http.MethodPost, body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, rec.Code)
	require.NotContains(t, rec.Body.String(), "PRIVATE KEY")
	require.NotContains(t, rec.Body.String(), "ds_private_key_pem")
	stored, err := handler.repo.GetActiveByDocType(context.Background(), f.org.ID, mdoc.DocTypeEuPid)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.NotNil(t, stored.DSPrivateKeyPEM)
	require.True(t, strings.HasPrefix(*stored.DSPrivateKeyPEM, "wallet-key:v1:"))
	require.NotContains(t, *stored.DSPrivateKeyPEM, string(key))
	signer, chainDER, err := walletsigning.ResolveMdoc(stored, enc, nil)
	require.NoError(t, err)
	require.Len(t, chainDER, 1)
	parsed, err := x509.ParseCertificate(leaf.Bytes)
	require.NoError(t, err)
	pub, ok := parsed.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	digest := sha256.Sum256([]byte("mdoc"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.True(t, ecdsa.VerifyASN1(pub, digest[:], signature))
	_, err = mdocAdminRequest(t, f.org.ID, handler.Create, http.MethodPost, body)
	var httpErr *echo.HTTPError
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.StatusConflict, httpErr.Code)
	body["replace_existing"] = true
	rec, err = mdocAdminRequest(t, f.org.ID, handler.Create, http.MethodPost, body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, rec.Code)
	rec, err = mdocAdminRequest(t, uuid.New(), handler.List, http.MethodGet, nil)
	require.NoError(t, err)
	require.JSONEq(t, "[]", rec.Body.String())
	rec, err = mdocAdminRequest(t, f.org.ID, handler.List, http.MethodGet, nil)
	require.NoError(t, err)
	require.NotContains(t, rec.Body.String(), "PRIVATE KEY")
	require.Contains(t, rec.Body.String(), "sha256_fingerprint")
	// The actual issuance path resolves the encrypted key; no OIDC key substitute.
	f.h.WithMdocSigningStorage(enc, nil)
	f.cfg.VCT = mdoc.DocTypeEuPid
	issued, err := f.h.issueMdocCredential(context.Background(), f.org, f.cfg, nil, map[string]interface{}{"given_name": "Test"}, nil, oid4w.StatusClaim{})
	require.NoError(t, err)
	require.NotEmpty(t, issued)
}

func TestMdocVaultImportAndIssuanceWithoutStoredPrivateKey(t *testing.T) {
	f := vciFixture(t)
	chainPath, keyPath := testWalletCertificateFiles(t)
	raw, err := os.ReadFile(chainPath)
	require.NoError(t, err)
	leaf, ca := pem.Decode(raw)
	require.NotNil(t, leaf)
	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block)
	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	key, ok := rawKey.(*ecdsa.PrivateKey)
	require.True(t, ok)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "isolated-test-vault-token", r.Header.Get("X-Vault-Token"))
		if r.Method == http.MethodGet {
			require.Equal(t, "/v1/transit/keys/tenant-mdoc", r.URL.Path)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false, "derived": false, "keys": map[string]any{"3": map[string]string{"public_key": pubPEM}}}}))
			return
		}
		require.Equal(t, "/v1/transit/sign/tenant-mdoc", r.URL.Path)
		var req struct {
			Input     string `json:"input"`
			Version   int    `json:"key_version"`
			Prehashed bool   `json:"prehashed"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, 3, req.Version)
		require.True(t, req.Prehashed)
		digest, err := base64.StdEncoding.DecodeString(req.Input)
		require.NoError(t, err)
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
		require.NoError(t, err)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": "vault:v3:" + base64.StdEncoding.EncodeToString(sig)}}))
	}))
	defer server.Close()
	dir := t.TempDir()
	tlsCA := filepath.Join(dir, "vault-tls-ca.pem")
	require.NoError(t, os.WriteFile(tlsCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600))
	profilePath := filepath.Join(dir, "profiles.json")
	profiles, err := json.Marshal([]walletsigning.TransitProfile{{ID: "tenant-mdoc", Label: "Test Vault DS", OrgID: f.org.ID, Address: server.URL, CAFile: tlsCA, TokenEnv: "CLAVEX_MOCK_WALLET_VAULT_TOKEN", Mount: "transit", Key: "tenant-mdoc", Version: 3}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(profilePath, profiles, 0600))
	t.Setenv("CLAVEX_MOCK_WALLET_VAULT_TOKEN", "isolated-test-vault-token")
	registry := walletsigning.LoadRegistry(profilePath)
	require.NoError(t, registry.Err())
	h := NewMdocIssuerHandler(f.pool).WithSigningStorage(secretcrypto.NewEncryptor("test-key"), registry)
	body := map[string]any{"display_name": "Vault DS", "doc_type": mdoc.DocTypeEuPid, "ds_certificate_pem": string(pem.EncodeToMemory(leaf)), "iaca_certificate_pem": string(ca), "vault_signer_ref": "tenant-mdoc", "validity_hours": 24}
	rec, err := mdocAdminRequest(t, f.org.ID, h.Create, http.MethodPost, body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, rec.Code)
	require.NotContains(t, rec.Body.String(), "PRIVATE KEY")
	require.NotContains(t, rec.Body.String(), "isolated-test-vault-token")
	stored, err := h.repo.GetActiveByDocType(context.Background(), f.org.ID, mdoc.DocTypeEuPid)
	require.NoError(t, err)
	require.Nil(t, stored.DSPrivateKeyPEM)
	require.Equal(t, "tenant-mdoc", stored.VaultSignerRef)
	f.cfg.VCT = mdoc.DocTypeEuPid
	f.h.WithMdocSigningStorage(nil, registry)
	credential, err := f.h.issueMdocCredential(context.Background(), f.org, f.cfg, nil, map[string]interface{}{"given_name": "Test"}, nil, oid4w.StatusClaim{})
	require.NoError(t, err)
	require.NotEmpty(t, credential)
	// An unauthorised tenant cannot discover or select the profile.
	rec, err = mdocAdminRequest(t, uuid.New(), h.VaultProfiles, http.MethodGet, nil)
	require.NoError(t, err)
	require.JSONEq(t, "[]", rec.Body.String())
	_, err = mdocAdminRequest(t, uuid.New(), h.Create, http.MethodPost, body)
	var httpErr *echo.HTTPError
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.StatusBadRequest, httpErr.Code)
}

func TestMdocSignerDowngradeGuard(t *testing.T) {
	f := vciFixture(t)
	downSQL, err := os.ReadFile("../db/migrations/000193_wallet_mdoc_signer.down.sql")
	require.NoError(t, err)
	for _, vaultRef := range []string{"", "tenant-mdoc"} {
		var key *string
		if vaultRef == "" {
			s := "wallet-key:v1:test-only-envelope"
			key = &s
		}
		_, err = f.h.mdocIssuers.CreateWithSigner(context.Background(), f.org.ID, "Rollback guard", mdoc.DocTypeEuPid, key, "test-only-public-placeholder", nil, 24, vaultRef, true)
		require.NoError(t, err)
		_, err = f.pool.Exec(context.Background(), string(downSQL))
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "P0001", pgErr.Code)
		require.Contains(t, pgErr.Message, "Review external references and encrypted DS keys")
		// The refused downgrade must leave both the schema and key reference intact.
		stored, err := f.h.mdocIssuers.GetActiveByDocType(context.Background(), f.org.ID, mdoc.DocTypeEuPid)
		require.NoError(t, err)
		require.Equal(t, vaultRef, stored.VaultSignerRef)
	}
}
