package handler

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/require"
)

func TestDedicatedCredentialKeySelectionPreservesLegacyAndTenantBoundary(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), 0600))
	keys, err := oidc.LoadKeySet(path)
	require.NoError(t, err)
	dedicated := vciTestHolder(t)
	other := vciTestHolder(t)
	h := &OID4VPHandler{keys: keys, credentialSigningPublicKey: &dedicated.PublicKey}
	const issuer = "https://issuer.example/tenant"
	for _, tc := range []struct {
		name, iss string
		key       crypto.Signer
		alg       jwa.SignatureAlgorithm
		want      crypto.PublicKey
	}{
		{"dedicated local", issuer, dedicated, jwa.ES256, &dedicated.PublicKey},
		{"legacy local", issuer, rsaKey, jwa.PS256, &rsaKey.PublicKey},
		{"other tenant", "https://issuer.example/another-tenant", dedicated, jwa.ES256, &rsaKey.PublicKey},
		{"unknown key", issuer, other, jwa.ES256, &rsaKey.PublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			presentation, _, err := oid4w.IssueSDJWT(oid4w.SDJWTParams{Issuer: tc.iss, Subject: "fictional", VCT: "urn:example:test", TTL: time.Hour, Signer: tc.key, Alg: tc.alg})
			require.NoError(t, err)
			require.Equal(t, tc.want, h.localCredentialVerificationKey(presentation, issuer))
		})
	}
	require.Equal(t, &rsaKey.PublicKey, h.localCredentialVerificationKey("malformed", issuer))
	presentation, _, err := oid4w.IssueSDJWT(oid4w.SDJWTParams{Issuer: issuer, Subject: "fictional", VCT: "urn:example:test", TTL: 24 * time.Hour, Signer: dedicated, Alg: jwa.ES256})
	require.NoError(t, err)
	h.WithCredentialSigningPublicKey(&dedicated.PublicKey, time.Now().Add(-2*time.Hour), time.Now().Add(48*time.Hour))
	require.Equal(t, &dedicated.PublicKey, h.localCredentialVerificationKey(presentation, issuer))
	h.credentialKeyNotAfter = time.Now().Add(time.Minute)
	require.Equal(t, &rsaKey.PublicKey, h.localCredentialVerificationKey(presentation, issuer), "a credential must not outlive its signing certificate")
	h.credentialKeyNotAfter = time.Now().Add(-time.Minute)
	require.Equal(t, &rsaKey.PublicKey, h.localCredentialVerificationKey(presentation, issuer), "expired certificate key must not be selected")
}
