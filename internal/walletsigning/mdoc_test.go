package walletsigning

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	secretcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func mdocPair(t *testing.T) (string, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	require.NoError(t, err)
	ds, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &ds.PublicKey, key)
	require.NoError(t, err)
	pk, err := x509.MarshalPKCS8PrivateKey(ds)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
}

func TestMdocEncryptedAndLegacyKeys(t *testing.T) {
	cert, key, ca := mdocPair(t)
	enc := secretcrypto.NewEncryptor("isolated-test-master-secret")
	encrypted, err := EncryptKey(enc, key)
	require.NoError(t, err)
	require.NotContains(t, encrypted, "PRIVATE KEY")
	for _, raw := range []string{encrypted, key} {
		rec := &models.OrgMdocIssuer{OrgID: uuid.New(), DSCertificatePEM: cert, IACACertificatePEM: &ca, DSPrivateKeyPEM: &raw}
		signer, chain, err := ResolveMdoc(rec, enc, nil)
		require.NoError(t, err)
		require.NotNil(t, signer)
		require.Len(t, chain, 1)
	}
	rec := &models.OrgMdocIssuer{DSCertificatePEM: cert, IACACertificatePEM: &ca, DSPrivateKeyPEM: &encrypted}
	_, _, err = ResolveMdoc(rec, secretcrypto.NewEncryptor("wrong-master-secret"), nil)
	require.Error(t, err)
	_, _, err = ResolveMdoc(rec, nil, nil)
	require.Error(t, err)
	require.NoError(t, func() error { _, _, err := Certificates(cert, &ca, false); return err }())
	_, _, err = Certificates(cert, nil, false)
	require.Error(t, err)
	_, _, err = Certificates(ca, &ca, false)
	require.Error(t, err)
	_, _, err = Certificates(cert+key, &ca, false)
	require.Error(t, err)
	_, _, err = Certificates(cert, ptr(ca+key), false)
	require.Error(t, err)
	_, otherKey, _ := mdocPair(t)
	_, err = LocalKey(cert, otherKey)
	require.Error(t, err)
	_, err = LocalKey(cert, key+key)
	require.Error(t, err)
	rec.VaultSignerRef = "missing"
	_, _, err = ResolveMdoc(rec, enc, nil)
	require.Error(t, err)
}
func ptr(s string) *string { return &s }
