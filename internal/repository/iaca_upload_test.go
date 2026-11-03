package repository

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIACAUploadAcceptsOnlyOnePublicCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	private, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	parsed, err := parseIACAUploadPEM("\n" + certificate + " \n")
	require.NoError(t, err)
	require.Equal(t, der, parsed.Raw)
	for name, raw := range map[string]string{
		"private key":          privatePEM,
		"certificate then key": certificate + privatePEM,
		"key then certificate": privatePEM + certificate,
		"certificate bundle":   certificate + certificate,
		"leading material":     "unrelated secret\n" + certificate,
		"trailing material":    certificate + "unrelated secret",
		"oversized":            strings.Repeat(" ", 2) + certificate + strings.Repeat("x", 65*1024),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseIACAUploadPEM(raw)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "unrelated secret")
		})
	}
	// Existing configured anchors retain their previous read interpretation;
	// stricter upload validation does not rewrite or silently revoke them.
	legacy, err := parseSingleCertPEM(certificate + certificate)
	require.NoError(t, err)
	require.Equal(t, der, legacy.Raw)
}
