package oid4w

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func metadataTestMaterial(t *testing.T, change func(*x509.Certificate)) ([]byte, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "metadata test root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"issuer.example"}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if change != nil {
		change(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), key
}

func TestCertificateMetadataSignerProducesVerifiableX5C(t *testing.T) {
	chain, keyPEM, key := metadataTestMaterial(t, nil)
	signer, err := newCertificateMetadataSigner(chain, keyPEM)
	require.NoError(t, err)
	token, err := SignIssuerMetadata(&CredentialIssuerMetadata{CredentialIssuer: "https://issuer.example/tenant"}, signer)
	require.NoError(t, err)
	verified, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.ES256, &key.PublicKey))
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example/tenant", verified.Subject())
	require.Equal(t, signer.certificates[0].NotAfter, verified.Expiration())
	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	require.NoError(t, err)
	var header struct {
		X5C []string `json:"x5c"`
		JWK any      `json:"jwk"`
		Typ string   `json:"typ"`
	}
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	require.Len(t, header.X5C, 1, "the root must not be transmitted")
	require.Nil(t, header.JWK)
	require.Equal(t, "openidvci-issuer-metadata+jwt", header.Typ)
	der, err := base64.StdEncoding.DecodeString(header.X5C[0])
	require.NoError(t, err)
	require.Equal(t, signer.certificates[0].Raw, der)
	for _, issuer := range []string{"http://issuer.example/tenant", "https://other.example/tenant", "https://user@issuer.example/tenant", "https://issuer.example/tenant#fragment"} {
		_, err := SignIssuerMetadata(&CredentialIssuerMetadata{CredentialIssuer: issuer}, signer)
		require.Error(t, err)
	}
	// Revalidate at request time, rather than trusting only the startup check.
	signer.certificates[0].NotAfter = time.Now().Add(-time.Minute)
	_, err = SignIssuerMetadata(&CredentialIssuerMetadata{CredentialIssuer: "https://issuer.example/tenant"}, signer)
	require.Error(t, err)
}

func TestCertificateMetadataSignerRejectsInvalidMaterial(t *testing.T) {
	for name, change := range map[string]func(*x509.Certificate){
		"expired":               func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) },
		"future":                func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) },
		"CA leaf":               func(c *x509.Certificate) { c.IsCA = true },
		"missing signing usage": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
	} {
		t.Run(name, func(t *testing.T) {
			chain, key, _ := metadataTestMaterial(t, change)
			_, err := newCertificateMetadataSigner(chain, key)
			require.Error(t, err)
		})
	}
	chain, key, _ := metadataTestMaterial(t, nil)
	_, otherKey, _ := metadataTestMaterial(t, nil)
	leaf, rest := pem.Decode(chain)
	require.NotNil(t, leaf)
	for name, raw := range map[string][]byte{"missing root": pem.EncodeToMemory(leaf), "reversed": append(append([]byte{}, rest...), pem.EncodeToMemory(leaf)...), "trailing key": append(append([]byte{}, chain...), key...), "garbage": append([]byte("garbage"), chain...)} {
		t.Run(name, func(t *testing.T) { _, err := newCertificateMetadataSigner(raw, key); require.Error(t, err) })
	}
	_, err := newCertificateMetadataSigner(chain, otherKey)
	require.Error(t, err)
	_, err = LoadCertificateMetadataSigner("certificate-only", "")
	require.Error(t, err)
}
