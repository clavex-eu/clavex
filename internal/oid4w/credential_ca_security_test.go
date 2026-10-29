package oid4w

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCredentialCANeedsSecretMaterialEvenWhenCached(t *testing.T) {
	key := newTestKey(t)
	_, err := BuildIssuerCACertDER(key)
	require.NoError(t, err)
	_, err = deriveCAKey(&rsa.PrivateKey{PublicKey: key.PublicKey})
	require.Error(t, err)
	_, err = deriveCAKey(nil)
	require.Error(t, err)
}

func TestCredentialCAStableButDifferentFromPublicDerivedCA(t *testing.T) {
	key := newTestKey(t)
	first, err := BuildIssuerCACertDER(key)
	require.NoError(t, err)
	caKeyCacheMu.Lock()
	delete(caKeyCache, string(key.N.Bytes()))
	caKeyCacheMu.Unlock()
	second, err := BuildIssuerCACertDER(key)
	require.NoError(t, err)
	require.Equal(t, first, second, "CA must remain stable across cache eviction/restart")
	cert, err := x509.ParseCertificate(first)
	require.NoError(t, err)
	h := sha256.New()
	h.Write(key.N.Bytes())
	h.Write([]byte("clavex-x5c-ca-v1"))
	old, err := ecdh.P256().NewPrivateKey(h.Sum(nil))
	require.NoError(t, err)
	newPublic, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)
	oldECDSA, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), old.PublicKey().Bytes())
	require.NoError(t, err)
	oldPublic, err := x509.MarshalPKIXPublicKey(oldECDSA)
	require.NoError(t, err)
	require.NotEqual(t, newPublic, oldPublic, "old publicly reconstructible key must not remain the trust anchor")
	require.True(t, cert.IsCA)
	require.NoError(t, cert.CheckSignatureFrom(cert))
}
