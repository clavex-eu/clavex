package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testWalletCertificateFiles(t *testing.T) (string, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(3 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"issuer.example"}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	chainPath, keyPath := filepath.Join(dir, "chain.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(chainPath, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...), 0600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600))
	return chainPath, keyPath
}

func TestCertificateDeferredDeliveryAndRevocation(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(fmt.Sprint(revoked), func(t *testing.T) {
			f := vciFixture(t)
			chain, key := testWalletCertificateFiles(t)
			f.h.WithCredentialSigningFiles(chain, key)
			require.NoError(t, f.h.credentialSigningErr)
			tokens := startWallet(t, f, deferredOffer(t, f, nil))
			txn, _ := requestDeferred(t, f, tokens)
			rec := approveWalletDeferred(t, f, txn)
			require.Equal(t, 200, rec.Code, rec.Body.String())
			dc, err := f.h.repo.GetDeferredCredential(context.Background(), txn)
			require.NoError(t, err)
			signed, err := f.h.verifyLocalIssuedSDJWT(*dc.CredentialJWT)
			require.NoError(t, err)
			stored, err := f.h.repo.GetIssuedCredentialByHash(context.Background(), f.org.ID, oid4w.HashToken(*dc.CredentialJWT))
			require.NoError(t, err)
			require.WithinDuration(t, signed.Identity.ExpiresAt, *stored.ExpiresAt, time.Second)
			if revoked {
				require.NoError(t, f.h.repo.RevokeIssuedCredential(context.Background(), stored.ID, "test"))
			}
			rec = walletHTTP(t, f, f.h.DeferredCredential, "oid4vci/deferred-credential", nil, map[string]string{"transaction_id": txn}, tokens.Access, "", nil)
			if revoked {
				require.Equal(t, 400, rec.Code, rec.Body.String())
			} else {
				require.Equal(t, 200, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCertificateIssuedCredentialApprovesOnlyItsCIBAAccount(t *testing.T) {
	f := newCibaWalletFixture(t)
	chain, key := testWalletCertificateFiles(t)
	f.vciIssuanceFixture.h.WithCredentialSigningFiles(chain, key)
	require.NoError(t, f.vciIssuanceFixture.h.credentialSigningErr)
	start, end := f.vciIssuanceFixture.h.CredentialSigningKeyValidity()
	f.h.WithCredentialSigningPublicKey(f.vciIssuanceFixture.h.CredentialSigningPublicKey(), start, end)
	raw, holder, _ := issueStatusCredential(t, f.vciIssuanceFixture, &f.user.ID)
	se, auth := f.request(t, false)
	presentation := presentStatusCredential(t, raw, holder, se.Nonce, se.ClientID, false)
	rec := f.submit(t, se, presentation, false)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	approved, err := f.ciba.Get(context.Background(), auth)
	require.NoError(t, err)
	require.Equal(t, "approved", approved.Status)

	// A valid credential from the same dedicated issuer key is still not proof
	// of ownership of another account. Existing account binding must fail closed.
	other, err := f.vciIssuanceFixture.h.users.Create(context.Background(), f.org.ID, "another@example.invalid", nil, nil)
	require.NoError(t, err)
	f.user = other
	se, auth = f.request(t, false)
	presentation = presentStatusCredential(t, raw, holder, se.Nonce, se.ClientID, false)
	rec = f.submit(t, se, presentation, false)
	require.NotEqual(t, 200, rec.Code)
	pending, err := f.ciba.Get(context.Background(), auth)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Status)
}
