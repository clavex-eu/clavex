package handler

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

func TestWalletStatusMdocIssuanceDeliveryAndRevocation(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	rootKey, dsKey, holder := vciTestHolder(t), vciTestHolder(t), vciTestHolder(t)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	dsTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic DS"}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, root, &dsKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	_, err = repository.NewIACARepository(f.pool).Create(ctx, f.org.ID, "test", rootPEM, []string{mdoc.DocTypeEuPid}, nil)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(dsKey)
	require.NoError(t, err)
	_, err = f.h.mdocIssuers.Create(ctx, f.org.ID, "test", mdoc.DocTypeEuPid, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dsDER})), &rootPEM, 1)
	require.NoError(t, err)
	cfg := *f.cfg
	cfg.CredentialFormat = "mso_mdoc"
	cfg.VCT = mdoc.DocTypeEuPid
	_, err = f.pool.Exec(ctx, `UPDATE identity.organizations SET settings='{"wallet_certificate_revocation_required":false}' WHERE id=$1`, f.org.ID)
	require.NoError(t, err)
	h, tx, err := f.h.beginCredentialIssuance(ctx, nil, "")
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	holderKey, err := jwk.FromRaw(&holder.PublicKey)
	require.NoError(t, err)
	raw, err := h.signCredential(ctx, f.org, &cfg, nil, map[string]interface{}{"given_name": "Alice"}, holderKey)
	require.NoError(t, err)
	require.NoError(t, h.recordWalletCredential(ctx, f.org.ID, nil, cfg.VCT, raw, nil, cfg.CredentialFormat))
	require.NoError(t, h.checkDeferredCredentialStatus(ctx, f.org, &cfg, raw))
	require.NoError(t, tx.Commit(ctx))
	record, err := f.h.repo.GetIssuedCredentialByHash(ctx, f.org.ID, oid4w.HashToken(raw))
	require.NoError(t, err)
	require.NotNil(t, record.StatusListID)
	encoded, err := base64.RawURLEncoding.DecodeString(raw)
	require.NoError(t, err)
	var signed mdoc.IssuerSigned
	require.NoError(t, cbor.Unmarshal(encoded, &signed))
	before, err := mdoc.IssuerAuthenticationHash(signed.IssuerAuth)
	require.NoError(t, err)
	// Removing a disclosed attribute leaves the signed issuer identity unchanged.
	signed.NameSpaces = map[string][]mdoc.IssuerSignedItemRaw{}
	after, err := mdoc.IssuerAuthenticationHash(signed.IssuerAuth)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.NoError(t, f.h.repo.SuspendIssuedCredential(ctx, record.ID, "temporary"))
	check := func() error {
		h, tx, err := f.h.beginCredentialIssuance(ctx, nil, "")
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		return h.checkDeferredCredentialStatus(ctx, f.org, &cfg, raw)
	}
	require.ErrorIs(t, check(), errWalletStatusRejected)
	require.NoError(t, f.h.repo.RestoreIssuedCredential(ctx, record.ID))
	require.NoError(t, check())
	require.NoError(t, f.h.repo.RevokeIssuedCredential(ctx, record.ID, "terminal"))
	require.ErrorIs(t, check(), errWalletStatusRejected)
	// Root deactivation is independently enforced, even when certificate CRLs
	// were explicitly disabled for these synthetic development certificates.
	_, err = f.pool.Exec(ctx, `UPDATE identity.org_iaca_roots SET is_active=false WHERE org_id=$1`, f.org.ID)
	require.NoError(t, err)
	h, tx, err = f.h.beginCredentialIssuance(ctx, nil, "")
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = h.verifiedIssuedMdoc(ctx, f.org.ID, cfg.VCT, raw)
	require.Error(t, err)
}
