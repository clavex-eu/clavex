package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/walletsigning"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestMdocProfilePKIPreservesKeysTrustAndRevokedSerials(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	config.ConnConfig.RuntimeParams["search_path"] = "identity,sessions,audit,public"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	defer pool.Close()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "synthetic profile test", orgSlug, nil)
	require.NoError(t, err)
	defer func() { _, e := pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID); require.NoError(t, e) }()
	_, err = pool.Exec(ctx, `UPDATE organizations SET conformance_mode=true WHERE id=$1`, org.ID)
	require.NoError(t, err)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root, ds, err := mdocFixtureCertificates(rootKey, dsKey, "https://issuer.example/conformance", time.Now().UTC())
	require.NoError(t, err)
	require.Equal(t, []string{"IT"}, root.Subject.Country)
	require.True(t, root.MaxPathLenZero)
	require.Equal(t, root.SubjectKeyId, ds.AuthorityKeyId)
	require.Less(t, ds.NotAfter.Sub(ds.NotBefore), 457*24*time.Hour)
	require.Len(t, ds.CRLDistributionPoints, 1)
	criticalEKU, issuerContact := false, false
	for _, e := range ds.Extensions {
		if e.Id.String() == "2.5.29.37" {
			criticalEKU = e.Critical
		}
		if e.Id.String() == "2.5.29.18" {
			issuerContact = true
		}
	}
	require.True(t, criticalEKU)
	require.True(t, issuerContact)
	encode := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	rootPEM := encode(root)
	dsPEM := encode(ds)
	_, _, err = walletsigning.Certificates(dsPEM, &rootPEM, false)
	require.NoError(t, err)
	dir := t.TempDir()
	var dsPrivate string
	for name, key := range map[string]*ecdsa.PrivateKey{"mdoc-iaca-private-key.pem": rootKey, "mdoc-ds-private-key.pem": dsKey} {
		der, e := x509.MarshalECPrivateKey(key)
		require.NoError(t, e)
		raw := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), raw, 0o600))
		if name == "mdoc-ds-private-key.pem" {
			dsPrivate = string(raw)
		}
	}
	for _, name := range []string{"oid4vci-issuer-mso-mdoc-plan.json", "oid4vci-issuer-mso-mdoc-encrypted-plan.json"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(`{"credential":{"format":"mso_mdoc"}}`), 0o600))
	}
	issuers := repository.NewMdocIssuerRepository(pool)
	before, err := issuers.Create(ctx, org.ID, "synthetic", mdoc.DocTypeMdl, dsPrivate, dsPEM, &rootPEM, 24)
	require.NoError(t, err)
	require.NoError(t, seedMdocTrust(ctx, pool, org.ID))
	require.Error(t, seedMdocPKI(ctx, pool, org.ID, dir, "http://issuer.example", false))
	require.NoError(t, seedMdocPKI(ctx, pool, org.ID, dir, "https://issuer.example", false))
	after, err := issuers.GetActiveByDocType(ctx, org.ID, mdoc.DocTypeMdl)
	require.NoError(t, err)
	require.Equal(t, before.DSPrivateKeyPEM, after.DSPrivateKeyPEM)
	require.Equal(t, before.ID, after.ID)
	require.NotEqual(t, before.DSCertificatePEM, after.DSCertificatePEM)
	roots, err := repository.NewIACARepository(pool).List(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, roots, 2, "historical root remains available for existing credentials")
	block, _ := pem.Decode([]byte(*after.IACACertificatePEM))
	root, err = x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	fp := sha256.Sum256(root.Raw)
	fingerprint := hex.EncodeToString(fp[:])
	crls := repository.NewMdocCRLRepository(pool)
	der, err := crls.Get(ctx, org.ID, fingerprint)
	require.NoError(t, err)
	crl, err := repository.ValidateMdocCRL(root, der, time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(1), crl.Number.Int64())
	// Refresh preserves actual revocations and never rewrites the DS or keys.
	now := time.Now().UTC().Truncate(time.Second)
	der, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: now, NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(4242), RevocationTime: now.Add(-time.Hour)}}}, root, rootKey)
	require.NoError(t, err)
	_, err = crls.Put(ctx, org.ID, root, der)
	require.NoError(t, err)
	_, err = crls.Put(ctx, org.ID, root, der)
	require.Error(t, err, "CRL numbers cannot be replayed or rolled back")
	require.NoError(t, seedMdocPKI(ctx, pool, org.ID, dir, "https://issuer.example", true))
	refreshed, err := issuers.GetActiveByDocType(ctx, org.ID, mdoc.DocTypeMdl)
	require.NoError(t, err)
	require.Equal(t, after, refreshed)
	der, err = crls.Get(ctx, org.ID, fingerprint)
	require.NoError(t, err)
	crl, err = repository.ValidateMdocCRL(root, der, time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(3), crl.Number.Int64())
	require.Len(t, crl.RevokedCertificateEntries, 1)
	require.Equal(t, int64(4242), crl.RevokedCertificateEntries[0].SerialNumber.Int64())
	_, err = repository.ValidateMdocCRL(root, der, crl.NextUpdate.Add(time.Second))
	require.Error(t, err, "expired CRLs are not served")
}
