package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/fxamacker/cbor/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestSeedMdocTrustRestoresLocalVerificationWithoutReplacingKeys(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	config.ConnConfig.RuntimeParams["search_path"] = "identity,sessions,audit,public"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	defer pool.Close()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "mdoc trust test", orgSlug, nil)
	require.NoError(t, err)
	defer func() {
		_, err := pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org.ID)
		require.NoError(t, err)
	}()
	require.Error(t, seedMdocTrust(ctx, pool, org.ID))
	_, err = pool.Exec(ctx, `UPDATE organizations SET conformance_mode=true WHERE id=$1`, org.ID)
	require.NoError(t, err)
	require.Error(t, seedMdocTrust(ctx, pool, org.ID)) // no configured DS yet
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	dsTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, root, &dsKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	privateDER, err := x509.MarshalECPrivateKey(dsKey)
	require.NoError(t, err)
	issuers := repository.NewMdocIssuerRepository(pool)
	issuer, err := issuers.Create(ctx, org.ID, "synthetic", mdoc.DocTypeMdl, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dsDER})), &rootPEM, 24)
	require.NoError(t, err)
	repo := repository.NewOID4WRepository(pool)
	_, err = repo.LockIACAPool(ctx, org.ID, mdoc.DocTypeMdl)
	require.Error(t, err)
	attrs := map[string]interface{}{"given_name": "Synthetic"}
	mdoc.FillMdlMandatory(attrs)
	raw, err := mdoc.IssueMdoc(mdoc.IssuanceParams{DocType: mdoc.DocTypeMdl, Namespace: mdoc.NSMdl, Attributes: attrs, DSKey: dsKey, DSCertDER: dsDER, ValidityHours: 1, DevicePublicKey: &dsKey.PublicKey})
	require.NoError(t, err)
	var signed mdoc.IssuerSigned
	require.NoError(t, cbor.Unmarshal(raw, &signed))
	require.NoError(t, seedMdocTrust(ctx, pool, org.ID))
	require.NoError(t, seedMdocTrust(ctx, pool, org.ID))
	roots, err := repo.LockIACAPool(ctx, org.ID, mdoc.DocTypeMdl)
	require.NoError(t, err)
	verified, errs := mdoc.VerifyDeviceResponse(&mdoc.DeviceResponse{Version: "1.0", Status: 0, Documents: []mdoc.Document{{DocType: mdoc.DocTypeMdl, IssuerSigned: signed}}}, mdoc.VerificationOptions{TrustedRoots: roots, RequireTrustedIssuer: true})
	require.Empty(t, errs)
	require.Len(t, verified, 1)
	after, err := issuers.GetActiveByDocType(ctx, org.ID, mdoc.DocTypeMdl)
	require.NoError(t, err)
	require.Equal(t, issuer, after)
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM org_iaca_roots WHERE org_id=$1`, org.ID).Scan(&count))
	require.Equal(t, 1, count)
	_, err = pool.Exec(ctx, `UPDATE org_iaca_roots SET is_active=false WHERE org_id=$1`, org.ID)
	require.NoError(t, err)
	require.Error(t, seedMdocTrust(ctx, pool, org.ID)) // never silently undo operator distrust
	_, err = repo.LockIACAPool(ctx, org.ID, mdoc.DocTypeMdl)
	require.Error(t, err)
}
