package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestMdocCRLPublicEndpointVerifiesFreshnessAndTenantScope(t *testing.T) {
	f := vciFixture(t)
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic CRL issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	der, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(42), RevocationTime: now.Add(-time.Minute)}}}, root, key)
	require.NoError(t, err)
	fingerprint, err := f.h.mdocCRLs.Put(ctx, f.org.ID, root, der)
	require.NoError(t, err)
	tampered := append([]byte(nil), der...)
	tampered[len(tampered)-1] ^= 1
	_, err = f.h.mdocCRLs.Put(ctx, f.org.ID, root, tampered)
	require.Error(t, err, "a forged CRL cannot replace the signed publication")
	request := func(slug, fp string) *httptest.ResponseRecorder {
		e := echo.New()
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
		c.SetParamNames("org_slug", "fingerprint")
		c.SetParamValues(slug, fp)
		if err := f.h.MdocIACACRL(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		return rec
	}
	r := request(f.org.Slug, fingerprint)
	require.Equal(t, 200, r.Code)
	require.Equal(t, "application/pkix-crl", r.Header().Get("Content-Type"))
	require.Equal(t, der, r.Body.Bytes())
	wrong, err := f.h.orgs.Create(ctx, "other CRL tenant", "crl-other-"+uuid.NewString(), nil)
	require.NoError(t, err)
	require.Equal(t, 404, request(wrong.Slug, fingerprint).Code)
	require.Equal(t, 404, request(f.org.Slug, "../invalid").Code)
	stale, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: now.Add(-2 * time.Hour), NextUpdate: now.Add(-time.Hour)}, root, key)
	require.NoError(t, err)
	_, err = f.h.mdocCRLs.Put(ctx, f.org.ID, root, stale)
	require.Error(t, err, "stale publication rejected")
	// Even damaged/stale storage cannot cause an expired CRL to be served.
	_, err = f.pool.Exec(ctx, `UPDATE identity.mdoc_iaca_crls SET der=$3 WHERE org_id=$1 AND fingerprint=$2`, f.org.ID, fingerprint, stale)
	require.NoError(t, err)
	require.Equal(t, 503, request(f.org.Slug, fingerprint).Code)
}
