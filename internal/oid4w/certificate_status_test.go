package oid4w

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func crlTestCA(t *testing.T, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test IACA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}
func crlTestLeaf(t *testing.T, now time.Time, ca *x509.Certificate, key *ecdsa.PrivateKey, serial int64) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "DS"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, CRLDistributionPoints: []string{"https://crl.example/list"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
func crlTestDER(t *testing.T, now time.Time, ca *x509.Certificate, key *ecdsa.PrivateKey, edit func(*x509.RevocationList)) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, key)
	require.NoError(t, err)
	return der
}
func crlResponse(der []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/pkix-crl"}}, Body: io.NopCloser(strings.NewReader(string(der))), ContentLength: int64(len(der))}
}
func TestCertificateStatusCacheRevocationAndDistrust(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ca, key := crlTestCA(t, now)
	leaf := crlTestLeaf(t, now, ca, key, 10)
	chain := [][]*x509.Certificate{{leaf, ca}}
	calls := 0
	var revoked, outage bool
	resolver := NewStatusResolverWithHTTPClient(&http.Client{Transport: statusRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		require.Empty(t, req.Header.Get("Authorization"))
		require.Empty(t, req.Header.Get("Cookie"))
		if outage {
			return nil, errors.New("test outage")
		}
		return crlResponse(crlTestDER(t, now, ca, key, func(crl *x509.RevocationList) {
			if revoked {
				crl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: now.Add(-time.Minute), ReasonCode: 1}}
			}
		})), nil
	})})
	resolver.now = func() time.Time { return now }
	check := func(scope string, settings map[string]interface{}) (string, error) {
		return resolver.CheckCertificateChain(context.Background(), scope, settings, chain, true)
	}
	assessment, err := check("a", nil)
	require.NoError(t, err)
	require.Equal(t, "valid_crl", assessment)
	_, err = check("a", nil)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	_, err = check("b", nil)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	_, err = check("a", map[string]interface{}{"wallet_certificate_distrust": []string{CertificateFingerprint(ca)}})
	require.ErrorIs(t, err, ErrRevoked)
	now = now.Add(61 * time.Second)
	revoked = true
	_, err = check("a", nil)
	require.ErrorIs(t, err, ErrRevoked)
	now = now.Add(61 * time.Second)
	outage = true
	_, err = check("a", nil)
	require.ErrorIs(t, err, ErrStatusUnavailable)
}
func TestCertificateStatusRejectsUnsupportedAndInvalidCRLs(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ca, key := crlTestCA(t, now)
	leaf := crlTestLeaf(t, now, ca, key, 10)
	wrongCA, wrongKey := crlTestCA(t, now)
	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"wrong signer", crlTestDER(t, now, wrongCA, wrongKey, nil)},
		{"expired", crlTestDER(t, now, ca, key, func(c *x509.RevocationList) {
			c.ThisUpdate = now.Add(-2 * time.Hour)
			c.NextUpdate = now.Add(-time.Minute)
		})},
		{"future", crlTestDER(t, now, ca, key, func(c *x509.RevocationList) { c.ThisUpdate = now.Add(time.Minute) })},
		{"delta", crlTestDER(t, now, ca, key, func(c *x509.RevocationList) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Value: []byte{2, 1, 1}}}
		})},
		{"partitioned", crlTestDER(t, now, ca, key, func(c *x509.RevocationList) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Value: []byte{0x30, 0}}}
		})},
		{"critical", crlTestDER(t, now, ca, key, func(c *x509.RevocationList) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		})},
		{"duplicate serial", crlTestDER(t, now, ca, key, func(c *x509.RevocationList) {
			e := x509.RevocationListEntry{SerialNumber: big.NewInt(10), RevocationTime: now.Add(-time.Minute)}
			c.RevokedCertificateEntries = []x509.RevocationListEntry{e, e}
		})},
		{"remove from delta", crlTestDER(t, now, ca, key, func(c *x509.RevocationList) {
			c.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(10), RevocationTime: now.Add(-time.Minute), ReasonCode: 8}}
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := NewStatusResolverWithHTTPClient(&http.Client{Transport: statusRoundTrip(func(*http.Request) (*http.Response, error) { return crlResponse(tc.der), nil })})
			resolver.now = func() time.Time { return now }
			_, err := resolver.CheckCertificateChain(context.Background(), "a", nil, [][]*x509.Certificate{{leaf, ca}}, true)
			require.ErrorIs(t, err, ErrStatusInvalid)
		})
	}
}
func TestCertificateStatusExplicitMissingPolicyAndConfiguration(t *testing.T) {
	resolver := NewStatusResolver()
	_, err := resolver.CheckCertificateChain(context.Background(), "a", nil, nil, true)
	require.ErrorIs(t, err, ErrStatusUnavailable)
	assessment, err := resolver.CheckCertificateChain(context.Background(), "a", map[string]interface{}{"wallet_certificate_revocation_required": false}, nil, true)
	require.NoError(t, err)
	require.Equal(t, "missing_permitted", assessment)
	_, err = CRLSources(map[string]interface{}{"wallet_crl_sources": []CRLSource{{IssuerSHA256: strings.Repeat("a", 64), URI: "file:///private"}}})
	require.Error(t, err)
	now := time.Now()
	ca, key := crlTestCA(t, now)
	leaf := crlTestLeaf(t, now, ca, key, 10)
	leaf.CRLDistributionPoints = nil
	_, err = resolver.CheckCertificateChain(context.Background(), "a", nil, [][]*x509.Certificate{{leaf, ca}}, true)
	require.ErrorIs(t, err, ErrStatusUnavailable)
	assessment, err = resolver.CheckCertificateChain(context.Background(), "a", nil, [][]*x509.Certificate{{leaf, ca}}, false)
	require.NoError(t, err)
	require.Equal(t, "missing_permitted", assessment)
}
