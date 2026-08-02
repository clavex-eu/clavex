package devicepki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── test fixtures ────────────────────────────────────────────────────────────

func genCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// genCA returns a self-signed CA certificate (PEM + parsed) and its key.
func genCA(t *testing.T) (string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Device CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), cert, key
}

// genLeaf signs a leaf certificate under the given CA, with the given CN and
// extended key usages (pass nil for none, to exercise the "wrong EKU" path).
func genLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, eku []x509.ExtKeyUsage) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), leaf
}

// ── parseCSR ─────────────────────────────────────────────────────────────────

func TestParseCSR_Valid(t *testing.T) {
	csrPEM := genCSR(t, "device-1@org-1")
	csr, err := parseCSR(csrPEM, "device-1@org-1")
	require.NoError(t, err)
	assert.Equal(t, "device-1@org-1", csr.Subject.CommonName)
}

func TestParseCSR_CNMismatch(t *testing.T) {
	csrPEM := genCSR(t, "device-1@org-1")
	_, err := parseCSR(csrPEM, "device-2@org-1")
	assert.ErrorIs(t, err, ErrCNMismatch)
}

func TestParseCSR_NotPEM(t *testing.T) {
	_, err := parseCSR([]byte("not a pem block"), "device-1@org-1")
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

func TestParseCSR_WrongPEMType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})
	_, err := parseCSR(block, "device-1@org-1")
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

func TestParseCSR_TamperedSignature(t *testing.T) {
	csrPEM := genCSR(t, "device-1@org-1")
	block, _ := pem.Decode(csrPEM)
	// Flip a byte well inside the DER body to invalidate the signature without
	// corrupting the ASN.1 structure enough to fail parsing outright.
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-5] ^= 0xff
	tamperedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})

	_, err := parseCSR(tamperedPEM, "device-1@org-1")
	require.Error(t, err)
}

// ── expectedCN ───────────────────────────────────────────────────────────────

func TestExpectedCN(t *testing.T) {
	orgID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	assert.Equal(t, "sensor-42@11111111-2222-3333-4444-555555555555", expectedCN("sensor-42", orgID))
}

// ── parseIssuedCertificate ───────────────────────────────────────────────────

func TestParseIssuedCertificate(t *testing.T) {
	caPEM, ca, caKey := genCA(t)
	_ = caPEM
	leafPEM, leaf := genLeaf(t, ca, caKey, "device-1@org-1", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	parsed, serial, err := parseIssuedCertificate(leafPEM)
	require.NoError(t, err)
	assert.Equal(t, leaf.SerialNumber, parsed.SerialNumber)
	assert.Equal(t, FormatSerial(leaf.SerialNumber), serial)
}

func TestParseIssuedCertificate_BadPEM(t *testing.T) {
	_, _, err := parseIssuedCertificate("not a pem")
	require.Error(t, err)
}

// ── verifyCertAgainstCAPEM ───────────────────────────────────────────────────

func TestVerifyCertAgainstCAPEM_Success(t *testing.T) {
	caPEM, ca, caKey := genCA(t)
	_, leaf := genLeaf(t, ca, caKey, "device-1@org-1", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	err := verifyCertAgainstCAPEM(leaf, caPEM, "org-1")
	assert.NoError(t, err)
}

func TestVerifyCertAgainstCAPEM_WrongCA(t *testing.T) {
	_, otherCA, otherKey := genCA(t)
	caPEM, ca, caKey := genCA(t)
	_ = ca
	_ = caKey
	// Leaf signed by a DIFFERENT CA than the one we verify against — this is
	// exactly the cross-tenant confusion scenario the union-pool listener must
	// not be fooled by.
	_, leaf := genLeaf(t, otherCA, otherKey, "device-1@org-1", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	err := verifyCertAgainstCAPEM(leaf, caPEM, "org-1")
	assert.Error(t, err)
}

func TestVerifyCertAgainstCAPEM_WrongEKU(t *testing.T) {
	caPEM, ca, caKey := genCA(t)
	// ServerAuth only, no ClientAuth — must fail the KeyUsages requirement.
	// (An ABSENT ExtKeyUsage extension is treated by Go as "unrestricted" and
	// would pass, so the negative case must set an explicitly conflicting EKU.)
	_, leaf := genLeaf(t, ca, caKey, "device-1@org-1", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	err := verifyCertAgainstCAPEM(leaf, caPEM, "org-1")
	assert.Error(t, err)
}

func TestVerifyCertAgainstCAPEM_MalformedCAPEM(t *testing.T) {
	_, ca, caKey := genCA(t)
	_, leaf := genLeaf(t, ca, caKey, "device-1@org-1", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	err := verifyCertAgainstCAPEM(leaf, "not a valid PEM certificate", "org-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse cached Device CA certificate")
}
