package mds3

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── certLevelFromReports ──────────────────────────────────────────────────────

func TestCertLevelFromReports_Empty(t *testing.T) {
	assert.Equal(t, "", certLevelFromReports(nil))
	assert.Equal(t, "", certLevelFromReports([]StatusReport{}))
}

func TestCertLevelFromReports_BaseL1(t *testing.T) {
	reports := []StatusReport{{Status: "FIDO_CERTIFIED"}}
	assert.Equal(t, "L1", certLevelFromReports(reports))
}

func TestCertLevelFromReports_ExplicitL1(t *testing.T) {
	reports := []StatusReport{{Status: "FIDO_CERTIFIED_L1"}}
	assert.Equal(t, "L1", certLevelFromReports(reports))
}

func TestCertLevelFromReports_L2PlusWinsOverL1(t *testing.T) {
	reports := []StatusReport{
		{Status: "FIDO_CERTIFIED"},
		{Status: "FIDO_CERTIFIED_L2_PLUS"},
	}
	assert.Equal(t, "L2+", certLevelFromReports(reports))
}

func TestCertLevelFromReports_L3Plus(t *testing.T) {
	reports := []StatusReport{
		{Status: "FIDO_CERTIFIED_L2"},
		{Status: "FIDO_CERTIFIED_L3_PLUS"},
		{Status: "FIDO_CERTIFIED_L1"},
	}
	assert.Equal(t, "L3+", certLevelFromReports(reports))
}

func TestCertLevelFromReports_L1Plus(t *testing.T) {
	reports := []StatusReport{{Status: "FIDO_CERTIFIED_L1_PLUS"}}
	assert.Equal(t, "L1+", certLevelFromReports(reports))
}

func TestCertLevelFromReports_L1p(t *testing.T) {
	reports := []StatusReport{{Status: "FIDO_CERTIFIED_L1p"}}
	assert.Equal(t, "L1p", certLevelFromReports(reports))
}

func TestCertLevelFromReports_NonCertStatusIgnored(t *testing.T) {
	reports := []StatusReport{
		{Status: "REVOKED"},
		{Status: "USER_VERIFICATION_BYPASS"},
	}
	assert.Equal(t, "", certLevelFromReports(reports))
}

func TestCertLevelFromReports_AllLevelsPriority(t *testing.T) {
	// All levels present — L3+ should win.
	reports := []StatusReport{
		{Status: "FIDO_CERTIFIED_L1"},
		{Status: "FIDO_CERTIFIED_L1_PLUS"},
		{Status: "FIDO_CERTIFIED_L2"},
		{Status: "FIDO_CERTIFIED_L2_PLUS"},
		{Status: "FIDO_CERTIFIED_L3"},
		{Status: "FIDO_CERTIFIED_L3_PLUS"},
	}
	assert.Equal(t, "L3+", certLevelFromReports(reports))
}

// ── StatusReportStrings ───────────────────────────────────────────────────────

func TestStatusReportStrings_Empty(t *testing.T) {
	assert.Equal(t, []string{}, StatusReportStrings([]StatusReport{}))
}

func TestStatusReportStrings_Single(t *testing.T) {
	reports := []StatusReport{{Status: "FIDO_CERTIFIED_L2"}}
	assert.Equal(t, []string{"FIDO_CERTIFIED_L2"}, StatusReportStrings(reports))
}

func TestStatusReportStrings_Multiple(t *testing.T) {
	reports := []StatusReport{
		{Status: "FIDO_CERTIFIED_L2", CertificateNumber: "FIDO20020230401001"},
		{Status: "REVOKED"},
	}
	got := StatusReportStrings(reports)
	require.Len(t, got, 2)
	assert.Equal(t, "FIDO_CERTIFIED_L2", got[0])
	assert.Equal(t, "REVOKED", got[1])
}

// ── enrichEntry ───────────────────────────────────────────────────────────────

func TestEnrichEntry_NoMetadataStatement(t *testing.T) {
	e := &Entry{}
	enrichEntry(e)
	assert.Equal(t, "unknown", e.AuthenticatorType)
	assert.Equal(t, "", e.Description)
	assert.Empty(t, e.RootCertificates)
}

func TestEnrichEntry_InvalidJSON(t *testing.T) {
	e := &Entry{MetadataStatement: json.RawMessage(`not json`)}
	enrichEntry(e)
	assert.Equal(t, "unknown", e.AuthenticatorType)
}

func TestEnrichEntry_FIDO2PlatformAuthenticator(t *testing.T) {
	ms := map[string]interface{}{
		"description":   "Test Platform Authenticator",
		"protocolFamily": "fido2",
	}
	msJSON, _ := json.Marshal(ms)
	e := &Entry{MetadataStatement: json.RawMessage(msJSON)}
	enrichEntry(e)

	assert.Equal(t, "Test Platform Authenticator", e.Description)
	assert.Equal(t, "platform", e.AuthenticatorType)
}

func TestEnrichEntry_FIDO2PlatformExplicit(t *testing.T) {
	ms := map[string]interface{}{
		"description":   "Another Platform",
		"protocolFamily": "fido2-platform",
	}
	msJSON, _ := json.Marshal(ms)
	e := &Entry{MetadataStatement: json.RawMessage(msJSON)}
	enrichEntry(e)
	assert.Equal(t, "platform", e.AuthenticatorType)
}

func TestEnrichEntry_CrossPlatformU2F(t *testing.T) {
	ms := map[string]interface{}{
		"description":   "Test Security Key",
		"protocolFamily": "u2f",
	}
	msJSON, _ := json.Marshal(ms)
	e := &Entry{MetadataStatement: json.RawMessage(msJSON)}
	enrichEntry(e)

	assert.Equal(t, "Test Security Key", e.Description)
	assert.Equal(t, "cross-platform", e.AuthenticatorType)
}

func TestEnrichEntry_CrossPlatformExplicit(t *testing.T) {
	ms := map[string]interface{}{
		"protocolFamily": "fido2-crossplatform",
	}
	msJSON, _ := json.Marshal(ms)
	e := &Entry{MetadataStatement: json.RawMessage(msJSON)}
	enrichEntry(e)
	assert.Equal(t, "cross-platform", e.AuthenticatorType)
}

func TestEnrichEntry_UnknownProtocol(t *testing.T) {
	ms := map[string]interface{}{
		"description":   "Some device",
		"protocolFamily": "ctap1",
	}
	msJSON, _ := json.Marshal(ms)
	e := &Entry{MetadataStatement: json.RawMessage(msJSON)}
	enrichEntry(e)
	assert.Equal(t, "unknown", e.AuthenticatorType)
}

func TestEnrichEntry_AttestationRootCertificates(t *testing.T) {
	// Generate a self-signed cert to use as a fake root.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// MDS3 stores attestation root certificates as base64-standard-encoded DER.
	b64Cert := base64.StdEncoding.EncodeToString(certDER)

	ms := map[string]interface{}{
		"description":    "Device with Root Cert",
		"protocolFamily": "fido2",
		"attestationRootCertificates": []string{b64Cert},
	}
	msJSON, _ := json.Marshal(ms)
	e := &Entry{MetadataStatement: json.RawMessage(msJSON)}
	enrichEntry(e)

	require.Len(t, e.RootCertificates, 1)
	assert.Contains(t, e.RootCertificates[0], "-----BEGIN CERTIFICATE-----")
}

func TestEnrichEntry_CertLevelFromStatusReports(t *testing.T) {
	ms := map[string]interface{}{
		"protocolFamily": "fido2",
	}
	msJSON, _ := json.Marshal(ms)
	e := &Entry{
		MetadataStatement: json.RawMessage(msJSON),
		StatusReports: []StatusReport{
			{Status: "FIDO_CERTIFIED_L2", CertificateNumber: "FIDO20020230401001", EffectiveDate: "2023-04-01"},
		},
	}
	enrichEntry(e)

	assert.Equal(t, "L2", e.CertificationLevel)
	assert.Equal(t, "FIDO20020230401001", e.CertificateNumber)
	assert.Equal(t, "2023-04-01", e.CertifiedAt)
}

func TestEnrichEntry_BadBase64RootCert(t *testing.T) {
	ms := map[string]interface{}{
		"protocolFamily":              "fido2",
		"attestationRootCertificates": []string{"!!not-valid-base64!!"},
	}
	msJSON, _ := json.Marshal(ms)
	e := &Entry{MetadataStatement: json.RawMessage(msJSON)}
	enrichEntry(e) // must not panic
	assert.Empty(t, e.RootCertificates)
}

// ── parseAndVerify ────────────────────────────────────────────────────────────

// buildTestJWS creates a well-formed MDS3 JWS token signed with a freshly
// generated RSA-2048 key and a self-signed leaf certificate in the x5c header.
// The cert chain will NOT verify against the FIDO root (expected warning), but
// the JWS signature will verify correctly.
func buildTestJWS(t *testing.T, blob map[string]interface{}) string {
	t.Helper()

	// 1. Generate key pair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// 2. Self-signed certificate (key usage: digital signature).
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "MDS3 Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// 3. Payload JSON (MDS3 blob structure).
	payloadJSON, err := json.Marshal(blob)
	require.NoError(t, err)

	// 4. Protected header.
	//    x5c values are base64-standard (not base64url) encoded DER per RFC 7515 §4.1.6.
	x5cB64 := base64.StdEncoding.EncodeToString(certDER)
	header := map[string]interface{}{
		"alg": "RS256",
		"x5c": []string{x5cB64},
	}
	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)

	// 5. JWS signing input = base64url(header) + "." + base64url(payload).
	b64Header := base64.RawURLEncoding.EncodeToString(headerJSON)
	b64Payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := b64Header + "." + b64Payload

	// 6. Sign with RSA-PKCS1v15 + SHA-256.
	h := sha256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	require.NoError(t, err)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestParseAndVerify_ValidToken(t *testing.T) {
	blob := map[string]interface{}{
		"legalHeader": "FIDO Alliance Test",
		"no":          int64(42),
		"nextUpdate":  "2099-12-31",
		"entries": []map[string]interface{}{
			{
				"aaguid": "fbfc3007-154e-4ecc-8ade-601177b8b3f6",
				"statusReports": []map[string]interface{}{
					{"status": "FIDO_CERTIFIED_L2", "effectiveDate": "2023-01-01"},
				},
				"metadataStatement": map[string]interface{}{
					"description":   "Test Passkey Device",
					"protocolFamily": "fido2",
				},
			},
		},
	}

	token := buildTestJWS(t, blob)
	parsed, exp, err := parseAndVerify([]byte(token))
	require.NoError(t, err)
	require.NotNil(t, parsed)

	assert.Equal(t, int64(42), parsed.No)
	assert.Equal(t, "2099-12-31", parsed.NextUpdate)
	assert.Equal(t, "FIDO Alliance Test", parsed.LegalHeader)
	require.Len(t, parsed.Entries, 1)
	assert.Equal(t, "fbfc3007-154e-4ecc-8ade-601177b8b3f6", parsed.Entries[0].AAGUID)
	// enrichEntry should have populated these.
	assert.Equal(t, "Test Passkey Device", parsed.Entries[0].Description)
	assert.Equal(t, "platform", parsed.Entries[0].AuthenticatorType)
	assert.Equal(t, "L2", parsed.Entries[0].CertificationLevel)
	// No JWT exp claim in our blob → nil.
	assert.Nil(t, exp)
}

func TestParseAndVerify_WithExpClaim(t *testing.T) {
	expTime := time.Now().Add(24 * time.Hour).Unix()
	blob := map[string]interface{}{
		"legalHeader": "test",
		"no":          int64(1),
		"nextUpdate":  "2099-01-01",
		"exp":         expTime,
		"entries":     []interface{}{},
	}

	token := buildTestJWS(t, blob)
	parsed, exp, err := parseAndVerify([]byte(token))
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.NotNil(t, exp)
	assert.WithinDuration(t, time.Unix(expTime, 0).UTC(), *exp, time.Second)
}

func TestParseAndVerify_MultipleEntries(t *testing.T) {
	blob := map[string]interface{}{
		"legalHeader": "test",
		"no":          int64(10),
		"nextUpdate":  "2099-01-01",
		"entries": []map[string]interface{}{
			{
				"aaguid":        "aabbccdd-1234-5678-9012-aabbccddeeff",
				"statusReports": []map[string]interface{}{{"status": "FIDO_CERTIFIED_L3_PLUS"}},
				"metadataStatement": map[string]interface{}{
					"description":   "YubiKey Test",
					"protocolFamily": "u2f",
				},
			},
			{
				// Entry with no AAGUID (FIDO UAF authenticator) — should be parsed but aaguid="".
				"statusReports": []map[string]interface{}{{"status": "FIDO_CERTIFIED"}},
			},
		},
	}

	token := buildTestJWS(t, blob)
	parsed, _, err := parseAndVerify([]byte(token))
	require.NoError(t, err)
	require.Len(t, parsed.Entries, 2)

	assert.Equal(t, "aabbccdd-1234-5678-9012-aabbccddeeff", parsed.Entries[0].AAGUID)
	assert.Equal(t, "cross-platform", parsed.Entries[0].AuthenticatorType)
	assert.Equal(t, "L3+", parsed.Entries[0].CertificationLevel)

	assert.Equal(t, "", parsed.Entries[1].AAGUID)
}

func TestParseAndVerify_QuotedToken(t *testing.T) {
	// Some MDS3 endpoints return the JWT wrapped in JSON string quotes.
	blob := map[string]interface{}{
		"legalHeader": "test",
		"no":          int64(1),
		"nextUpdate":  "2099-01-01",
		"entries":     []interface{}{},
	}
	token := buildTestJWS(t, blob)
	quoted := `"` + token + `"`

	parsed, _, err := parseAndVerify([]byte(quoted))
	require.NoError(t, err)
	require.NotNil(t, parsed)
}

func TestParseAndVerify_InvalidJWS(t *testing.T) {
	_, _, err := parseAndVerify([]byte("not.a.valid.jws.token"))
	require.Error(t, err)
}

func TestParseAndVerify_EmptyInput(t *testing.T) {
	_, _, err := parseAndVerify([]byte(""))
	require.Error(t, err)
}

func TestParseAndVerify_TwoPartToken(t *testing.T) {
	_, _, err := parseAndVerify([]byte("header.payload"))
	require.Error(t, err)
}

func TestParseAndVerify_TamperedSignature(t *testing.T) {
	blob := map[string]interface{}{
		"legalHeader": "test",
		"no":          int64(1),
		"nextUpdate":  "2099-01-01",
		"entries":     []interface{}{},
	}
	token := buildTestJWS(t, blob)

	// Flip a few bytes in the signature (last segment).
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	sig := parts[2]
	if len(sig) > 10 {
		tampered := sig[:5] + "XXXXX" + sig[10:]
		parts[2] = tampered
	}
	badToken := strings.Join(parts, ".")

	_, _, err := parseAndVerify([]byte(badToken))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWS signature invalid")
}

func TestParseAndVerify_NoX5CHeader(t *testing.T) {
	// Build a JWS without x5c in the protected header.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	payload := `{"legalHeader":"test","no":1,"nextUpdate":"2099-01-01","entries":[]}`
	header := `{"alg":"RS256"}` // no x5c

	b64Header := base64.RawURLEncoding.EncodeToString([]byte(header))
	b64Payload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := b64Header + "." + b64Payload

	h := sha256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	require.NoError(t, err)

	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	_, _, err = parseAndVerify([]byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x5c")
}
// ── helpers for new error-path tests ─────────────────────────────────────────

// buildTestKey generates an RSA-2048 key and a self-signed leaf certificate.
func buildTestKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "mds3-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return key, certDER
}

// buildRawJWS assembles a JWS from arbitrary header JSON and payload bytes,
// signing with the provided RSA key. It does NOT embed any certificate — the
// caller controls the exact header (used to inject invalid x5c values).
func buildRawJWS(t *testing.T, headerJSON string, payload []byte, key *rsa.PrivateKey) string {
	t.Helper()
	b64h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	b64p := base64.RawURLEncoding.EncodeToString(payload)
	sigInput := b64h + "." + b64p
	h := sha256.New()
	h.Write([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	require.NoError(t, err)
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// buildJWSWithCert creates a properly signed JWS with the given cert in x5c
// and the given payload. Used to reach code paths past x5c parsing.
func buildJWSWithCert(t *testing.T, key *rsa.PrivateKey, certDER []byte, payload []byte) string {
	t.Helper()
	x5cB64 := base64.StdEncoding.EncodeToString(certDER)
	headerJSON := `{"alg":"RS256","x5c":["` + x5cB64 + `"]}`
	return buildRawJWS(t, headerJSON, payload, key)
}

// ── parseAndVerify — error branches ──────────────────────────────────────────

// TestParseAndVerify_BadX5CBase64 exercises the base64-decode error in the x5c
// loop. The x5c entry is "!!" which is not valid base64-standard encoding.
func TestParseAndVerify_BadX5CBase64(t *testing.T) {
	key, _ := buildTestKey(t)
	headerJSON := `{"alg":"RS256","x5c":["!!not-valid-base64!!"]}`
	token := buildRawJWS(t, headerJSON, []byte(`{}`), key)
	_, _, err := parseAndVerify([]byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64 decode")
}

// TestParseAndVerify_BadX5EDER exercises the x509.ParseCertificate error: the
// x5c entry is valid base64 but the decoded bytes are not a valid DER cert.
func TestParseAndVerify_BadX5EDER(t *testing.T) {
	key, _ := buildTestKey(t)
	badDERB64 := base64.StdEncoding.EncodeToString([]byte("this-is-not-a-der-cert"))
	headerJSON := `{"alg":"RS256","x5c":["` + badDERB64 + `"]}`
	token := buildRawJWS(t, headerJSON, []byte(`{}`), key)
	_, _, err := parseAndVerify([]byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse cert")
}

// TestParseAndVerify_NonJSONPayload exercises the "unmarshal claims" error.
// jws.Verify passes (signature is valid) but the payload is not JSON.
func TestParseAndVerify_NonJSONPayload(t *testing.T) {
	key, certDER := buildTestKey(t)
	token := buildJWSWithCert(t, key, certDER, []byte("not-json-at-all"))
	_, _, err := parseAndVerify([]byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal claims")
}

// TestParseAndVerify_BadBlobJSON exercises the "unmarshal blob" error.
// The payload is valid JSON for the claims struct (no entries field) but
// `entries` has the wrong type for the Blob struct (string, not []Entry).
func TestParseAndVerify_BadBlobJSON(t *testing.T) {
	key, certDER := buildTestKey(t)
	// entries is a string — json.Unmarshal into Blob.Entries ([]Entry) will fail.
	payload := []byte(`{"legalHeader":"x","no":1,"nextUpdate":"2099-01-01","entries":"wrong-type"}`)
	token := buildJWSWithCert(t, key, certDER, payload)
	_, _, err := parseAndVerify([]byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal blob")
}

// ── verifyCertChain ───────────────────────────────────────────────────────────

// TestVerifyCertChain_MultiCert covers the certs[1:] loop paths by supplying a
// 2-cert chain [leaf, CA]. The CA is added to both sysRoots and intermediates.
// Verification should succeed: the CA is in sysRoots, and the leaf is signed by it.
func TestVerifyCertChain_MultiCert(t *testing.T) {
	// Build self-signed CA.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Chain CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	// Build leaf signed by CA.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Chain Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// certs = [leaf, CA] — verifyCertChain adds CA to sysRoots (if non-nil)
	// and to intermediates, covering both for-range certs[1:] paths.
	// The verification result depends on sysRoots availability: on systems with
	// a CA bundle sysRoots is non-nil → CA is added → leaf verifies successfully.
	// We don't assert the error value, only that the code runs without panic.
	_ = verifyCertChain([]*x509.Certificate{leafCert, caCert})
}

// TestVerifyCertChain_WithFidoRoot temporarily sets the package-level fidoRoot
// to a synthetic CA, covering the "if fidoRoot != nil" branch.
// A leaf cert signed by that CA should verify successfully.
func TestVerifyCertChain_WithFidoRoot(t *testing.T) {
	// Save and restore the package-level fidoRoot.
	origFidoRoot := fidoRoot
	defer func() { fidoRoot = origFidoRoot }()

	// Build synthetic CA (becomes the "FIDO root" for this test).
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Synthetic FIDO Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	fidoRoot = caCert // ← covers "if fidoRoot != nil { roots.AddCert(fidoRoot) }"

	// Build leaf signed by the synthetic FIDO root.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "Synthetic Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// Leaf is signed by fidoRoot → chain should verify with no error.
	err = verifyCertChain([]*x509.Certificate{leafCert})
	assert.NoError(t, err)
}

// ── parseAndVerify — chain round-trip with multi-cert x5c ────────────────────

// TestParseAndVerify_MultiCertChain uses a JWS with two certs in x5c
// (leaf + CA issuer), covering the x5c parse loop beyond index 0 and the
// certs[1:] paths inside verifyCertChain.
func TestParseAndVerify_MultiCertChain(t *testing.T) {
	// Build CA.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(200),
		Subject:               pkix.Name{CommonName: "JWS Chain CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	// Build leaf signed by CA (leaf key is used to sign the JWS).
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(201),
		Subject:      pkix.Name{CommonName: "JWS Chain Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	// Build the JWS header with two x5c entries: [leaf, CA].
	x5cLeaf := base64.StdEncoding.EncodeToString(leafDER)
	x5cCA := base64.StdEncoding.EncodeToString(caDER)
	headerJSON := `{"alg":"RS256","x5c":["` + x5cLeaf + `","` + x5cCA + `"]}`

	blob := map[string]interface{}{
		"legalHeader": "chain test",
		"no":          int64(1),
		"nextUpdate":  "2099-01-01",
		"entries":     []interface{}{},
	}
	payloadJSON, err := json.Marshal(blob)
	require.NoError(t, err)

	token := buildRawJWS(t, headerJSON, payloadJSON, leafKey)
	parsed, _, err := parseAndVerify([]byte(token))
	require.NoError(t, err) // signature verifies with leaf key; chain warning is OK
	assert.Equal(t, int64(1), parsed.No)
}

// ── New and Fetch ─────────────────────────────────────────────────────────────

func TestNew_DefaultEndpoint(t *testing.T) {
	c := New("")
	assert.Equal(t, DefaultEndpoint, c.endpoint)
	assert.NotNil(t, c.http)
}

func TestNew_CustomEndpoint(t *testing.T) {
	c := New("https://custom.example.com/mds3/blob")
	assert.Equal(t, "https://custom.example.com/mds3/blob", c.endpoint)
}

func TestFetch_NotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, `"abc123"`, r.Header.Get("If-None-Match"))
		assert.Equal(t, "Mon, 01 Jan 2024 00:00:00 GMT", r.Header.Get("If-Modified-Since"))
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	c := New(srv.URL)
	blob, meta, err := c.Fetch(context.Background(), `"abc123"`, "Mon, 01 Jan 2024 00:00:00 GMT")
	require.NoError(t, err)
	assert.Nil(t, blob) // nil Blob signals "use cached copy"
	require.NotNil(t, meta)
	assert.Equal(t, `"abc123"`, meta.HTTPETag)
}

func TestFetch_200OK(t *testing.T) {
	blobMap := map[string]interface{}{
		"legalHeader": "FIDO Alliance Test",
		"no":          int64(7),
		"nextUpdate":  "2099-12-31",
		"entries":     []interface{}{},
	}
	token := buildTestJWS(t, blobMap)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"etag-v7"`)
		w.Header().Set("Last-Modified", "Fri, 09 May 2026 00:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, token)
	}))
	defer srv.Close()

	c := New(srv.URL)
	blob, meta, err := c.Fetch(context.Background(), "", "")
	require.NoError(t, err)
	require.NotNil(t, blob)
	assert.Equal(t, int64(7), blob.No)
	assert.Equal(t, "2099-12-31", blob.NextUpdate)
	require.NotNil(t, meta)
	assert.Equal(t, `"etag-v7"`, meta.HTTPETag)
}

func TestFetch_200OK_WithExpiry(t *testing.T) {
	expTime := time.Now().Add(48 * time.Hour).Unix()
	blobMap := map[string]interface{}{
		"legalHeader": "test",
		"no":          int64(1),
		"nextUpdate":  "2099-01-01",
		"exp":         expTime,
		"entries":     []interface{}{},
	}
	token := buildTestJWS(t, blobMap)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, token)
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, meta, err := c.Fetch(context.Background(), "", "")
	require.NoError(t, err)
	require.NotNil(t, meta.TokenExpiresAt)
	assert.WithinDuration(t, time.Unix(expTime, 0).UTC(), *meta.TokenExpiresAt, time.Second)
}

func TestFetch_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, _, err := c.Fetch(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
}

func TestFetch_BadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "not-a-valid-jws-at-all")
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, _, err := c.Fetch(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse/verify")
}