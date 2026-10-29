package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func testMdocKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func testMdocSignature(t *testing.T, key *ecdsa.PrivateKey, protected, payload []byte) []byte {
	t.Helper()
	structure, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	require.NoError(t, err)
	digest := sha256.Sum256(structure)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	result := make([]byte, 64)
	r.FillBytes(result[:32])
	s.FillBytes(result[32:])
	return result
}

func attachDeviceProof(t *testing.T, doc *Document, key *ecdsa.PrivateKey, transcript []byte) {
	t.Helper()
	ns, err := cbor.Marshal(map[string]any{})
	require.NoError(t, err)
	doc.DeviceSigned.NameSpaces, err = cbor.Marshal(cbor.Tag{Number: 24, Content: ns})
	require.NoError(t, err)
	// Construct independently of DeviceAuthenticationBytes/VerifyDeviceSignature.
	auth, err := cbor.Marshal([]any{"DeviceAuthentication", cbor.RawMessage(transcript), doc.DocType, doc.DeviceSigned.NameSpaces})
	require.NoError(t, err)
	authBytes, err := cbor.Marshal(cbor.Tag{Number: 24, Content: auth})
	require.NoError(t, err)
	protected, err := cbor.Marshal(map[int]int{1: -7})
	require.NoError(t, err)
	signature := testMdocSignature(t, key, protected, authBytes)
	doc.DeviceSigned.DeviceAuth.DeviceSignature, err = cbor.Marshal([]any{protected, map[int]any{}, nil, signature})
	require.NoError(t, err)
}

func testTrustedMdoc(t *testing.T) (*DeviceResponse, *x509.CertPool, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey := testMdocKey(t)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	intermediateKey := testMdocKey(t)
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	require.NoError(t, err)
	intermediate, err := x509.ParseCertificate(intermediateDER)
	require.NoError(t, err)
	device, ds := testMdocKey(t), testMdocKey(t)
	dsTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour)}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, intermediate, &ds.PublicKey, intermediateKey)
	require.NoError(t, err)
	issued, err := IssueMdoc(IssuanceParams{DocType: DocTypeEuPid, Namespace: NSEuPid, Attributes: map[string]interface{}{"given_name": "Alice"}, DSKey: ds, DSCertDER: dsDER, DevicePublicKey: &device.PublicKey, ValidityHours: 1})
	require.NoError(t, err)
	var is IssuerSigned
	require.NoError(t, cbor.Unmarshal(issued, &is))
	var issuerAuth []cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(is.IssuerAuth, &issuerAuth))
	var payload []byte
	require.NoError(t, cbor.Unmarshal(issuerAuth[2], &payload))
	protected, err := cbor.Marshal(map[int]int{1: -7})
	require.NoError(t, err)
	is.IssuerAuth, err = cbor.Marshal([]any{protected, map[int]any{33: [][]byte{dsDER, intermediateDER}}, payload, testMdocSignature(t, ds, protected, payload)})
	require.NoError(t, err)
	doc := Document{DocType: DocTypeEuPid, IssuerSigned: is}
	transcript, err := BuildSessionTranscript("redirect_uri:https://verifier.example/response", "https://verifier.example/response", "challenge")
	require.NoError(t, err)
	attachDeviceProof(t, &doc, device, transcript)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &DeviceResponse{Version: "1.0", Documents: []Document{doc}}, pool, transcript, device
}

func TestFinalMdocTranscriptOfficialVector(t *testing.T) {
	thumbprint, err := hex.DecodeString("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047")
	require.NoError(t, err)
	got, err := BuildRedirectSessionTranscript("x509_san_dns:example.com", "https://example.com/response", "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA", thumbprint)
	require.NoError(t, err)
	require.Equal(t, "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac", hex.EncodeToString(got), "OID4VP Final B.2.6.1 example")
}

func TestMdocTrustedIssuerAndSessionBoundDeviceAuthentication(t *testing.T) {
	dr, roots, transcript, _ := testTrustedMdoc(t)
	opts := VerificationOptions{TrustedRoots: roots, RequireTrustedIssuer: true, RequireDeviceAuth: true, SessionTranscript: transcript}
	verified, errs := VerifyDeviceResponse(dr, opts)
	require.Empty(t, errs)
	require.Len(t, verified, 1)
	require.Equal(t, "Alice", verified[0].Attributes[NSEuPid]["given_name"])
	for _, tc := range []struct {
		name   string
		mutate func(*DeviceResponse, *VerificationOptions)
	}{
		{"no roots", func(_ *DeviceResponse, o *VerificationOptions) { o.TrustedRoots = nil }},
		{"untrusted issuer", func(_ *DeviceResponse, o *VerificationOptions) { o.TrustedRoots = x509.NewCertPool() }},
		{"missing device auth", func(d *DeviceResponse, _ *VerificationOptions) {
			d.Documents[0].DeviceSigned.DeviceAuth.DeviceSignature = nil
		}},
		{"wrong device key", func(d *DeviceResponse, _ *VerificationOptions) {
			attachDeviceProof(t, &d.Documents[0], testMdocKey(t), transcript)
		}},
		{"different nonce", func(_ *DeviceResponse, o *VerificationOptions) {
			o.SessionTranscript, _ = BuildSessionTranscript("redirect_uri:https://verifier.example/response", "https://verifier.example/response", "other")
		}},
		{"different client", func(_ *DeviceResponse, o *VerificationOptions) {
			o.SessionTranscript, _ = BuildSessionTranscript("other-client", "https://verifier.example/response", "challenge")
		}},
		{"different URI", func(_ *DeviceResponse, o *VerificationOptions) {
			o.SessionTranscript, _ = BuildSessionTranscript("redirect_uri:https://verifier.example/response", "https://attacker.example/response", "challenge")
		}},
		{"expired MSO", func(_ *DeviceResponse, o *VerificationOptions) {
			later := time.Now().Add(2 * time.Hour)
			o.Now = &later
		}},
		{"wrong doctype", func(d *DeviceResponse, _ *VerificationOptions) { d.Documents[0].DocType = "other" }},
		{"unsuccessful status", func(d *DeviceResponse, _ *VerificationOptions) { d.Status = 10 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := cbor.Marshal(dr)
			require.NoError(t, err)
			var copy DeviceResponse
			require.NoError(t, cbor.Unmarshal(encoded, &copy))
			o := opts
			tc.mutate(&copy, &o)
			_, errs := VerifyDeviceResponse(&copy, o)
			require.NotEmpty(t, errs)
		})
	}
}
