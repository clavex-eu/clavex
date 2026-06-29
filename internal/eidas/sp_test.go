package eidas_test

import (
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/eidas"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// newTestSP creates a ServiceProvider with a freshly generated certificate —
// suitable for all tests that don't need a specific IdP cert.
func newTestSP(t *testing.T) *eidas.ServiceProvider {
	t.Helper()
	certPEM, keyPEM, err := eidas.GenerateSelfSignedCert("Test Org")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return eidas.New(eidas.SPConfig{
		EntityID:                    "https://auth.example.com/eidas/metadata",
		AssertionConsumerServiceURL: "https://auth.example.com/acme/eidas/callback",
		EidasNodeURL:                "https://eidas.example.eu/EidasNode/ServiceProvider",
		OrgName:                     "Test Org",
		OrgDisplayName:              "Test Org",
		OrgURL:                      "https://www.example.com",
		ContactEmail:                "admin@example.com",
		Certificate:                 cert,
		PrivateKey:                  key,
		RequestedLoA:                eidas.LoASubstantial,
	})
}

// ── GenerateSelfSignedCert ────────────────────────────────────────────────────

func TestGenerateSelfSignedCert(t *testing.T) {
	certPEM, keyPEM, err := eidas.GenerateSelfSignedCert("My Org")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(certPEM), "-----BEGIN CERTIFICATE-----") {
		t.Error("certPEM missing PEM header")
	}
	if !strings.Contains(string(keyPEM), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("keyPEM missing PEM header")
	}
	// Parse to confirm it's valid.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("certPEM is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("invalid certificate: %v", err)
	}
	if cert.Subject.CommonName != "My Org" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "My Org")
	}
}

// ── MetadataXML ───────────────────────────────────────────────────────────────

func TestMetadataXML_wellFormed(t *testing.T) {
	sp := newTestSP(t)
	xmlBytes, err := sp.MetadataXML()
	if err != nil {
		t.Fatalf("MetadataXML error: %v", err)
	}
	if len(xmlBytes) == 0 {
		t.Fatal("MetadataXML returned empty output")
	}
	// Must be valid XML.
	if err := xml.Unmarshal(xmlBytes, new(interface{})); err != nil {
		t.Errorf("metadata XML is not well-formed: %v", err)
	}
}

func TestMetadataXML_containsRequiredElements(t *testing.T) {
	sp := newTestSP(t)
	xmlBytes, err := sp.MetadataXML()
	if err != nil {
		t.Fatalf("MetadataXML error: %v", err)
	}
	xmlStr := string(xmlBytes)

	checks := []struct{ name, contains string }{
		{"EntityDescriptor", "EntityDescriptor"},
		{"SPSSODescriptor", "SPSSODescriptor"},
		{"entityID", "https://auth.example.com/eidas/metadata"},
		{"AssertionConsumerService", "AssertionConsumerService"},
		{"acs_url", "https://auth.example.com/acme/eidas/callback"},
		{"LoA", eidas.LoASubstantial},
		{"mandatory attr PersonIdentifier", eidas.AttrPersonIdentifier},
		{"mandatory attr FamilyName", eidas.AttrFamilyName},
		{"mandatory attr FirstName", eidas.AttrFirstName},
		{"mandatory attr DateOfBirth", eidas.AttrDateOfBirth},
	}
	for _, tc := range checks {
		if !strings.Contains(xmlStr, tc.contains) {
			t.Errorf("MetadataXML missing %s (looking for %q)", tc.name, tc.contains)
		}
	}
}

// ── BuildAuthnRequestURL ──────────────────────────────────────────────────────

func TestBuildAuthnRequestURL_queryParams(t *testing.T) {
	sp := newTestSP(t)
	redirectURL, reqID, err := sp.BuildAuthnRequestURL("test-relay-state-1234")
	if err != nil {
		t.Fatalf("BuildAuthnRequestURL error: %v", err)
	}
	if reqID == "" {
		t.Error("BuildAuthnRequestURL must return a non-empty request ID")
	}

	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("redirect URL is not valid: %v", err)
	}

	q := parsed.Query()
	for _, param := range []string{"SAMLRequest", "RelayState", "SigAlg", "Signature"} {
		if q.Get(param) == "" {
			t.Errorf("query param %q is missing", param)
		}
	}
	if q.Get("RelayState") != "test-relay-state-1234" {
		t.Errorf("RelayState = %q, want %q", q.Get("RelayState"), "test-relay-state-1234")
	}
	if !strings.Contains(q.Get("SigAlg"), "rsa-sha256") {
		t.Errorf("SigAlg = %q, want rsa-sha256 variant", q.Get("SigAlg"))
	}
	if !strings.HasPrefix(parsed.String(), "https://eidas.example.eu/") {
		t.Errorf("redirect URL has wrong base: %s", parsed.String())
	}
}

func TestBuildAuthnRequestURL_SAMLRequestIsDeflated(t *testing.T) {
	sp := newTestSP(t)
	redirectURL, _, err := sp.BuildAuthnRequestURL("relay")
	if err != nil {
		t.Fatalf("BuildAuthnRequestURL: %v", err)
	}
	parsed, _ := url.Parse(redirectURL)
	encoded := parsed.Query().Get("SAMLRequest")
	if encoded == "" {
		t.Fatal("SAMLRequest param empty")
	}
	// Decode base64 and inflate — must produce valid XML starting with <.
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("SAMLRequest base64 decode: %v", err)
	}
	r := flate.NewReader(io.NopCloser(strings.NewReader(string(compressed))))
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("deflate decompress: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "<") {
		t.Errorf("inflated SAMLRequest is not XML: %q", string(raw)[:min(80, len(raw))])
	}
	if !strings.Contains(string(raw), "AuthnRequest") {
		t.Error("inflated SAMLRequest is missing AuthnRequest element")
	}
}

func TestBuildAuthnRequestURL_differentRelayStatesProduceDifferentURLs(t *testing.T) {
	sp := newTestSP(t)
	u1, _, _ := sp.BuildAuthnRequestURL("relay-A")
	u2, _, _ := sp.BuildAuthnRequestURL("relay-B")
	if u1 == u2 {
		t.Error("different relay states should produce different redirect URLs")
	}
}

// ── SynthesiseEmail ───────────────────────────────────────────────────────────

func TestSynthesiseEmail(t *testing.T) {
	tests := []struct {
		name      string
		id        eidas.EidasIdentity
		domain    string
		wantLocal string // expected local part (before @)
	}{
		{
			name:      "standard CC/CC/ID format",
			id:        eidas.EidasIdentity{PersonIdentifier: "DE/IT/123456789"},
			domain:    "example.com",
			wantLocal: "de_it_123456789",
		},
		{
			name:      "lowercase normalisation",
			id:        eidas.EidasIdentity{PersonIdentifier: "FR/FR/FRFRXYZ"},
			domain:    "example.org",
			wantLocal: "fr_fr_frfrxyz",
		},
		{
			name:      "fallback to NameID when PersonIdentifier empty",
			id:        eidas.EidasIdentity{NameID: "persistent-id-abc"},
			domain:    "example.net",
			wantLocal: "persistent-id-abc",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.id.SynthesiseEmail(tc.domain)
			wantSuffix := "@eidas." + tc.domain
			if !strings.HasSuffix(got, wantSuffix) {
				t.Errorf("SynthesiseEmail = %q, want suffix %q", got, wantSuffix)
			}
			local := strings.TrimSuffix(got, wantSuffix)
			if local != tc.wantLocal {
				t.Errorf("local part = %q, want %q", local, tc.wantLocal)
			}
		})
	}
}

// ── LoA defaults ─────────────────────────────────────────────────────────────

func TestNew_defaultLoA(t *testing.T) {
	certPEM, keyPEM, _ := eidas.GenerateSelfSignedCert("X")
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	kb, _ := pem.Decode(keyPEM)
	key, _ := x509.ParsePKCS1PrivateKey(kb.Bytes)

	sp := eidas.New(eidas.SPConfig{
		EntityID:    "https://example.com",
		Certificate: cert, PrivateKey: key,
		EidasNodeURL:                "https://node.example.eu",
		AssertionConsumerServiceURL: "https://example.com/callback",
	})
	// When RequestedLoA is empty, defaults to LoALow.
	u, _, err := sp.BuildAuthnRequestURL("r")
	if err != nil {
		t.Fatalf("BuildAuthnRequestURL: %v", err)
	}
	// Inflate and check LoALow is present.
	parsed, _ := url.Parse(u)
	enc, _ := base64.StdEncoding.DecodeString(parsed.Query().Get("SAMLRequest"))
	r := flate.NewReader(io.NopCloser(strings.NewReader(string(enc))))
	raw, _ := io.ReadAll(r)
	if !strings.Contains(string(raw), eidas.LoALow) {
		t.Errorf("default LoA should be %q; AuthnRequest: %s", eidas.LoALow, raw)
	}
}

// ── ParseAssertion error paths ────────────────────────────────────────────────

func TestParseAssertion_invalidBase64(t *testing.T) {
	sp := newTestSP(t)
	certPEM, _, _ := eidas.GenerateSelfSignedCert("IDP")
	_, err := sp.ParseAssertion("NOT-VALID-BASE64!!!", "", certPEM)
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestParseAssertion_invalidIDPCert(t *testing.T) {
	sp := newTestSP(t)
	// A valid base64 payload but garbage content.
	garbage := base64.StdEncoding.EncodeToString([]byte("not xml"))
	_, err := sp.ParseAssertion(garbage, "", []byte("not a pem cert"))
	if err == nil {
		t.Error("expected error for invalid IDP cert PEM, got nil")
	}
}

func TestParseAssertion_wrongSignature(t *testing.T) {
	// A well-formed but unsigned (empty) XML document, signed by a different key.
	sp := newTestSP(t)
	// Use a different cert for the "IDP" — sig verification must fail.
	idpCertPEM, _, _ := eidas.GenerateSelfSignedCert("Different IDP")
	fakeResponse := base64.StdEncoding.EncodeToString([]byte(`<samlp:Response
		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		ID="_fake" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
	</samlp:Response>`))
	_, err := sp.ParseAssertion(fakeResponse, "", idpCertPEM)
	if err == nil {
		t.Error("expected signature validation error, got nil")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
