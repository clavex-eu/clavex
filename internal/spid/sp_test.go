package spid

import (
	"context"
	"strings"
	"testing"

	"github.com/beevik/etree"
	crewsaml "github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestSP(t *testing.T) *ServiceProvider {
	t.Helper()
	key, cert, _, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)
	sp, err := New(&SPConfig{
		EntityID:       "https://clavex.example.com/spid/sp",
		OrgName:        "Example Org",
		OrgDisplayName: "Example Organization",
		OrgURL:         "https://example.com",
		ContactEmail:   "admin@example.com",
		ACSURL:         "https://clavex.example.com/test-org/spid/callback",
		EntityType:     "private",
		AuthnLevel:     2,
		AttributeSet:   AttributeSetBase,
		Certificate:    cert,
		PrivateKey:     key,
	})
	require.NoError(t, err)
	return sp
}

// ── GenerateCert ──────────────────────────────────────────────────────────────

func TestGenerateCert_ReturnsKeyAndCert(t *testing.T) {
	key, cert, certPEM, keyPEM, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	assert.NotNil(t, key)
	assert.NotNil(t, cert)
	assert.Contains(t, certPEM, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, keyPEM, "-----BEGIN RSA PRIVATE KEY-----")
}

func TestGenerateCert_CertMatchesKey(t *testing.T) {
	key, cert, _, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)
	assert.Equal(t, &key.PublicKey, cert.PublicKey)
}

func TestGenerateCert_BasicConstraintsNotCritical(t *testing.T) {
	_, cert, _, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.19" { // basicConstraints OID
			assert.False(t, ext.Critical, "basicConstraints MUST NOT be critical for SPID SP certs")
			return
		}
	}
	t.Error("basicConstraints extension not found in certificate")
}

func TestGenerateCert_SPIDPolicyOID(t *testing.T) {
	_, cert, _, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	// Both AgID SPID policy OIDs must be present.
	requiredOIDs := []string{"1.3.76.16.6", "1.3.76.16.4.2.1"}
	for _, spidPolicyOID := range requiredOIDs {
		found := false
		for _, p := range cert.PolicyIdentifiers { //nolint:staticcheck
			if p.String() == spidPolicyOID {
				found = true
				break
			}
		}
		assert.True(t, found, "SPID policy OID %s must be present in certificatePolicies", spidPolicyOID)
	}
}

// ── ParseCertAndKey ───────────────────────────────────────────────────────────

func TestParseCertAndKey_RoundTrip(t *testing.T) {
	_, _, certPEM, keyPEM, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	cert, key, err := ParseCertAndKey(certPEM, keyPEM)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, key)
}

func TestParseCertAndKey_InvalidCert(t *testing.T) {
	_, _, _, keyPEM, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	_, _, err = ParseCertAndKey("not-a-pem", keyPEM)
	assert.Error(t, err)
}

func TestParseCertAndKey_InvalidKey(t *testing.T) {
	_, _, certPEM, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	_, _, err = ParseCertAndKey(certPEM, "not-a-pem")
	assert.Error(t, err)
}

// ── New ───────────────────────────────────────────────────────────────────────

func TestNew_RequiresCertAndKey(t *testing.T) {
	_, err := New(&SPConfig{})
	assert.Error(t, err)
}

func TestNew_SucceedsWithValidConfig(t *testing.T) {
	_, cert, _, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)
	key, _, _, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	sp, err := New(&SPConfig{
		EntityID:    "https://example.com",
		ACSURL:      "https://example.com/callback",
		Certificate: cert,
		PrivateKey:  key,
	})
	require.NoError(t, err)
	assert.NotNil(t, sp)
}

// ── PEMCert / PEMKey ──────────────────────────────────────────────────────────

func TestPEMCert_ContainsCertHeader(t *testing.T) {
	_, cert, _, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	pem := PEMCert(cert)
	assert.Contains(t, pem, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, pem, "-----END CERTIFICATE-----")
}

func TestPEMKey_ContainsKeyHeader(t *testing.T) {
	key, _, _, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	pem := PEMKey(key)
	assert.Contains(t, pem, "-----BEGIN RSA PRIVATE KEY-----")
	assert.Contains(t, pem, "-----END RSA PRIVATE KEY-----")
}

// ── MetadataXML ───────────────────────────────────────────────────────────────

func TestMetadataXML_IsWellFormedXML(t *testing.T) {
	sp := newTestSP(t)
	xml, err := sp.MetadataXML()
	require.NoError(t, err)

	s := string(xml)
	assert.Contains(t, s, "EntityDescriptor")
	assert.Contains(t, s, "AssertionConsumerService")
}

func TestMetadataXML_ContainsEntityID(t *testing.T) {
	sp := newTestSP(t)
	xml, err := sp.MetadataXML()
	require.NoError(t, err)
	assert.Contains(t, string(xml), "https://clavex.example.com/spid/sp")
}

func TestMetadataXML_ContainsACSURL(t *testing.T) {
	sp := newTestSP(t)
	xml, err := sp.MetadataXML()
	require.NoError(t, err)
	assert.Contains(t, string(xml), "test-org/spid/callback")
}

func TestMetadataXMLSigned_SignatureIsFirstChildAndNotDuplicated(t *testing.T) {
	sp := newTestSP(t)
	xmlBytes, err := sp.MetadataXMLSigned()
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(xmlBytes))

	root := doc.Root()
	require.NotNil(t, root, "root element must exist")

	// Count top-level Signature elements and check position.
	sigCount := 0
	firstNonChardata := -1
	elemIdx := 0
	firstSigAt := -1
	for _, child := range root.Child {
		elem, ok := child.(*etree.Element)
		if !ok {
			continue
		}
		if firstNonChardata == -1 {
			firstNonChardata = elemIdx
		}
		if elem.Tag == "Signature" {
			sigCount++
			if firstSigAt == -1 {
				firstSigAt = elemIdx
			}
		}
		elemIdx++
	}

	assert.Equal(t, 1, sigCount, "EntityDescriptor must contain exactly one ds:Signature")
	assert.Equal(t, 0, firstSigAt, "ds:Signature must be the first child element of EntityDescriptor")
}

func TestMetadataXML_ContainsRequestedAttributes(t *testing.T) {
	sp := newTestSP(t)
	xml, err := sp.MetadataXML()
	require.NoError(t, err)

	// AttributeSetBase includes "email" and "fiscalNumber"
	s := string(xml)
	assert.Contains(t, s, "email")
	assert.Contains(t, s, "fiscalNumber")
}

// ── AttributeSet definitions ──────────────────────────────────────────────────

func TestAttributeSetMinimo_ContainsSpidCodeAndFiscalNumber(t *testing.T) {
	assert.Contains(t, AttributeSetMinimo, "spidCode")
	assert.Contains(t, AttributeSetMinimo, "fiscalNumber")
}

func TestAttributeSetBase_SupersetOfMinimo(t *testing.T) {
	minimoSet := make(map[string]struct{}, len(AttributeSetMinimo))
	for _, a := range AttributeSetMinimo {
		minimoSet[a] = struct{}{}
	}
	for _, a := range AttributeSetMinimo {
		assert.Contains(t, AttributeSetBase, a, "base set must contain %q from minimo", a)
	}
	_ = minimoSet
}

func TestAttributeSetFull_ContainsAllBaseAttributes(t *testing.T) {
	for _, a := range AttributeSetBase {
		assert.Contains(t, AttributeSetFull, a, "full set must contain %q from base", a)
	}
}

// ── MakeAuthnRequest ──────────────────────────────────────────────────────────

func TestMakeAuthnRequest_ReturnsHTMLForm(t *testing.T) {
	sp := newTestSP(t)
	reqID, form, err := sp.MakeAuthnRequest(
		context.Background(),
		"https://idp.spid.gov.it/sso",
		"relay-state-1",
		"",
	)
	require.NoError(t, err)

	assert.NotEmpty(t, reqID)
	assert.True(t, strings.HasPrefix(reqID, "_"), "request ID should start with underscore")
	assert.Contains(t, string(form), "SAMLRequest")
	assert.Contains(t, string(form), "relay-state-1")
}

func TestMakeAuthnRequest_UniqueIDs(t *testing.T) {
	sp := newTestSP(t)
	id1, _, err1 := sp.MakeAuthnRequest(context.Background(), "https://idp.example.com/sso", "", "")
	id2, _, err2 := sp.MakeAuthnRequest(context.Background(), "https://idp.example.com/sso", "", "")
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.NotEqual(t, id1, id2)
}

// ── ExtractIDPSSOURL ──────────────────────────────────────────────────────────

func TestExtractIDPSSOURL_ReturnsPostBinding(t *testing.T) {
	meta := crewsaml.EntityDescriptor{
		IDPSSODescriptors: []crewsaml.IDPSSODescriptor{
			{
				SSODescriptor: crewsaml.SSODescriptor{},
				SingleSignOnServices: []crewsaml.Endpoint{
					{Binding: crewsaml.HTTPRedirectBinding, Location: "https://idp.example.com/sso/redirect"},
					{Binding: crewsaml.HTTPPostBinding, Location: "https://idp.example.com/sso/post"},
				},
			},
		},
	}

	url, err := ExtractIDPSSOURL(&meta)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/sso/post", url)
}

func TestExtractIDPSSOURL_FallsBackToFirstIfNoPost(t *testing.T) {
	meta := crewsaml.EntityDescriptor{
		IDPSSODescriptors: []crewsaml.IDPSSODescriptor{
			{
				SingleSignOnServices: []crewsaml.Endpoint{
					{Binding: crewsaml.HTTPRedirectBinding, Location: "https://idp.example.com/sso/redirect"},
				},
			},
		},
	}

	url, err := ExtractIDPSSOURL(&meta)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/sso/redirect", url)
}

func TestExtractIDPSSOURL_ErrorsIfNoDescriptors(t *testing.T) {
	meta := crewsaml.EntityDescriptor{}
	_, err := ExtractIDPSSOURL(&meta)
	assert.Error(t, err)
}

// ── ExtractIDPSigningCert ─────────────────────────────────────────────────────

func TestExtractIDPSigningCert_ParsesValidCert(t *testing.T) {
	_, origCert, _, _, err := GenerateCert(CertOptions{})
	require.NoError(t, err)

	import64 := strings.ReplaceAll(
		strings.ReplaceAll(PEMCert(origCert), "-----BEGIN CERTIFICATE-----\n", ""),
		"\n-----END CERTIFICATE-----\n", "",
	)
	// PEM cert base64 may have newlines — strip them
	import64 = strings.ReplaceAll(import64, "\n", "")

	meta := crewsaml.EntityDescriptor{
		IDPSSODescriptors: []crewsaml.IDPSSODescriptor{
			{
				SSODescriptor: crewsaml.SSODescriptor{
					RoleDescriptor: crewsaml.RoleDescriptor{
						KeyDescriptors: []crewsaml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: crewsaml.KeyInfo{
									X509Data: crewsaml.X509Data{
										X509Certificates: []crewsaml.X509Certificate{
											{Data: import64},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	cert, err := ExtractIDPSigningCert(&meta)
	require.NoError(t, err)
	assert.Equal(t, origCert.SerialNumber, cert.SerialNumber)
}

func TestExtractIDPSigningCert_ErrorsIfNoCert(t *testing.T) {
	meta := crewsaml.EntityDescriptor{}
	_, err := ExtractIDPSigningCert(&meta)
	assert.Error(t, err)
}
