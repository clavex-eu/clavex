package eidas_test

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/clavex-eu/clavex/internal/eidas"
)

func parseCertKey(t *testing.T, certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	cb, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	kb, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return cert, key
}

const (
	testEntityID = "https://auth.example.com/eidas/metadata"
	testACSURL   = "https://auth.example.com/acme/eidas/callback"
)

// signedEidasResponse builds a SAML Response signed with certPEM/keyPEM, with the
// given SubjectConfirmationData InResponseTo/Recipient and AudienceRestriction.
// Returns the base64-encoded signed response.
func signedEidasResponse(t *testing.T, certPEM, keyPEM []byte, inResponseTo, recipient, audience string) string {
	t.Helper()
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	future := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	past := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	respXML := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="%s">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assert1" Version="2.0" IssueInstant="%s">
    <saml:Issuer>https://eidas.example.eu/idp</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">DE/IT/123</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="%s" Recipient="%s" NotOnOrAfter="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"><saml:AttributeValue>DE/IT/123</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`, future, future, inResponseTo, recipient, future, past, future, audience)

	doc := etree.NewDocument()
	if err := doc.ReadFromString(respXML); err != nil {
		t.Fatalf("parse response xml: %v", err)
	}
	sigCtx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tlsCert))
	sigCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := sigCtx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatalf("sign enveloped: %v", err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	s, err := out.WriteToString()
	if err != nil {
		t.Fatalf("serialize signed xml: %v", err)
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func newACSTestSP(t *testing.T) *eidas.ServiceProvider {
	t.Helper()
	certPEM, keyPEM, _ := eidas.GenerateSelfSignedCert("SP")
	cert, key := parseCertKey(t, certPEM, keyPEM)
	return eidas.New(eidas.SPConfig{
		EntityID:                    testEntityID,
		AssertionConsumerServiceURL: testACSURL,
		EidasNodeURL:                "https://eidas.example.eu/node",
		Certificate:                 cert,
		PrivateKey:                  key,
		RequestedLoA:                eidas.LoASubstantial,
	})
}

func TestParseAssertion_AcceptsWellFormed(t *testing.T) {
	idpCertPEM, idpKeyPEM, _ := eidas.GenerateSelfSignedCert("IDP")
	sp := newACSTestSP(t)
	resp := signedEidasResponse(t, idpCertPEM, idpKeyPEM, "_req1", testACSURL, testEntityID)

	id, err := sp.ParseAssertion(resp, "_req1", idpCertPEM)
	if err != nil {
		t.Fatalf("expected valid assertion to pass, got: %v", err)
	}
	if id.PersonIdentifier != "DE/IT/123" {
		t.Errorf("PersonIdentifier = %q, want DE/IT/123", id.PersonIdentifier)
	}
}

func TestParseAssertion_RejectsInResponseToMismatch(t *testing.T) {
	idpCertPEM, idpKeyPEM, _ := eidas.GenerateSelfSignedCert("IDP")
	sp := newACSTestSP(t)
	resp := signedEidasResponse(t, idpCertPEM, idpKeyPEM, "_attacker", testACSURL, testEntityID)

	if _, err := sp.ParseAssertion(resp, "_req1", idpCertPEM); err == nil {
		t.Error("expected InResponseTo mismatch to be rejected")
	}
}

func TestParseAssertion_RejectsAudienceMismatch(t *testing.T) {
	idpCertPEM, idpKeyPEM, _ := eidas.GenerateSelfSignedCert("IDP")
	sp := newACSTestSP(t)
	resp := signedEidasResponse(t, idpCertPEM, idpKeyPEM, "_req1", testACSURL, "https://other-sp.example/metadata")

	if _, err := sp.ParseAssertion(resp, "_req1", idpCertPEM); err == nil {
		t.Error("expected audience mismatch to be rejected")
	}
}

func TestParseAssertion_RejectsRecipientMismatch(t *testing.T) {
	idpCertPEM, idpKeyPEM, _ := eidas.GenerateSelfSignedCert("IDP")
	sp := newACSTestSP(t)
	resp := signedEidasResponse(t, idpCertPEM, idpKeyPEM, "_req1", "https://evil.example/acs", testEntityID)

	if _, err := sp.ParseAssertion(resp, "_req1", idpCertPEM); err == nil {
		t.Error("expected Recipient mismatch to be rejected")
	}
}
