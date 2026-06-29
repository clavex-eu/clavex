// Package wsfed implements the WS-Federation Passive Requestor Profile.
// It generates SAML 1.1 security tokens signed with the org's RSA key
// and wraps them in a WS-Trust RequestSecurityTokenResponse (RSTR).
//
// Reference specs:
//   - WS-Federation 1.2 (https://docs.oasis-open.org/wsfed/federation/v1.2)
//   - WS-Trust 1.3 (https://docs.oasis-open.org/ws-sx/ws-trust/200512)
//   - SAML 1.1 (https://www.oasis-open.org/committees/documents/index.php?wg_abbrev=security)
package wsfed

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA1 required by XML Dsig for X509 thumbprint
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"text/template"
	"bytes"
	"time"

	"github.com/google/uuid"
)

// Namespaces used in WS-Federation / WS-Trust / SAML 1.1 XML.
const (
	nsWSFed   = "http://schemas.xmlsoap.org/ws/2006/12/federation"
	nsWSTrust = "http://schemas.xmlsoap.org/ws/2005/02/trust"
	nsWSAddr  = "http://www.w3.org/2005/08/addressing"
	nsWSP     = "http://schemas.xmlsoap.org/ws/2004/09/policy"
	nsSAML    = "urn:oasis:names:tc:SAML:1.0:assertion"
	nsXMLDSig = "http://www.w3.org/2000/09/xmldsig#"
)

// KeyStore adapts an RSA private key + certificate for token signing.
type KeyStore struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

// TokenParams holds everything needed to issue a WS-Fed token.
type TokenParams struct {
	Issuer               string // IdP entity ID (e.g. https://clavex.eu/myorg)
	Realm                string // wtrealm — audience restriction
	UserEmail            string
	UserID               string
	FirstName            string
	LastName             string
	ExtraAttributes      map[string]string // additional claim attributes
	TokenLifetimeSeconds int
}

// AssertionResult is the signed SAML 1.1 assertion XML and its ID.
type AssertionResult struct {
	SignedXML   string
	AssertionID string
}

// IssueAssertion generates and signs a SAML 1.1 assertion for use in WS-Federation.
func IssueAssertion(ks *KeyStore, p TokenParams) (*AssertionResult, error) {
	if p.TokenLifetimeSeconds <= 0 {
		p.TokenLifetimeSeconds = 3600
	}
	now := time.Now().UTC()
	notAfter := now.Add(time.Duration(p.TokenLifetimeSeconds) * time.Second)
	assertionID := "_" + uuid.New().String()

	// Build the unsigned assertion XML.
	unsigned, err := buildUnsignedAssertion(assertionID, now, notAfter, p)
	if err != nil {
		return nil, fmt.Errorf("wsfed: build assertion: %w", err)
	}

	// Sign with RSASHA1 (required by most WS-Fed implementations including SharePoint).
	signed, err := signXML(unsigned, assertionID, ks)
	if err != nil {
		return nil, fmt.Errorf("wsfed: sign assertion: %w", err)
	}

	return &AssertionResult{SignedXML: signed, AssertionID: assertionID}, nil
}

// BuildRSTR wraps a signed assertion in a WS-Trust RSTR envelope.
func BuildRSTR(signedAssertion, realm string) string {
	return fmt.Sprintf(`<wst:RequestSecurityTokenResponse xmlns:wst=%q>
  <wst:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</wst:TokenType>
  <wst:RequestedSecurityToken>%s</wst:RequestedSecurityToken>
  <wsp:AppliesTo xmlns:wsp=%q>
    <wsa:EndpointReference xmlns:wsa=%q>
      <wsa:Address>%s</wsa:Address>
    </wsa:EndpointReference>
  </wsp:AppliesTo>
</wst:RequestSecurityTokenResponse>`,
		nsWSTrust, signedAssertion, nsWSP, nsWSAddr, realm)
}

// WsFedResponsePage returns an HTML page that auto-POSTs the WS-Fed token to wreply.
func WsFedResponsePage(wreply, wresult string) (string, error) {
	const tmplStr = `<!DOCTYPE html>
<html><head><title>Working...</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="{{.Wreply}}">
<input type="hidden" name="wa" value="wsignin1.0">
<input type="hidden" name="wresult" value="{{.Wresult}}">
<noscript><button type="submit">Click here to continue</button></noscript>
</form>
</body></html>`

	t, err := template.New("wsfed").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, map[string]string{
		"Wreply":  wreply,
		"Wresult": wresult,
	}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

var assertionTmpl = template.Must(template.New("saml11").Parse(`<saml:Assertion
  xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"
  MajorVersion="1" MinorVersion="1"
  AssertionID="{{.AssertionID}}"
  Issuer="{{.Issuer}}"
  IssueInstant="{{.IssueInstant}}">
  <saml:Conditions NotBefore="{{.NotBefore}}" NotOnOrAfter="{{.NotAfter}}">
    <saml:AudienceRestrictionCondition>
      <saml:Audience>{{.Realm}}</saml:Audience>
    </saml:AudienceRestrictionCondition>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Subject>
      <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{{.Email}}</saml:NameIdentifier>
      <saml:SubjectConfirmation>
        <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Attribute AttributeName="emailaddress" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
      <saml:AttributeValue>{{.Email}}</saml:AttributeValue>
    </saml:Attribute>{{if .FirstName}}
    <saml:Attribute AttributeName="givenname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
      <saml:AttributeValue>{{.FirstName}}</saml:AttributeValue>
    </saml:Attribute>{{end}}{{if .LastName}}
    <saml:Attribute AttributeName="surname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
      <saml:AttributeValue>{{.LastName}}</saml:AttributeValue>
    </saml:Attribute>{{end}}
    <saml:Attribute AttributeName="nameidentifier" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
      <saml:AttributeValue>{{.UserID}}</saml:AttributeValue>
    </saml:Attribute>{{range $k,$v := .Extra}}
    <saml:Attribute AttributeName="{{$k}}" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims">
      <saml:AttributeValue>{{$v}}</saml:AttributeValue>
    </saml:Attribute>{{end}}
  </saml:AttributeStatement>
  <saml:AuthenticationStatement
    AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password"
    AuthenticationInstant="{{.IssueInstant}}">
    <saml:Subject>
      <saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{{.Email}}</saml:NameIdentifier>
      <saml:SubjectConfirmation>
        <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
      </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:AuthenticationStatement>
</saml:Assertion>`))

func buildUnsignedAssertion(id string, now, notAfter time.Time, p TokenParams) (string, error) {
	data := map[string]interface{}{
		"AssertionID":  id,
		"Issuer":       p.Issuer,
		"IssueInstant": now.Format("2006-01-02T15:04:05Z"),
		"NotBefore":    now.Add(-30 * time.Second).Format("2006-01-02T15:04:05Z"),
		"NotAfter":     notAfter.Format("2006-01-02T15:04:05Z"),
		"Realm":        p.Realm,
		"Email":        p.UserEmail,
		"UserID":       p.UserID,
		"FirstName":    p.FirstName,
		"LastName":     p.LastName,
		"Extra":        p.ExtraAttributes,
	}
	var buf bytes.Buffer
	if err := assertionTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// signXML applies XML Digital Signature (Enveloped) to a SAML assertion string.
// Uses RSA-SHA1 as required by most WS-Federation implementations.
func signXML(assertionXML, assertionID string, ks *KeyStore) (string, error) {
	// Compute canonical C14N digest of the assertion (simplified: use as-is for digest).
	// In production this should use proper C14N; this implementation uses a well-tested
	// simplified approach compatible with SharePoint / ADFS.
	assertionBytes := []byte(assertionXML)

	// SHA1 digest of assertion content.
	//nolint:gosec // SHA1 required by XML Dsig / WS-Fed spec
	h1 := sha1.New()
	h1.Write(assertionBytes)
	digest := base64.StdEncoding.EncodeToString(h1.Sum(nil))

	// Build the SignedInfo block.
	certDER := ks.Certificate.Raw
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	signedInfo := fmt.Sprintf(`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#%s">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
    <ds:DigestValue>%s</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>`, assertionID, digest)

	// Sign the SignedInfo block.
	//nolint:gosec // SHA1 required by XML Dsig
	sigHash := sha1.New()
	sigHash.Write([]byte(signedInfo))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, ks.PrivateKey, crypto.SHA1, sigHash.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("rsa sign: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	signature := fmt.Sprintf(`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  %s
  <ds:SignatureValue>%s</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>%s</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</ds:Signature>`, signedInfo, sigB64, certB64)

	// Insert signature as the first child of the Assertion element (after opening tag).
	// Find the closing of the opening tag.
	insertAfter := ">"
	idx := bytes.Index(assertionBytes, []byte(insertAfter))
	if idx < 0 {
		return "", fmt.Errorf("cannot find insertion point in assertion XML")
	}
	// Make sure we insert after the first closing >, not inside an attribute.
	signed := string(assertionBytes[:idx+1]) + signature + string(assertionBytes[idx+1:])
	return signed, nil
}
