package spid

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"text/template"
)

// SPIDIdentity is defined in attributes.go — attributes extracted from assertion.

// MetadataXML generates a SPID-compliant SP metadata XML document.
// The output must be submitted to AgID during service activation.
func (sp *ServiceProvider) MetadataXML() ([]byte, error) {
	certB64 := base64.StdEncoding.EncodeToString(sp.cfg.Certificate.Raw)

	type attrDef struct {
		Name         string
		NameFormat   string
		FriendlyName string
	}

	var attrs []attrDef
	for _, name := range sp.cfg.AttributeSet {
		a, ok := knownAttributes[name]
		if !ok {
			continue
		}
		attrs = append(attrs, attrDef{
			Name:         name,
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			FriendlyName: a.FriendlyName,
		})
	}

	data := struct {
		EntityID       string
		ACSURL         string
		CertB64        string
		OrgName        string
		OrgDisplayName string
		OrgURL         string
		ContactEmail   string
		ContactPhone   string
		VATNumber      string
		IPACode        string
		IsPublic       bool
		Attributes     []attrDef
	}{
		EntityID:       sp.cfg.EntityID,
		ACSURL:         sp.cfg.ACSURL,
		CertB64:        certB64,
		OrgName:        sp.cfg.OrgName,
		OrgDisplayName: sp.cfg.OrgDisplayName,
		OrgURL:         sp.cfg.OrgURL,
		ContactEmail:   sp.cfg.ContactEmail,
		ContactPhone:   sp.cfg.ContactPhone,
		VATNumber:      sp.cfg.VATNumber,
		IPACode:        sp.cfg.IPACode,
		IsPublic:       sp.cfg.EntityType == "public",
		Attributes:     attrs,
	}

	var buf bytes.Buffer
	if err := metadataTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("spid: render metadata: %w", err)
	}

	// Validate the output is well-formed XML before returning.
	if err := xml.NewDecoder(strings.NewReader(buf.String())).Decode(&struct{ XMLName xml.Name }{}); err != nil {
		return nil, fmt.Errorf("spid: metadata xml validation: %w", err)
	}

	return buf.Bytes(), nil
}

// MetadataXMLSigned returns the SP metadata XML signed with the SP key.
func (sp *ServiceProvider) MetadataXMLSigned() ([]byte, error) {
	raw, err := sp.MetadataXML()
	if err != nil {
		return nil, err
	}
	return sp.signXML(raw, "")
}

// PEMCert returns the SP signing certificate as PEM (public, safe to include in metadata).
func PEMCert(cert *x509.Certificate) string {
	return string(encodeCertPEM(cert))
}

// PEMKey returns the SP private key as PEM PKCS#1.
func PEMKey(key *rsa.PrivateKey) string {
	return string(encodeKeyPEM(key))
}

func encodeCertPEM(cert *x509.Certificate) []byte {
	return []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
		chunkB64(base64.StdEncoding.EncodeToString(cert.Raw), 64)))
}

func encodeKeyPEM(key *rsa.PrivateKey) []byte {
	return []byte(fmt.Sprintf("-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n",
		chunkB64(base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)), 64)))
}

func chunkB64(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// metadataTmpl is the SPID-compliant SP metadata XML template.
// Based on AgID SPID regola tecnica (SPID-AVVISO-n29, rev3 2021).
var metadataTmpl = template.Must(template.New("meta").Funcs(template.FuncMap{
	// urlhash produces a short stable ID token from the entityID URL string.
	"urlhash": func(s string) string {
		h := 0
		for _, c := range s {
			h = h*31 + int(c)
		}
		return fmt.Sprintf("%x", uint32(h))
	},
	// phone39 ensures the Italian phone number is prefixed with "+39" as required by AgID.
	"phone39": func(s string) string {
		if strings.HasPrefix(s, "+39") {
			return s
		}
		return "+39" + s
	},
}).Parse(`<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:spid="https://spid.gov.it/saml-extensions"
    entityID="{{.EntityID}}"
    ID="_{{.EntityID | urlhash}}">

  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{{.CertB64}}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>

    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{{.ACSURL}}"/>

    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>

    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{{.ACSURL}}"
        index="0"
        isDefault="true"/>

    <md:AttributeConsumingService index="0">
      <md:ServiceName xml:lang="it">{{.OrgDisplayName}}</md:ServiceName>
      {{range .Attributes}}<md:RequestedAttribute
          Name="{{.Name}}"
          NameFormat="{{.NameFormat}}"
          FriendlyName="{{.FriendlyName}}"/>
      {{end}}
    </md:AttributeConsumingService>

  </md:SPSSODescriptor>

  <md:Organization>
    <md:OrganizationName xml:lang="it">{{.OrgName}}</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="it">{{.OrgDisplayName}}</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="it">{{.OrgURL}}</md:OrganizationURL>
  </md:Organization>

  <md:ContactPerson contactType="other">
    <md:Extensions>
      {{if .IsPublic}}<spid:Public/>
      <spid:IPACode>{{.IPACode}}</spid:IPACode>
      {{else}}<spid:VATNumber>IT{{.VATNumber}}</spid:VATNumber>
      <spid:Private/>
      {{end}}</md:Extensions>
    <md:EmailAddress>{{.ContactEmail}}</md:EmailAddress>
    {{if .ContactPhone}}<md:TelephoneNumber>{{.ContactPhone | phone39}}</md:TelephoneNumber>{{end}}
  </md:ContactPerson>

</md:EntityDescriptor>`))
