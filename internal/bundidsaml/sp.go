// Package bundidsaml implements a SAML 2.0 Service Provider for BundID,
// the German federal digital identity portal operated by FITKO (Föderale
// IT-Kooperation). BundID aggregates multiple eID means:
//
//   - Online-Ausweis / nPA (eIDAS High)
//   - ELSTER-Zertifikat     (eIDAS Substantial)
//   - Benutzername + PW     (eIDAS Low)
//
// IdP Metadata URLs:
//
//	Production:  https://id.bund.de/idp/saml/metadata
//	Integration: https://int.id.bund.de/idp/saml/metadata
//
// Registration (SP-Registrierung):
//
//	Production:  https://id.bund.de/de/fuer-dienstleister/registrierung
//	Integration: self-service at https://int.id.bund.de (no review needed)
//
// Registration checklist:
//  1. Generate SP metadata XML via GET /api/v1/organizations/:id/bundid-saml/metadata
//  2. Host SP metadata publicly at a HTTPS URL (e.g. https://app.example.de/<slug>/bundidsaml/metadata)
//  3. Submit SP metadata URL + contact details via the FITKO registration portal
//  4. FITKO review takes ~3-5 business days; integration environment is instant
//  5. Receive confirmation email → activate provider in admin UI (is_active = true)
//  6. Test with integration environment before switching to production
package bundidsaml

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/beevik/etree"
	crewsaml "github.com/crewjam/saml"
	"github.com/google/uuid"
)

// ── LoA constants (eIDAS AuthnContextClassRef URIs) ─────────────────────────

const (
	// LoALow is eIDAS Low — username + password at BundID (Benutzerkonto Bund).
	LoALow = "http://eidas.europa.eu/LoA/low"

	// LoASubstantial is eIDAS Substantial — verified identity or ELSTER certificate.
	LoASubstantial = "http://eidas.europa.eu/LoA/substantial"

	// LoAHigh is eIDAS High — Online-Ausweis (nPA) or equivalent hardware token.
	LoAHigh = "http://eidas.europa.eu/LoA/high"

	// BundID-native LoA URIs (used in some AuthnContextClassRef positions)
	LoABundIDLow         = "https://www.authenticationlevel.bund.de/ns/eID/internet"
	LoABundIDSubstantial = "https://www.authenticationlevel.bund.de/ns/eID/substantial"
	LoABundIDHigh        = "https://www.authenticationlevel.bund.de/ns/eID/high"
)

// loaURI maps the stored short key ("low","substantial","high") to the canonical
// eIDAS AuthnContextClassRef URI used in AuthnRequest / SP metadata.
func loaURI(minLoA string) string {
	switch minLoA {
	case "low":
		return LoALow
	case "high":
		return LoAHigh
	default:
		return LoASubstantial
	}
}

// ── Endpoints ────────────────────────────────────────────────────────────────

// Endpoints holds the BundID IdP endpoint URLs for one environment.
type Endpoints struct {
	// MetadataURL is the BundID IdP SAML metadata URL.
	// Fetched once and cached; refreshed every 24 h.
	MetadataURL string
}

// GetEndpoints returns the BundID IdP endpoint set for the given environment.
// env must be "production" or "integration".
func GetEndpoints(env string) Endpoints {
	if env == "production" {
		return Endpoints{
			MetadataURL: "https://id.bund.de/idp/saml/metadata",
		}
	}
	return Endpoints{
		MetadataURL: "https://int.id.bund.de/idp/saml/metadata",
	}
}

// ── Attributes ───────────────────────────────────────────────────────────────

// Attribute name constants. BundID uses eIDAS Natural Person attribute names
// (http://eidas.europa.eu/attributes/naturalperson/*) plus standard LDAP OIDs.
const (
	// AttrPersonIdentifier is the eIDAS pseudonymous persistent identifier (BundID-ID).
	// Format: <CC>/<CC>/<pseudonym>, e.g. "DE/DE/ABCDEF123456789"
	// Required; always present.
	AttrPersonIdentifier = "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"

	// AttrCurrentFamilyName is the legal family name (Nachname).
	// Available when LoA ≥ Substantial and identity is verified.
	AttrCurrentFamilyName = "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"

	// AttrCurrentGivenName is the legal given name (Vorname).
	// Available when LoA ≥ Substantial and identity is verified.
	AttrCurrentGivenName = "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"

	// AttrDateOfBirth is the date of birth (Geburtsdatum), format YYYY-MM-DD.
	// Available at LoA ≥ Substantial.
	AttrDateOfBirth = "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth"

	// AttrPlaceOfBirth is the place of birth (Geburtsort).
	// Available at LoA ≥ Substantial, only when released.
	AttrPlaceOfBirth = "http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth"

	// AttrBirthName is the birth name (Geburtsname), if different from family name.
	AttrBirthName = "http://eidas.europa.eu/attributes/naturalperson/BirthName"

	// AttrCurrentAddress is the current address (Anschrift), structured XML.
	// Available at LoA High (nPA only); requires explicit FITKO approval.
	AttrCurrentAddress = "http://eidas.europa.eu/attributes/naturalperson/CurrentAddress"

	// AttrGender is the gender attribute (Geschlecht).
	// Available at LoA High (nPA only); may not be released by all eID means.
	AttrGender = "http://eidas.europa.eu/attributes/naturalperson/Gender"

	// AttrEmailAddress is the user's email address.
	// Only available when the user has a verified BundID account and has consented.
	AttrEmailAddress = "http://eidas.europa.eu/attributes/naturalperson/EmailAddress"
)

// AttributeDef describes a BundID attribute with its friendly name for SP metadata.
type AttributeDef struct {
	FriendlyName string
	NameFormat   string // always "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
}

// KnownAttributes is the full set of BundID-supported attributes.
var KnownAttributes = map[string]AttributeDef{
	AttrPersonIdentifier:  {FriendlyName: "BundID-ID (eIDAS PersonIdentifier)", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
	AttrCurrentFamilyName: {FriendlyName: "Nachname (CurrentFamilyName)", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
	AttrCurrentGivenName:  {FriendlyName: "Vorname (CurrentGivenName)", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
	AttrDateOfBirth:       {FriendlyName: "Geburtsdatum (DateOfBirth)", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
	AttrPlaceOfBirth:      {FriendlyName: "Geburtsort (PlaceOfBirth)", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
	AttrBirthName:         {FriendlyName: "Geburtsname (BirthName)", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
	AttrCurrentAddress:    {FriendlyName: "Anschrift (CurrentAddress)", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
	AttrGender:            {FriendlyName: "Geschlecht (Gender)", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
	AttrEmailAddress:      {FriendlyName: "E-Mail-Adresse", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
}

// Predefined attribute sets.
var (
	// AttributeSetMinimum: just the pseudonymous BundID-ID — suitable for
	// applications that manage their own user record and only need a stable key.
	AttributeSetMinimum = []string{AttrPersonIdentifier}

	// AttributeSetBase: identity + name — suitable for most citizen-facing services.
	AttributeSetBase = []string{
		AttrPersonIdentifier,
		AttrCurrentFamilyName,
		AttrCurrentGivenName,
	}

	// AttributeSetFull: full natural person dataset (requires LoA ≥ Substantial).
	AttributeSetFull = []string{
		AttrPersonIdentifier,
		AttrCurrentFamilyName,
		AttrCurrentGivenName,
		AttrDateOfBirth,
		AttrPlaceOfBirth,
		AttrEmailAddress,
	}
)

// BundIDIdentity holds the verified identity attributes extracted from a BundID assertion.
type BundIDIdentity struct {
	// Sub is the persistent pseudonymous BundID-ID (eIDAS PersonIdentifier).
	// Format: "DE/DE/<pseudonym>". Always present. Use as the stable account key.
	Sub string

	// Email is the user's verified email address (may be empty).
	// If empty, synthesise one from Sub for internal routing (see EmailOrSynth).
	Email string

	// EmailSynthetic is true when Email was synthesised rather than asserted by BundID.
	EmailSynthetic bool

	// GivenName is the legal first name (Vorname). Empty at LoA Low.
	GivenName string

	// FamilyName is the legal family name (Nachname). Empty at LoA Low.
	FamilyName string

	// DateOfBirth is the date of birth in YYYY-MM-DD format. Empty at LoA Low.
	DateOfBirth string

	// PlaceOfBirth is the place of birth (Geburtsort). May be empty.
	PlaceOfBirth string

	// LoA is the assurance level of this authentication
	// (one of the eIDAS URI constants above).
	LoA string
}

// EmailOrSynth returns the asserted email or a synthesised fallback
// based on the pseudonymous BundID-ID. The fallback is deterministic and
// stable across logins for the same BundID account.
func (id *BundIDIdentity) EmailOrSynth() string {
	if id.Email != "" {
		return id.Email
	}
	// Derive a stable internal address from the last component of the eIDAS sub.
	// e.g. "DE/DE/ABCDEF123456789" → "abcdef123456789@bundid.internal"
	parts := strings.Split(id.Sub, "/")
	key := strings.ToLower(parts[len(parts)-1])
	return key + "@bundid.internal"
}

// ── Service Provider ─────────────────────────────────────────────────────────

// SPConfig holds everything needed to act as a BundID SAML SP for one tenant org.
type SPConfig struct {
	EntityID       string
	OrgName        string
	OrgDisplayName string
	OrgURL         string
	ContactEmail   string
	ContactPhone   string
	MinLoA         string // "low" | "substantial" | "high"
	AttributeSet   []string
	// ACSURL is the absolute HTTP-POST callback URL.
	// e.g. https://app.example.de/{slug}/bundidsaml/callback
	ACSURL      string
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// ServiceProvider performs BundID SAML SP operations for one tenant.
type ServiceProvider struct {
	cfg *SPConfig
}

// New builds a ServiceProvider from cfg.
func New(cfg *SPConfig) (*ServiceProvider, error) {
	if cfg.Certificate == nil || cfg.PrivateKey == nil {
		return nil, fmt.Errorf("bundidsaml: SP certificate and private key are required")
	}
	if cfg.MinLoA == "" {
		cfg.MinLoA = "substantial"
	}
	return &ServiceProvider{cfg: cfg}, nil
}

// ── Certificate helpers ───────────────────────────────────────────────────────

// GenerateCert creates a self-signed RSA-2048 certificate suitable for BundID SP signing.
// The certificate must be included in the SP metadata submitted to FITKO.
func GenerateCert() (*rsa.PrivateKey, *x509.Certificate, string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("bundidsaml: generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "BundID SP Signing Certificate"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("bundidsaml: create cert: %w", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	certPEM := encodeCertPEM(cert)
	keyPEM := encodeKeyPEM(key)
	return key, cert, string(certPEM), string(keyPEM), nil
}

// ParseCertAndKey parses PEM-encoded certificate and private key.
func ParseCertAndKey(certPEM, keyPEM string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certParsed, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("bundidsaml: parse cert: %w", err)
	}
	keyParsed, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("bundidsaml: parse key: %w", err)
	}
	return certParsed, keyParsed, nil
}

// ── AuthnRequest ─────────────────────────────────────────────────────────────

var authnRequestTmpl = template.Must(template.New("authnreq").Parse(`<?xml version="1.0"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{{.ID}}"
    Version="2.0"
    IssueInstant="{{.IssueInstant}}"
    Destination="{{.Destination}}"
    AssertionConsumerServiceURL="{{.ACSURL}}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer
      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{{.EntityID}}</saml:Issuer>
  <samlp:NameIDPolicy
      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
      AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="minimum">
    <saml:AuthnContextClassRef>{{.AuthnContextClassRef}}</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`))

type authnRequestData struct {
	ID                   string
	IssueInstant         string
	Destination          string
	EntityID             string
	ACSURL               string
	AuthnContextClassRef string
}

// MakeAuthnRequest generates a signed BundID AuthnRequest for the given IdP SSO URL.
// Returns the request ID (stored in session for validation) and the HTML auto-submit form.
func (sp *ServiceProvider) MakeAuthnRequest(_ context.Context, idpSSOURL, relayState string) (requestID string, htmlForm []byte, err error) {
	reqID := "_" + strings.ReplaceAll(uuid.New().String(), "-", "")

	var xmlBuf bytes.Buffer
	if err = authnRequestTmpl.Execute(&xmlBuf, authnRequestData{
		ID:                   reqID,
		IssueInstant:         time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Destination:          idpSSOURL,
		EntityID:             sp.cfg.EntityID,
		ACSURL:               sp.cfg.ACSURL,
		AuthnContextClassRef: loaURI(sp.cfg.MinLoA),
	}); err != nil {
		return "", nil, fmt.Errorf("bundidsaml: render authn request: %w", err)
	}

	signed, err := sp.signXML(xmlBuf.Bytes(), reqID)
	if err != nil {
		return "", nil, fmt.Errorf("bundidsaml: sign authn request: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(signed)
	form, err := renderPostForm(idpSSOURL, encoded, relayState)
	if err != nil {
		return "", nil, err
	}
	return reqID, form, nil
}

func (sp *ServiceProvider) signXML(xmlBytes []byte, refID string) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("bundidsaml: parse xml: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{sp.cfg.Certificate.Raw},
		PrivateKey:  sp.cfg.PrivateKey,
		Leaf:        sp.cfg.Certificate,
	}
	keyStore := dsig.TLSCertKeyStore(tlsCert)
	sigCtx := dsig.NewDefaultSigningContext(keyStore)
	sigCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	sigCtx.Hash = crypto.SHA256
	sigCtx.IdAttribute = "ID"
	_ = refID

	signed, err := sigCtx.SignEnveloped(doc.Root())
	if err != nil {
		return nil, fmt.Errorf("bundidsaml: xmldsig sign: %w", err)
	}

	outDoc := etree.NewDocument()
	outDoc.SetRoot(signed)
	return outDoc.WriteToBytes()
}

var postFormTmpl = template.Must(template.New("post").Parse(`<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="POST" action="{{.Action}}">
  <input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}"/>
  {{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}"/>{{end}}
  <noscript><button type="submit">Weiter zum BundID-Identitätsportal</button></noscript>
</form>
</body></html>`))

type postFormData struct {
	Action      string
	SAMLRequest string
	RelayState  string
}

func renderPostForm(idpURL, encodedRequest, relayState string) ([]byte, error) {
	var buf bytes.Buffer
	if err := postFormTmpl.Execute(&buf, postFormData{
		Action:      idpURL,
		SAMLRequest: encodedRequest,
		RelayState:  relayState,
	}); err != nil {
		return nil, fmt.Errorf("bundidsaml: render post form: %w", err)
	}
	return buf.Bytes(), nil
}

// ── SAMLResponse parsing ──────────────────────────────────────────────────────

// ParseResponse validates and extracts a BundIDIdentity from a raw SAMLResponse
// (base64-encoded XML as received in the HTTP-POST parameter).
func (sp *ServiceProvider) ParseResponse(samlResponseB64, expectedRequestID string, idpCert *x509.Certificate) (*BundIDIdentity, error) {
	raw, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return nil, fmt.Errorf("bundidsaml: decode saml response: %w", err)
	}

	// Parse issuer from raw XML to build IdP metadata.
	var respXML struct {
		XMLName xml.Name `xml:"Response"`
		Issuer  struct {
			Value string `xml:",chardata"`
		} `xml:"Issuer"`
	}
	_ = xml.Unmarshal(raw, &respXML)

	spURL, _ := url.Parse(sp.cfg.ACSURL)
	entityURL, _ := url.Parse(sp.cfg.EntityID)

	var idpMeta crewsaml.EntityDescriptor
	if idpCert != nil {
		idpMeta = buildIDPMetadata(respXML.Issuer.Value, idpCert)
	}

	csamlSP := crewsaml.ServiceProvider{
		Key:         sp.cfg.PrivateKey,
		Certificate: sp.cfg.Certificate,
		MetadataURL: *entityURL,
		AcsURL:      *spURL,
		IDPMetadata: &idpMeta,
	}

	assertion, err := csamlSP.ParseXMLResponse(raw, []string{expectedRequestID}, *spURL)
	if err != nil {
		return nil, fmt.Errorf("bundidsaml: parse assertion: %w", err)
	}

	return extractBundIDAttributes(assertion), nil
}

// extractBundIDAttributes maps SAML assertion attributes to BundIDIdentity.
func extractBundIDAttributes(assertion *crewsaml.Assertion) *BundIDIdentity {
	id := &BundIDIdentity{}

	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		id.Sub = assertion.Subject.NameID.Value
	}

	attrGet := func(name string) string {
		for _, stmt := range assertion.AttributeStatements {
			for _, attr := range stmt.Attributes {
				if attr.Name == name {
					if len(attr.Values) > 0 {
						return attr.Values[0].Value
					}
				}
			}
		}
		return ""
	}

	// BundID-ID: prefer explicit PersonIdentifier attribute, fall back to NameID.
	if pid := attrGet(AttrPersonIdentifier); pid != "" {
		id.Sub = pid
	}
	id.GivenName = attrGet(AttrCurrentGivenName)
	id.FamilyName = attrGet(AttrCurrentFamilyName)
	id.DateOfBirth = attrGet(AttrDateOfBirth)
	id.PlaceOfBirth = attrGet(AttrPlaceOfBirth)
	id.Email = attrGet(AttrEmailAddress)

	// Extract LoA from AuthnStatement.
	for _, stmt := range assertion.AuthnStatements {
		if stmt.AuthnContext.AuthnContextClassRef != nil {
			id.LoA = stmt.AuthnContext.AuthnContextClassRef.Value
		}
	}

	if id.Email == "" {
		id.EmailSynthetic = true
	}
	return id
}

// buildIDPMetadata creates a minimal crewjam EntityDescriptor for response validation.
func buildIDPMetadata(entityID string, cert *x509.Certificate) crewsaml.EntityDescriptor {
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)
	return crewsaml.EntityDescriptor{
		EntityID: entityID,
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
											{Data: certB64},
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
}

// ── Metadata ─────────────────────────────────────────────────────────────────

var metadataTmpl = template.Must(template.New("md").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    entityID="{{.EntityID}}">
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
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{{.ACSURL}}"
        index="0"
        isDefault="true"/>
    <md:AttributeConsumingService index="0">
      <md:ServiceName xml:lang="de">{{.OrgDisplayName}}</md:ServiceName>
      {{range .Attributes}}<md:RequestedAttribute
          Name="{{.Name}}"
          NameFormat="{{.NameFormat}}"
          FriendlyName="{{.FriendlyName}}"
          isRequired="true"/>
      {{end}}</md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="de">{{.OrgName}}</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="de">{{.OrgDisplayName}}</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="de">{{.OrgURL}}</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:EmailAddress>{{.ContactEmail}}</md:EmailAddress>
    {{if .ContactPhone}}<md:TelephoneNumber>{{.ContactPhone}}</md:TelephoneNumber>{{end}}
  </md:ContactPerson>
</md:EntityDescriptor>`))

// MetadataXML generates a BundID-compliant SP metadata XML document.
// Submit this to FITKO during SP registration.
func (sp *ServiceProvider) MetadataXML() ([]byte, error) {
	certB64 := base64.StdEncoding.EncodeToString(sp.cfg.Certificate.Raw)

	type attrDef struct {
		Name         string
		NameFormat   string
		FriendlyName string
	}
	var attrs []attrDef
	for _, name := range sp.cfg.AttributeSet {
		a, ok := KnownAttributes[name]
		if !ok {
			continue
		}
		attrs = append(attrs, attrDef{
			Name:         name,
			NameFormat:   a.NameFormat,
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
		Attributes:     attrs,
	}

	var buf bytes.Buffer
	if err := metadataTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("bundidsaml: render metadata: %w", err)
	}
	// Validate well-formed XML.
	if err := xml.NewDecoder(strings.NewReader(buf.String())).Decode(&struct{ XMLName xml.Name }{}); err != nil {
		return nil, fmt.Errorf("bundidsaml: metadata xml invalid: %w", err)
	}
	return buf.Bytes(), nil
}

// ── IdP metadata fetching ─────────────────────────────────────────────────────

// ParseIDPMetadataURL fetches and parses the BundID IdP SAML metadata from the given URL.
func ParseIDPMetadataURL(ctx context.Context, metadataURL string) (*crewsaml.EntityDescriptor, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("bundidsaml: build metadata request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("bundidsaml: fetch metadata: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	var metaXML bytes.Buffer
	if _, err := metaXML.ReadFrom(resp.Body); err != nil {
		return nil, "", fmt.Errorf("bundidsaml: read metadata body: %w", err)
	}
	xmlStr := metaXML.String()

	var ed crewsaml.EntityDescriptor
	if err := xml.NewDecoder(strings.NewReader(xmlStr)).Decode(&ed); err != nil {
		return nil, "", fmt.Errorf("bundidsaml: parse metadata xml: %w", err)
	}
	return &ed, xmlStr, nil
}

// ExtractIDPSSOURL returns the HTTP-POST SSO service URL from an EntityDescriptor.
func ExtractIDPSSOURL(meta *crewsaml.EntityDescriptor) (string, error) {
	for _, desc := range meta.IDPSSODescriptors {
		for _, sso := range desc.SingleSignOnServices {
			if sso.Binding == crewsaml.HTTPPostBinding {
				return sso.Location, nil
			}
		}
		if len(desc.SingleSignOnServices) > 0 {
			return desc.SingleSignOnServices[0].Location, nil
		}
	}
	return "", fmt.Errorf("bundidsaml: no SSO URL found in IdP metadata")
}

// ExtractIDPSigningCert extracts the first signing certificate from an EntityDescriptor.
func ExtractIDPSigningCert(meta *crewsaml.EntityDescriptor) (*x509.Certificate, error) {
	for _, desc := range meta.IDPSSODescriptors {
		for _, kd := range desc.KeyDescriptors {
			if kd.Use == "signing" || kd.Use == "" {
				for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
					certDER, err := base64.StdEncoding.DecodeString(xc.Data)
					if err != nil {
						continue
					}
					cert, err := x509.ParseCertificate(certDER)
					if err != nil {
						continue
					}
					return cert, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("bundidsaml: no signing certificate found in IdP metadata")
}

// ── PEM helpers ───────────────────────────────────────────────────────────────

func encodeCertPEM(cert *x509.Certificate) []byte {
	b64 := chunkB64(base64.StdEncoding.EncodeToString(cert.Raw), 64)
	return []byte("-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n")
}

func encodeKeyPEM(key *rsa.PrivateKey) []byte {
	b64 := chunkB64(base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)), 64)
	return []byte("-----BEGIN RSA PRIVATE KEY-----\n" + b64 + "\n-----END RSA PRIVATE KEY-----\n")
}

func parseCertPEM(pem string) (*x509.Certificate, error) {
	// Strip header/footer and decode
	pem = strings.TrimSpace(pem)
	pem = strings.ReplaceAll(pem, "-----BEGIN CERTIFICATE-----", "")
	pem = strings.ReplaceAll(pem, "-----END CERTIFICATE-----", "")
	pem = strings.ReplaceAll(pem, "\n", "")
	pem = strings.ReplaceAll(pem, "\r", "")
	der, err := base64.StdEncoding.DecodeString(pem)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func parseKeyPEM(pem string) (*rsa.PrivateKey, error) {
	pem = strings.TrimSpace(pem)
	pem = strings.ReplaceAll(pem, "-----BEGIN RSA PRIVATE KEY-----", "")
	pem = strings.ReplaceAll(pem, "-----END RSA PRIVATE KEY-----", "")
	pem = strings.ReplaceAll(pem, "\n", "")
	pem = strings.ReplaceAll(pem, "\r", "")
	der, err := base64.StdEncoding.DecodeString(pem)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(der)
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
