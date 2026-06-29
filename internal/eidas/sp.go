package eidas

// Package eidas implements a SAML 2.0 Service Provider for the eIDAS node network.
//
// The eIDAS regulation (EU 910/2014) mandates cross-border recognition of national eIDs
// across all 27 EU member states.  A single integration with the national eIDAS Node/Proxy
// gives access to every notified national eID scheme.
//
// Protocol: SAML 2.0 with eIDAS SAML Attribute Profile v1.3
//   - Binding:    HTTP-Redirect (AuthnRequest) + HTTP-POST (ACS)
//   - NameID:     urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
//   - Signing:    XML-DSig enveloped RSA-SHA256 + query-string RSA-SHA256
//   - LoA values: Low | Substantial | High (http://eidas.europa.eu/LoA/*)
//
// References:
//   https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/eIDAS+eID+Profile
//   https://docs.italia.it/italia/spid/spid-regole-tecniche/ (Italian eIDAS Node / AgID)

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
)

// Level of Assurance URIs (eIDAS SAML Attribute Profile §2.1.1).
const (
	LoALow         = "http://eidas.europa.eu/LoA/low"
	LoASubstantial = "http://eidas.europa.eu/LoA/substantial"
	LoAHigh        = "http://eidas.europa.eu/LoA/high"
)

// eIDAS natural-person mandatory attributes (eIDAS SAML Attribute Profile §2.2.1).
const (
	AttrPersonIdentifier = "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"
	AttrFamilyName       = "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"
	AttrFirstName        = "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"
	AttrDateOfBirth      = "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth"
)

// eIDAS optional natural-person attributes.
const (
	AttrBirthName    = "http://eidas.europa.eu/attributes/naturalperson/BirthName"
	AttrPlaceOfBirth = "http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth"
	AttrAddress      = "http://eidas.europa.eu/attributes/naturalperson/CurrentAddress"
	AttrGender       = "http://eidas.europa.eu/attributes/naturalperson/Gender"
)

// NameIDFormat is the SAML 2.0 NameID format used by eIDAS.
const NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

var mandatoryAttrs = map[string]bool{
	AttrPersonIdentifier: true,
	AttrFamilyName:       true,
	AttrFirstName:        true,
	AttrDateOfBirth:      true,
}

// SPConfig holds the configuration for an eIDAS SAML SP instance.
type SPConfig struct {
	EntityID                    string
	AssertionConsumerServiceURL string
	OrgName                     string
	OrgDisplayName              string
	OrgURL                      string
	ContactEmail                string
	Certificate                 *x509.Certificate
	PrivateKey                  crypto.Signer
	EidasNodeURL                string
	RequiredAttributes          []string
	RequestedLoA                string
}

// ServiceProvider is an eIDAS SAML 2.0 SP.
type ServiceProvider struct{ cfg SPConfig }

// New creates a ServiceProvider.
func New(cfg SPConfig) *ServiceProvider {
	if cfg.RequestedLoA == "" {
		cfg.RequestedLoA = LoALow
	}
	if len(cfg.RequiredAttributes) == 0 {
		cfg.RequiredAttributes = []string{
			AttrPersonIdentifier, AttrFamilyName, AttrFirstName, AttrDateOfBirth,
		}
	}
	return &ServiceProvider{cfg: cfg}
}

// GenerateSelfSignedCert creates a fresh 2048-bit RSA key + self-signed cert.
func GenerateSelfSignedCert(orgName string) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: orgName, Organization: []string{orgName}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

// MetadataXML generates SAML 2.0 SP metadata for eIDAS operator registration.
func (sp *ServiceProvider) MetadataXML() ([]byte, error) {
	certB64 := base64.StdEncoding.EncodeToString(sp.cfg.Certificate.Raw)
	type attrEntry struct {
		Name, FriendlyName, Required string
	}
	var attrs []attrEntry
	for _, name := range sp.cfg.RequiredAttributes {
		req := "false"
		if mandatoryAttrs[name] {
			req = "true"
		}
		attrs = append(attrs, attrEntry{name, eidasFriendlyName(name), req})
	}
	const tpl = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{{.EntityID}}">
  <md:Extensions>
    <mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">
      <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
          Name="urn:oasis:names:tc:SAML:attribute:assurance-certification">
        <saml:AttributeValue>{{.LoA}}</saml:AttributeValue>
      </saml:Attribute>
    </mdattr:EntityAttributes>
  </md:Extensions>
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{{.CertB64}}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{{.ACSURL}}" index="0" isDefault="true"/>
    <md:AttributeConsumingService index="0">
      <md:ServiceName xml:lang="en">{{.ServiceName}}</md:ServiceName>{{range .Attrs}}
      <md:RequestedAttribute Name="{{.Name}}" FriendlyName="{{.FriendlyName}}"
          NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="{{.Required}}"/>{{end}}
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">{{.OrgName}}</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">{{.OrgDisplayName}}</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">{{.OrgURL}}</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:EmailAddress>{{.ContactEmail}}</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`
	t, err := template.New("m").Parse(tpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, map[string]interface{}{
		"EntityID": sp.cfg.EntityID, "ACSURL": sp.cfg.AssertionConsumerServiceURL,
		"CertB64": certB64, "LoA": sp.cfg.RequestedLoA, "ServiceName": sp.cfg.OrgDisplayName,
		"OrgName": sp.cfg.OrgName, "OrgDisplayName": sp.cfg.OrgDisplayName,
		"OrgURL": sp.cfg.OrgURL, "ContactEmail": sp.cfg.ContactEmail, "Attrs": attrs,
	})
	return buf.Bytes(), err
}

// BuildAuthnRequestURL constructs a signed SAML 2.0 AuthnRequest URL using the
// HTTP-Redirect binding. It returns the request URL and the AuthnRequest ID, which
// the caller MUST persist so the ACS can enforce InResponseTo on the assertion.
func (sp *ServiceProvider) BuildAuthnRequestURL(relayState string) (string, string, error) {
	id := "_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	now := time.Now().UTC().Format(time.RFC3339)

	var attrsBuf strings.Builder
	for _, a := range sp.cfg.RequiredAttributes {
		req := "false"
		if mandatoryAttrs[a] {
			req = "true"
		}
		fmt.Fprintf(&attrsBuf,
			`<eidas:RequestedAttribute Name=%q NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired=%q/>`,
			a, req)
	}

	reqXML := fmt.Sprintf(`<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s" Version="2.0" IssueInstant="%s"
    ForceAuthn="false" IsPassive="false"
    ProviderName="%s" Destination="%s"
    AssertionConsumerServiceURL="%s"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Extensions>
    <eidas:SPType xmlns:eidas="http://eidas.europa.eu/saml-extensions">public</eidas:SPType>
    <eidas:RequestedAttributes xmlns:eidas="http://eidas.europa.eu/saml-extensions">%s</eidas:RequestedAttributes>
  </samlp:Extensions>
  <samlp:NameIDPolicy Format="%s" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="minimum">
    <saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`,
		id, now,
		xmlEscape(sp.cfg.OrgDisplayName), xmlEscape(sp.cfg.EidasNodeURL),
		xmlEscape(sp.cfg.AssertionConsumerServiceURL),
		xmlEscape(sp.cfg.EntityID),
		attrsBuf.String(), NameIDFormat, sp.cfg.RequestedLoA,
	)

	signed, err := signXMLRequest([]byte(reqXML), sp.cfg.PrivateKey, sp.cfg.Certificate)
	if err != nil {
		return "", "", fmt.Errorf("eidas: sign: %w", err)
	}
	encoded, err := deflateB64(signed)
	if err != nil {
		return "", "", fmt.Errorf("eidas: deflate: %w", err)
	}

	sigAlg := "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	q2sign := "SAMLRequest=" + url.QueryEscape(encoded) +
		"&RelayState=" + url.QueryEscape(relayState) +
		"&SigAlg=" + url.QueryEscape(sigAlg)

	sig, err := signQueryRSASHA256(q2sign, sp.cfg.PrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("eidas: query sign: %w", err)
	}
	params := url.Values{}
	params.Set("SAMLRequest", encoded)
	params.Set("RelayState", relayState)
	params.Set("SigAlg", sigAlg)
	params.Set("Signature", sig)
	return sp.cfg.EidasNodeURL + "?" + params.Encode(), id, nil
}

// ParseAssertion validates a base64-encoded SAML Response and returns the eIDAS identity.
func (sp *ServiceProvider) ParseAssertion(samlResponseB64, expectedRequestID string, idpCertPEM []byte) (*EidasIdentity, error) {
	raw, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return nil, fmt.Errorf("eidas: b64: %w", err)
	}
	block, _ := pem.Decode(idpCertPEM)
	if block == nil {
		return nil, fmt.Errorf("eidas: invalid IDP cert PEM")
	}
	idpCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("eidas: parse IDP cert: %w", err)
	}
	store := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idpCert}}
	vCtx := dsig.NewDefaultValidationContext(&store)

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("eidas: parse XML: %w", err)
	}
	validated, err := vCtx.Validate(doc.Root())
	if err != nil {
		return nil, fmt.Errorf("eidas: signature invalid: %w", err)
	}
	vdoc := etree.NewDocument()
	vdoc.SetRoot(validated)

	// StatusCode: a Response status is only present when the signature covers the
	// Response element. When present it MUST be Success.
	if sc := vdoc.FindElement("//StatusCode"); sc != nil {
		val := sc.SelectAttrValue("Value", "")
		if !strings.HasSuffix(val, ":Success") {
			msg := ""
			if sm := vdoc.FindElement("//StatusMessage"); sm != nil {
				msg = sm.Text()
			}
			return nil, fmt.Errorf("eidas: auth failed: %s — %s", val, msg)
		}
	}

	now := time.Now().UTC()

	// SubjectConfirmationData binds the assertion to THIS request and SP
	// (SAML Web SSO profile). Without these checks an assertion minted for another
	// SP or in response to a different request would be accepted.
	scd := vdoc.FindElement("//SubjectConfirmationData")
	if scd == nil {
		return nil, fmt.Errorf("eidas: assertion missing SubjectConfirmationData")
	}
	// InResponseTo MUST match the AuthnRequest we issued (replay/injection guard).
	if expectedRequestID != "" {
		if ir := scd.SelectAttrValue("InResponseTo", ""); ir != expectedRequestID {
			return nil, fmt.Errorf("eidas: InResponseTo mismatch")
		}
	}
	// Recipient MUST be our ACS URL.
	if rcpt := scd.SelectAttrValue("Recipient", ""); rcpt != "" && rcpt != sp.cfg.AssertionConsumerServiceURL {
		return nil, fmt.Errorf("eidas: SubjectConfirmationData Recipient mismatch")
	}
	// NotOnOrAfter on the subject confirmation MUST be in the future.
	if s := scd.SelectAttrValue("NotOnOrAfter", ""); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil && now.After(t) {
			return nil, fmt.Errorf("eidas: subject confirmation expired")
		}
	}

	// Conditions: NotBefore/NotOnOrAfter window + AudienceRestriction.
	if cond := vdoc.FindElement("//Conditions"); cond != nil {
		if s := cond.SelectAttrValue("NotOnOrAfter", ""); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil && now.After(t) {
				return nil, fmt.Errorf("eidas: assertion expired")
			}
		}
		if s := cond.SelectAttrValue("NotBefore", ""); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil && now.Before(t) {
				return nil, fmt.Errorf("eidas: assertion not yet valid")
			}
		}
	}
	// AudienceRestriction MUST name this SP — prevents cross-SP assertion reuse.
	audienceOK := false
	for _, aud := range vdoc.FindElements("//AudienceRestriction/Audience") {
		if strings.TrimSpace(aud.Text()) == sp.cfg.EntityID {
			audienceOK = true
			break
		}
	}
	if !audienceOK {
		return nil, fmt.Errorf("eidas: assertion audience does not match this service provider")
	}

	attrs := extractSAMLAttributes(vdoc)
	nameID := ""
	if el := vdoc.FindElement("//NameID"); el != nil {
		nameID = strings.TrimSpace(el.Text())
	}
	id := &EidasIdentity{
		NameID:           nameID,
		PersonIdentifier: attrs[AttrPersonIdentifier],
		FamilyName:       attrs[AttrFamilyName],
		FirstName:        attrs[AttrFirstName],
		DateOfBirth:      attrs[AttrDateOfBirth],
		BirthName:        attrs[AttrBirthName],
		PlaceOfBirth:     attrs[AttrPlaceOfBirth],
		Gender:           attrs[AttrGender],
		Address:          attrs[AttrAddress],
	}
	if el := vdoc.FindElement("//AuthnContextClassRef"); el != nil {
		id.LevelOfAssurance = strings.TrimSpace(el.Text())
	}
	if parts := strings.SplitN(id.PersonIdentifier, "/", 3); len(parts) >= 2 {
		id.CitizenCountry = strings.ToUpper(parts[0])
	}
	return id, nil
}

// EidasIdentity holds the verified attributes from an eIDAS authentication.
type EidasIdentity struct {
	NameID           string `json:"name_id"`
	PersonIdentifier string `json:"person_identifier"`
	FamilyName       string `json:"family_name"`
	FirstName        string `json:"first_name"`
	DateOfBirth      string `json:"date_of_birth"`
	BirthName        string `json:"birth_name,omitempty"`
	PlaceOfBirth     string `json:"place_of_birth,omitempty"`
	Gender           string `json:"gender,omitempty"`
	Address          string `json:"address,omitempty"`
	LevelOfAssurance string `json:"level_of_assurance"`
	CitizenCountry   string `json:"citizen_country"`
}

// SynthesiseEmail builds a stable placeholder email for eIDAS users.
func (id *EidasIdentity) SynthesiseEmail(domain string) string {
	local := strings.ReplaceAll(strings.ToLower(id.PersonIdentifier), "/", "_")
	if local == "" {
		local = strings.ToLower(id.NameID)
	}
	return local + "@eidas." + domain
}

// ── Private helpers ───────────────────────────────────────────────────────────

func eidasFriendlyName(uri string) string {
	parts := strings.Split(uri, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return uri
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func extractSAMLAttributes(doc *etree.Document) map[string]string {
	out := make(map[string]string)
	for _, el := range doc.FindElements("//Attribute") {
		name := el.SelectAttrValue("Name", "")
		if name == "" {
			continue
		}
		if val := el.FindElement("AttributeValue"); val != nil {
			if children := val.ChildElements(); len(children) > 0 {
				var parts []string
				for _, c := range children {
					if t := strings.TrimSpace(c.Text()); t != "" {
						parts = append(parts, t)
					}
				}
				if len(parts) > 0 {
					out[name] = strings.Join(parts, ", ")
					continue
				}
			}
			out[name] = strings.TrimSpace(val.Text())
		}
	}
	return out
}

func signXMLRequest(raw []byte, key crypto.Signer, cert *x509.Certificate) ([]byte, error) {
	tlsCert := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tlsCert))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.Hash = crypto.SHA256
	ctx.IdAttribute = "ID"

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, err
	}
	root := doc.Root()
	if root.SelectAttrValue("ID", "") == "" {
		return nil, fmt.Errorf("signXMLRequest: element missing ID attribute")
	}
	signed, err := ctx.SignEnveloped(root)
	if err != nil {
		return nil, err
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	return out.WriteToBytes()
}

func deflateB64(src []byte) (string, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(src); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func signQueryRSASHA256(query string, key crypto.Signer) (string, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("eidas: only RSA private keys supported")
	}
	h := sha256.Sum256([]byte(query))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
