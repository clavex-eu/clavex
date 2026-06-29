// Package spid implements a SPID (Sistema Pubblico di Identità Digitale) Service Provider
// compliant with the Italian AgID technical rules (SPID-AVVISO-n29 v3, LL.GG. OpenID Connect).
//
// Protocol: SAML 2.0 with SPID-specific extensions and attribute sets.
// Signing:  RSA-SHA256 (XML-DSig enveloped) using goxmldsig (etree-based).
//
// # Endpoints (SPID)
//
//	Demo / test (no approval needed):
//	  https://demo.spid.gov.it  — SpidSAML2 compliant test IdP
//	AgID validator (SP metadata check):
//	  https://validator.spid.gov.it
//
// # Production accreditation
//
// Production use requires registration as a SPID Service Provider with AgID.
// Only legal entities (companies, public administrations) may apply.
//
//  1. Register at https://spid.gov.it/cos-e-spid/come-diventare-fornitore-di-servizi/
//  2. Prepare SP metadata XML and submit to AgID via the accreditation portal.
//  3. AgID publishes the SP in the SPID registry (https://registry.spid.gov.it).
//  4. Each IdP downloads the registry and validates AuthnRequest signatures against
//     the SP certificate published in the metadata — no direct peer exchange needed.
//  5. Estimated timeline: 4–8 weeks from submission to approval.
//
// For SaaS / multi-tenant deployments (SP aggregator pattern) a single accreditation
// covers the whole instance. Tenants share the EntityID and signing certificate;
// only authentication preferences (LoA, attribute set) vary per tenant.
//
// # Development and testing
//
// Use the spid-testenv2 Docker image for local end-to-end tests:
//
//	docker run -p 8088:8088 italia/spid-testenv2
//
// No AgID approval is required for demo.spid.gov.it or spid-testenv2.
package spid

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/beevik/etree"
	crewsaml "github.com/crewjam/saml"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
)

// AuthnContext URIs for SPID levels.
const (
	SpidL1 = "https://www.spid.gov.it/SpidL1"
	SpidL2 = "https://www.spid.gov.it/SpidL2"
	SpidL3 = "https://www.spid.gov.it/SpidL3"
)

// authnLevelURI maps integer level to SPID AuthnContextClassRef URI.
func authnLevelURI(level int) string {
	switch level {
	case 1:
		return SpidL1
	case 3:
		return SpidL3
	default:
		return SpidL2
	}
}

// SPConfig holds everything needed to act as a SPID SP for one tenant org.
type SPConfig struct {
	EntityID       string
	OrgName        string
	OrgDisplayName string
	OrgURL         string
	OrgLocality    string // city/locality for SubjectDN (L field), e.g. "Roma"
	ContactEmail   string
	ContactPhone   string
	VATNumber      string // Partita IVA (private entities)
	IPACode        string // Codice IPA (public entities / PA)
	EntityType     string // "private" | "public"
	AuthnLevel     int    // 1, 2, or 3
	AttributeSet   []string
	// ACSURL is the absolute HTTP-POST callback URL, e.g. https://app.example.com/{slug}/spid/callback
	ACSURL      string
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// ServiceProvider performs SPID SAML SP operations for one tenant.
type ServiceProvider struct {
	cfg *SPConfig
}

// New builds a ServiceProvider. If cfg.Certificate/PrivateKey are nil it returns an error.
func New(cfg *SPConfig) (*ServiceProvider, error) {
	if cfg.Certificate == nil || cfg.PrivateKey == nil {
		return nil, fmt.Errorf("spid: SP certificate and private key are required")
	}
	return &ServiceProvider{cfg: cfg}, nil
}

// ── Certificate helpers ───────────────────────────────────────────────────────

// CertOptions holds the parameters for generating a SPID-compliant SP signing certificate.
// All fields that affect SubjectDN are required by SPID/eIDAS AgID rules.
type CertOptions struct {
	// OrgName is the organization name (O field, 2.5.4.10). Required.
	OrgName string
	// OrgLocality is the city/locality (L field, 2.5.4.7). Required.
	OrgLocality string
	// OrgIdentifier is the organizationIdentifier (2.5.4.97).
	// For private SP: "VATIT-<VATNumber>"; for public SP: "PA:IT-<IPACode>".
	OrgIdentifier string
	// EIDASIdentifier is the eIDAS unique identifier (2.5.4.83).
	// Required for ficep-eidas-sp profile. Same format as OrgIdentifier.
	EIDASIdentifier string
	// Country defaults to "IT" if empty.
	Country string
}

// ASN.1 OIDs for SPID/eIDAS certificate SubjectDN attributes.
var (
	oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	oidEIDASIdentifier        = asn1.ObjectIdentifier{2, 5, 4, 83}
	oidBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidCertificatePolicies    = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidSPIDPolicyBase         = asn1.ObjectIdentifier{1, 3, 76, 16, 6}       // AgID SPID base policy OID (check 84)
	oidSPIDPolicySP           = asn1.ObjectIdentifier{1, 3, 76, 16, 4, 2, 1} // AgID SPID SP policy OID for private SP (check 130)
)

// certPoliciesExtValue encodes the CertificatePolicies extension value containing
// both AgID SPID policy OIDs required by AVVISO n.29: 1.3.76.16.6 and 1.3.76.16.4.2.1.
func certPoliciesExtValue() ([]byte, error) {
	type policyInfo struct {
		PolicyID asn1.ObjectIdentifier
	}
	return asn1.Marshal([]policyInfo{
		{PolicyID: oidSPIDPolicyBase},
		{PolicyID: oidSPIDPolicySP},
	})
}

// GenerateCert creates a self-signed RSA-2048 certificate compliant with SPID SP signing
// requirements (AgID SPID-AVVISO-n29 / eIDAS). The generated certificate includes:
//   - SubjectDN with CN, O (organizationName), C (countryName), L (localityName),
//     OID 2.5.4.97 (organizationIdentifier) and optionally OID 2.5.4.83 (eIDASIdentifier)
//   - KeyUsage: digitalSignature + contentCommitment (nonRepudiation)
//   - basicConstraints: CA=FALSE (not critical, as required by SPID)
//   - certificatePolicies: 1.3.76.16.6 + 1.3.76.16.4.2.1 (AgID SPID policies)
func GenerateCert(opts CertOptions) (*rsa.PrivateKey, *x509.Certificate, string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("spid: generate key: %w", err)
	}

	country := opts.Country
	if country == "" {
		country = "IT"
	}

	// Build SubjectDN extra names for non-standard OIDs.
	extraNames := []pkix.AttributeTypeAndValue{}
	if opts.OrgIdentifier != "" {
		extraNames = append(extraNames, pkix.AttributeTypeAndValue{
			Type:  oidOrganizationIdentifier,
			Value: opts.OrgIdentifier,
		})
	}
	if opts.EIDASIdentifier != "" {
		extraNames = append(extraNames, pkix.AttributeTypeAndValue{
			Type:  oidEIDASIdentifier,
			Value: opts.EIDASIdentifier,
		})
	}

	subject := pkix.Name{
		CommonName:   "SPID SP Signing Certificate",
		Organization: []string{opts.OrgName},
		Country:      []string{country},
		Locality:     []string{opts.OrgLocality},
		ExtraNames:   extraNames,
	}

	// Encode certificatePolicies extension value.
	cpVal, err := certPoliciesExtValue()
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("spid: encode cert policies: %w", err)
	}

	// basicConstraints CA=FALSE — must be present but NOT critical (AgID AVVISO n.29 §4).
	// Go's x509 package always marks BasicConstraints as critical when BasicConstraintsValid=true,
	// so we encode it manually as a non-critical ExtraExtension.
	type basicConstraintsVal struct {
		IsCA bool `asn1:"optional"`
	}
	bcVal, err := asn1.Marshal(basicConstraintsVal{}) // CA=FALSE → empty SEQUENCE (0x30 0x00)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("spid: encode basic constraints: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(20 * 365 * 24 * time.Hour),
		// AgID rules: digitalSignature + contentCommitment (nonRepudiation) MUST be set.
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidBasicConstraints,
				Critical: false,
				Value:    bcVal,
			},
			{
				Id:    oidCertificatePolicies,
				Value: cpVal,
			},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("spid: create cert: %w", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, cert, string(certPEM), string(keyPEM), nil
}

// ParseCertAndKey parses PEM-encoded certificate and private key.
func ParseCertAndKey(certPEM, keyPEM string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, nil, fmt.Errorf("spid: invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("spid: parse cert: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("spid: invalid key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("spid: parse key: %w", err)
	}
	return cert, key, nil
}

// ── AuthnRequest generation ───────────────────────────────────────────────────

// authnRequestTmpl is an XML template for a SPID-compliant AuthnRequest.
// All SPID-required attributes and child elements are included.
var authnRequestTmpl = template.Must(template.New("authnreq").Parse(`<?xml version="1.0"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{{.ID}}"
    Version="2.0"
    IssueInstant="{{.IssueInstant}}"
    Destination="{{.Destination}}"
    ForceAuthn="true"
    AssertionConsumerServiceIndex="0"
    AttributeConsumingServiceIndex="0">
  <saml:Issuer
      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
      NameQualifier="{{.EntityID}}">{{.EntityID}}</saml:Issuer>
  <samlp:NameIDPolicy
      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
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
	AuthnContextClassRef string
}

// MakeAuthnRequest generates a signed SPID AuthnRequest for the given IdP SSO URL.
// nonce is the per-request CSP nonce used to allow the auto-submit script.
// Returns the request ID (to be stored in session) and the HTML auto-submit form bytes.
func (sp *ServiceProvider) MakeAuthnRequest(ctx context.Context, idpSSOURL, relayState, nonce string) (requestID string, htmlForm []byte, err error) {
	return sp.makeAuthnRequest(ctx, idpSSOURL, relayState, nonce, sp.cfg.AuthnLevel)
}

// MakeAuthnRequestWithLevel is like MakeAuthnRequest but overrides the SP's configured
// AuthnLevel with an explicit level. Used for in-session SPID level upgrades triggered
// by the flow engine's check_verified step.
func (sp *ServiceProvider) MakeAuthnRequestWithLevel(ctx context.Context, idpSSOURL, relayState, nonce string, level int) (requestID string, htmlForm []byte, err error) {
	return sp.makeAuthnRequest(ctx, idpSSOURL, relayState, nonce, level)
}

func (sp *ServiceProvider) makeAuthnRequest(ctx context.Context, idpSSOURL, relayState, nonce string, authnLevel int) (requestID string, htmlForm []byte, err error) {
	reqID := "_" + strings.ReplaceAll(uuid.New().String(), "-", "")

	var xmlBuf bytes.Buffer
	if err = authnRequestTmpl.Execute(&xmlBuf, authnRequestData{
		ID:                   reqID,
		IssueInstant:         time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Destination:          idpSSOURL,
		EntityID:             sp.cfg.EntityID,
		AuthnContextClassRef: authnLevelURI(authnLevel),
	}); err != nil {
		return "", nil, fmt.Errorf("spid: render authn request: %w", err)
	}

	signed, err := sp.signXML(xmlBuf.Bytes(), reqID)
	if err != nil {
		return "", nil, fmt.Errorf("spid: sign authn request: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(signed)
	form, err := renderPostForm(idpSSOURL, encoded, relayState, nonce)
	if err != nil {
		return "", nil, err
	}
	return reqID, form, nil
}

// signXML signs the XML document using XML-DSig (enveloped signature) with the SP key.
func (sp *ServiceProvider) signXML(xmlBytes []byte, refID string) ([]byte, error) {
	// Parse XML into etree
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("spid: parse xml: %w", err)
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

	// Remove the leading "_" from the reference ID because xmldsig uses the bare ID
	sigCtx.IdAttribute = "ID"

	signed, err := sigCtx.SignEnveloped(doc.Root())
	if err != nil {
		return nil, fmt.Errorf("spid: xmldsig sign: %w", err)
	}

	// goxmldsig appends ds:Signature at the end via direct slice manipulation, bypassing
	// etree's AddChild (leaving Parent nil). etree.RemoveChild silently no-ops because
	// t.Parent() != e. Move Signature to the correct position via slice ops instead.
	//
	// SAML 2.0 schema positions:
	//   EntityDescriptor: Signature is first child.
	//   AuthnRequest (RequestAbstractType): Signature is second child, after saml:Issuer.
	if children := signed.Child; len(children) > 0 {
		if sig, ok := children[len(children)-1].(*etree.Element); ok && sig.Tag == "Signature" {
			rest := children[:len(children)-1]
			if signed.Tag == "AuthnRequest" {
				// SAML 2.0 schema: Signature must follow saml:Issuer.
				// rest may include text/whitespace nodes, so find the Issuer by tag.
				insertAt := 0
				for i, tok := range rest {
					if el, ok2 := tok.(*etree.Element); ok2 && el.Tag == "Issuer" {
						insertAt = i + 1
						break
					}
				}
				inserted := make([]etree.Token, 0, len(children))
				inserted = append(inserted, rest[:insertAt]...)
				inserted = append(inserted, sig)
				inserted = append(inserted, rest[insertAt:]...)
				signed.Child = inserted
			} else {
				signed.Child = append([]etree.Token{sig}, rest...)
			}
		}
	}

	outDoc := etree.NewDocument()
	outDoc.SetRoot(signed)
	return outDoc.WriteToBytes()
}

// renderPostForm renders the self-submitting HTML POST form for SAML HTTP-POST binding.
// nonce is the per-request CSP nonce; the auto-submit script is tagged with it so that
// a strict-dynamic CSP (script-src 'nonce-...' 'strict-dynamic') does not block it.
var postFormTmpl = template.Must(template.New("post").Parse(`<!DOCTYPE html>
<html><body>
<form method="POST" action="{{.Action}}">
  <input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}"/>
  {{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}"/>{{end}}
  <noscript><button type="submit">Continue to identity provider</button></noscript>
</form>
<script nonce="{{.Nonce}}">document.forms[0].submit()</script>
</body></html>`))

type postFormData struct {
	Action      string
	SAMLRequest string
	RelayState  string
	Nonce       string
}

func renderPostForm(idpURL, encodedRequest, relayState, nonce string) ([]byte, error) {
	var buf bytes.Buffer
	if err := postFormTmpl.Execute(&buf, postFormData{
		Action:      idpURL,
		SAMLRequest: encodedRequest,
		RelayState:  relayState,
		Nonce:       nonce,
	}); err != nil {
		return nil, fmt.Errorf("spid: render post form: %w", err)
	}
	return buf.Bytes(), nil
}

// ── SAMLResponse parsing ──────────────────────────────────────────────────────

// ParseResponse validates and extracts a SPIDIdentity from a raw SAMLResponse value
// (base64-encoded XML as received in the POST parameter).
func (sp *ServiceProvider) ParseResponse(samlResponseB64, expectedRequestID string, idpCert *x509.Certificate) (*SPIDIdentity, error) {
	raw, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return nil, fmt.Errorf("spid: decode saml response: %w", err)
	}

	// Use crewjam/saml's EntityDescriptor parsing to leverage its assertion validation.
	// We build a minimal SP and parse the response against it.
	spURL, _ := url.Parse(sp.cfg.ACSURL)
	entityURL, _ := url.Parse(sp.cfg.EntityID)

	var idpMeta crewsaml.EntityDescriptor
	// Parse the assertion XML to extract issuer entity ID to look up the right IdP cert
	var respXML struct {
		XMLName xml.Name `xml:"Response"`
		Issuer  struct {
			Value string `xml:",chardata"`
		} `xml:"Issuer"`
	}
	_ = xml.Unmarshal(raw, &respXML)

	// Build IdP metadata with the known signing cert
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

	// Validate the response (signature, conditions, audience, etc.)
	// crewjam/saml v0.5+ requires the current ACS URL for response validation.
	assertion, err := csamlSP.ParseXMLResponse(raw, []string{expectedRequestID}, *spURL)
	if err != nil {
		return nil, fmt.Errorf("spid: parse assertion: %w", err)
	}

	identity := extractSPIDAttributes(assertion)
	return identity, nil
}

// buildIDPMetadata creates a minimal crewjam EntityDescriptor from an IdP entity ID + cert.
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

// ── Metadata generation ───────────────────────────────────────────────────────

// ParseIDPMetadataURL fetches and parses an IdP's SAML metadata from its URL.
func ParseIDPMetadataURL(ctx context.Context, metadataURL string) (*crewsaml.EntityDescriptor, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("spid: build metadata request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("spid: fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	var metaXML bytes.Buffer
	if _, err := metaXML.ReadFrom(resp.Body); err != nil {
		return nil, "", fmt.Errorf("spid: read metadata body: %w", err)
	}
	xmlStr := metaXML.String()

	var ed crewsaml.EntityDescriptor
	if err := xml.NewDecoder(strings.NewReader(xmlStr)).Decode(&ed); err != nil {
		return nil, "", fmt.Errorf("spid: parse metadata xml: %w", err)
	}
	return &ed, xmlStr, nil
}

// ExtractIDPSSOURL returns the HTTP-POST SSO URL from an EntityDescriptor.
func ExtractIDPSSOURL(meta *crewsaml.EntityDescriptor) (string, error) {
	for _, desc := range meta.IDPSSODescriptors {
		for _, sso := range desc.SingleSignOnServices {
			if sso.Binding == crewsaml.HTTPPostBinding {
				return sso.Location, nil
			}
		}
		// Fallback to first
		if len(desc.SingleSignOnServices) > 0 {
			return desc.SingleSignOnServices[0].Location, nil
		}
	}
	return "", fmt.Errorf("spid: no SSO URL found in IdP metadata")
}

// ExtractIDPSigningCert returns the first signing certificate from an EntityDescriptor.
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
	return nil, fmt.Errorf("spid: no signing certificate found in IdP metadata")
}
