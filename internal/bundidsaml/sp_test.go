package bundidsaml

import (
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"

	crewsaml "github.com/crewjam/saml"
)

// ── loaURI ────────────────────────────────────────────────────────────────────

func TestLoaURI(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"low", LoALow},
		{"high", LoAHigh},
		{"substantial", LoASubstantial},
		{"", LoASubstantial},        // empty → default
		{"unknown", LoASubstantial}, // unrecognised → default
		{"LOW", LoASubstantial},     // case-sensitive → default
	}
	for _, tc := range tests {
		got := loaURI(tc.input)
		if got != tc.want {
			t.Errorf("loaURI(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ── GetEndpoints ─────────────────────────────────────────────────────────────

func TestGetEndpoints_Production(t *testing.T) {
	ep := GetEndpoints("production")
	if !strings.Contains(ep.MetadataURL, "id.bund.de") {
		t.Errorf("production metadata URL should contain id.bund.de, got %s", ep.MetadataURL)
	}
	if strings.Contains(ep.MetadataURL, "int.") {
		t.Errorf("production metadata URL should not contain int., got %s", ep.MetadataURL)
	}
}

func TestGetEndpoints_Integration(t *testing.T) {
	ep := GetEndpoints("integration")
	if !strings.Contains(ep.MetadataURL, "int.id.bund.de") {
		t.Errorf("integration metadata URL should contain int.id.bund.de, got %s", ep.MetadataURL)
	}
}

func TestGetEndpoints_Default(t *testing.T) {
	// Any value other than "production" should return integration.
	ep := GetEndpoints("staging")
	if !strings.Contains(ep.MetadataURL, "int.") {
		t.Errorf("non-production env should return integration URL, got %s", ep.MetadataURL)
	}
}

// ── extractBundIDAttributes ───────────────────────────────────────────────────

func makeAttr(name, value string) crewsaml.Attribute {
	return crewsaml.Attribute{
		Name: name,
		Values: []crewsaml.AttributeValue{
			{Value: value},
		},
	}
}

func makeAssertion(attrs []crewsaml.Attribute, nameIDValue, loaClassRef string) *crewsaml.Assertion {
	a := &crewsaml.Assertion{}
	if nameIDValue != "" {
		a.Subject = &crewsaml.Subject{
			NameID: &crewsaml.NameID{Value: nameIDValue},
		}
	}
	if len(attrs) > 0 {
		a.AttributeStatements = []crewsaml.AttributeStatement{
			{Attributes: attrs},
		}
	}
	if loaClassRef != "" {
		classRef := &crewsaml.AuthnContextClassRef{Value: loaClassRef}
		a.AuthnStatements = []crewsaml.AuthnStatement{
			{
				AuthnContext: crewsaml.AuthnContext{
					AuthnContextClassRef: classRef,
				},
			},
		}
	}
	return a
}

func TestExtractBundIDAttributes_Full(t *testing.T) {
	attrs := []crewsaml.Attribute{
		makeAttr(AttrPersonIdentifier, "DE/DE/ABC123456789"),
		makeAttr(AttrCurrentGivenName, "Max"),
		makeAttr(AttrCurrentFamilyName, "Mustermann"),
		makeAttr(AttrDateOfBirth, "1985-06-15"),
		makeAttr(AttrPlaceOfBirth, "Berlin"),
		makeAttr(AttrEmailAddress, "max@example.de"),
	}
	a := makeAssertion(attrs, "DE/DE/ABC123456789", LoAHigh)

	id := extractBundIDAttributes(a)

	if id.Sub != "DE/DE/ABC123456789" {
		t.Errorf("Sub: got %q, want %q", id.Sub, "DE/DE/ABC123456789")
	}
	if id.GivenName != "Max" {
		t.Errorf("GivenName: got %q", id.GivenName)
	}
	if id.FamilyName != "Mustermann" {
		t.Errorf("FamilyName: got %q", id.FamilyName)
	}
	if id.DateOfBirth != "1985-06-15" {
		t.Errorf("DateOfBirth: got %q", id.DateOfBirth)
	}
	if id.PlaceOfBirth != "Berlin" {
		t.Errorf("PlaceOfBirth: got %q", id.PlaceOfBirth)
	}
	if id.Email != "max@example.de" {
		t.Errorf("Email: got %q", id.Email)
	}
	if id.EmailSynthetic {
		t.Error("EmailSynthetic should be false when email attribute present")
	}
	if id.LoA != LoAHigh {
		t.Errorf("LoA: got %q, want %q", id.LoA, LoAHigh)
	}
}

func TestExtractBundIDAttributes_LoALow_NoPersonalData(t *testing.T) {
	// LoA Low: only PersonIdentifier, no name / DOB.
	attrs := []crewsaml.Attribute{
		makeAttr(AttrPersonIdentifier, "DE/DE/ANONYMOUS001"),
	}
	a := makeAssertion(attrs, "DE/DE/ANONYMOUS001", LoALow)

	id := extractBundIDAttributes(a)

	if id.Sub != "DE/DE/ANONYMOUS001" {
		t.Errorf("Sub: got %q", id.Sub)
	}
	if id.GivenName != "" || id.FamilyName != "" || id.DateOfBirth != "" {
		t.Errorf("name fields should be empty at LoA Low, got: given=%q family=%q dob=%q",
			id.GivenName, id.FamilyName, id.DateOfBirth)
	}
	if id.LoA != LoALow {
		t.Errorf("LoA: got %q", id.LoA)
	}
	// Email absent → synthetic flag set.
	if !id.EmailSynthetic {
		t.Error("EmailSynthetic should be true when no email attribute")
	}
}

func TestExtractBundIDAttributes_PersonIdentifierOverridesNameID(t *testing.T) {
	// PersonIdentifier attribute must override NameID.
	attrs := []crewsaml.Attribute{
		makeAttr(AttrPersonIdentifier, "DE/DE/ATTR_VALUE"),
	}
	a := makeAssertion(attrs, "DE/DE/NAMEID_VALUE", LoASubstantial)

	id := extractBundIDAttributes(a)
	if id.Sub != "DE/DE/ATTR_VALUE" {
		t.Errorf("PersonIdentifier should override NameID, got %q", id.Sub)
	}
}

func TestExtractBundIDAttributes_NoAttributeStatements(t *testing.T) {
	// Only NameID, no attribute statements.
	a := makeAssertion(nil, "DE/DE/NAMEID_ONLY", "")

	id := extractBundIDAttributes(a)
	if id.Sub != "DE/DE/NAMEID_ONLY" {
		t.Errorf("Sub from NameID: got %q", id.Sub)
	}
	if id.LoA != "" {
		t.Errorf("LoA should be empty when no authn statement, got %q", id.LoA)
	}
}

func TestExtractBundIDAttributes_NilSubject(t *testing.T) {
	// Nil subject — should not panic and Sub should be empty.
	a := &crewsaml.Assertion{}
	id := extractBundIDAttributes(a)
	if id == nil {
		t.Fatal("extractBundIDAttributes returned nil")
	}
	if id.Sub != "" {
		t.Errorf("Sub should be empty for nil subject, got %q", id.Sub)
	}
}

// ── BundIDIdentity.EmailOrSynth ───────────────────────────────────────────────

func TestEmailOrSynth_WithRealEmail(t *testing.T) {
	id := &BundIDIdentity{Email: "user@example.de"}
	if got := id.EmailOrSynth(); got != "user@example.de" {
		t.Errorf("got %q, want real email", got)
	}
}

func TestEmailOrSynth_Synthetic(t *testing.T) {
	id := &BundIDIdentity{Sub: "DE/DE/ABCDEF123456"}
	synth := id.EmailOrSynth()
	if !strings.HasSuffix(synth, "@bundid.internal") {
		t.Errorf("synthetic email should end with @bundid.internal, got %q", synth)
	}
	// Must use the last component of Sub, lowercased.
	if !strings.HasPrefix(synth, "abcdef123456@") {
		t.Errorf("synthetic email should be derived from last Sub component, got %q", synth)
	}
}

func TestEmailOrSynth_Deterministic(t *testing.T) {
	id := &BundIDIdentity{Sub: "DE/DE/XYZ999"}
	e1 := id.EmailOrSynth()
	e2 := id.EmailOrSynth()
	if e1 != e2 {
		t.Errorf("EmailOrSynth should be deterministic: %q != %q", e1, e2)
	}
}

// ── buildIDPMetadata ──────────────────────────────────────────────────────────

func TestBuildIDPMetadata(t *testing.T) {
	// Generate a test cert to pass to buildIDPMetadata.
	_, cert, _, _, err := GenerateCert()
	if err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}

	entityID := "https://int.id.bund.de/idp/saml"
	meta := buildIDPMetadata(entityID, cert)

	if meta.EntityID != entityID {
		t.Errorf("EntityID: got %q, want %q", meta.EntityID, entityID)
	}
	if len(meta.IDPSSODescriptors) == 0 {
		t.Fatal("IDPSSODescriptors should not be empty")
	}
	desc := meta.IDPSSODescriptors[0]
	kds := desc.KeyDescriptors
	if len(kds) == 0 {
		t.Fatal("KeyDescriptors should not be empty")
	}
	if kds[0].Use != "signing" {
		t.Errorf("KeyDescriptor.Use: got %q, want %q", kds[0].Use, "signing")
	}
	certs := kds[0].KeyInfo.X509Data.X509Certificates
	if len(certs) == 0 {
		t.Fatal("no X509Certificate in metadata")
	}
	// The cert data must be valid base64 and round-trip correctly.
	der, err := base64.StdEncoding.DecodeString(certs[0].Data)
	if err != nil {
		t.Fatalf("cert data is not valid base64: %v", err)
	}
	if string(der) != string(cert.Raw) {
		t.Error("cert DER in metadata does not match original")
	}
}

// ── GenerateCert + ParseCertAndKey ───────────────────────────────────────────

func TestGenerateCert(t *testing.T) {
	key, cert, certPEM, keyPEM, err := GenerateCert()
	if err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}
	if key == nil || cert == nil {
		t.Fatal("GenerateCert returned nil key or cert")
	}
	if !strings.Contains(certPEM, "-----BEGIN CERTIFICATE-----") {
		t.Error("certPEM missing PEM header")
	}
	if !strings.Contains(keyPEM, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("keyPEM missing PEM header")
	}

	// Round-trip: parse the PEM back.
	parsedCert, parsedKey, err := ParseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ParseCertAndKey: %v", err)
	}
	if !parsedCert.Equal(cert) {
		t.Error("parsed cert does not equal original")
	}
	if parsedKey.N.Cmp(key.N) != 0 {
		t.Error("parsed key modulus does not match original")
	}
}

// ── ServiceProvider.New ───────────────────────────────────────────────────────

func TestNew_RequiresCertAndKey(t *testing.T) {
	_, err := New(&SPConfig{})
	if err == nil {
		t.Error("New with no cert/key should return error")
	}
}

func TestNew_DefaultsMinLoA(t *testing.T) {
	key, cert, _, _, err := GenerateCert()
	if err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}

	sp, err := New(&SPConfig{
		Certificate: cert,
		PrivateKey:  key,
		EntityID:    "https://example.de",
		ACSURL:      "https://example.de/callback",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// MinLoA should default to "substantial"
	if sp.cfg.MinLoA != "substantial" {
		t.Errorf("default MinLoA: got %q, want %q", sp.cfg.MinLoA, "substantial")
	}
}

// ── MetadataXML ───────────────────────────────────────────────────────────────

func TestMetadataXML_ValidXML(t *testing.T) {
	key, cert, _, _, err := GenerateCert()
	if err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}
	sp, err := New(&SPConfig{
		EntityID:       "https://example.de/saml",
		ACSURL:         "https://example.de/bundidsaml/callback",
		OrgName:        "Testbehörde",
		OrgDisplayName: "Testbehörde (DE)",
		OrgURL:         "https://example.de",
		ContactEmail:   "admin@example.de",
		Certificate:    cert,
		PrivateKey:     key,
		AttributeSet:   AttributeSetBase,
		MinLoA:         "substantial",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	xmlBytes, err := sp.MetadataXML()
	if err != nil {
		t.Fatalf("MetadataXML: %v", err)
	}
	if len(xmlBytes) == 0 {
		t.Fatal("MetadataXML returned empty bytes")
	}

	// Must be well-formed XML.
	var root struct{ XMLName xml.Name }
	if err := xml.Unmarshal(xmlBytes, &root); err != nil {
		t.Errorf("MetadataXML produced invalid XML: %v", err)
	}

	xmlStr := string(xmlBytes)
	if !strings.Contains(xmlStr, "https://example.de/saml") {
		t.Error("EntityID missing from metadata")
	}
	if !strings.Contains(xmlStr, "https://example.de/bundidsaml/callback") {
		t.Error("ACSURL missing from metadata")
	}
	if !strings.Contains(xmlStr, AttrPersonIdentifier) {
		t.Error("PersonIdentifier attribute missing from metadata")
	}
}

func TestMetadataXML_AttributeSetMinimum(t *testing.T) {
	key, cert, _, _, err := GenerateCert()
	if err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}
	sp, err := New(&SPConfig{
		EntityID:       "https://example.de/saml",
		ACSURL:         "https://example.de/callback",
		OrgName:        "X",
		OrgDisplayName: "X",
		OrgURL:         "https://example.de",
		ContactEmail:   "a@b.de",
		Certificate:    cert,
		PrivateKey:     key,
		AttributeSet:   AttributeSetMinimum,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	xmlBytes, err := sp.MetadataXML()
	if err != nil {
		t.Fatalf("MetadataXML: %v", err)
	}
	xmlStr := string(xmlBytes)
	// Minimum set should only contain PersonIdentifier.
	if !strings.Contains(xmlStr, AttrPersonIdentifier) {
		t.Error("PersonIdentifier missing")
	}
	if strings.Contains(xmlStr, AttrCurrentFamilyName) {
		t.Error("FamilyName should not be in minimum attribute set")
	}
}
