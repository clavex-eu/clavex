package federation

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// testKey generates a throwaway RSA-2048 key. Cached for speed.
var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

const testKID = "test-kid-1"

// buildAndParse is a helper that calls Build and then parses + verifies the JWT.
func buildAndParse(t *testing.T, cfg Config, issuer string) *EntityConfiguration {
	t.Helper()
	raw, err := Build(cfg, issuer, testKey, testKID, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Verify the JWS signature using the public key.
	pubSet := jwk.NewSet()
	pubJWK, _ := jwk.FromRaw(&testKey.PublicKey)
	_ = pubJWK.Set(jwk.KeyIDKey, testKID)
	_ = pubJWK.Set(jwk.AlgorithmKey, string(jwa.RS256))
	if err := pubSet.AddKey(pubJWK); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	payload, err := jws.Verify(raw, jws.WithKeySet(pubSet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("JWS verification failed: %v", err)
	}

	var ec EntityConfiguration
	if err := json.Unmarshal(payload, &ec); err != nil {
		t.Fatalf("unmarshal EC: %v", err)
	}
	return &ec
}

// ── Build: basic structure ────────────────────────────────────────────────────

func TestBuild_SignatureVerifiable(t *testing.T) {
	cfg := Config{OrganizationName: "Test Org"}
	buildAndParse(t, cfg, "https://idp.example.com/acme")
}

func TestBuild_IssuerAndSubjectEqual(t *testing.T) {
	issuer := "https://idp.example.com/acme"
	ec := buildAndParse(t, Config{}, issuer)
	if ec.Issuer != issuer {
		t.Errorf("iss: want %q, got %q", issuer, ec.Issuer)
	}
	if ec.Subject != issuer {
		t.Errorf("sub: want %q, got %q", issuer, ec.Subject)
	}
}

func TestBuild_EntityIDOverridesIssuer(t *testing.T) {
	entityID := "https://federation.example.com/idp"
	issuer := "https://idp.example.com/acme"
	cfg := Config{EntityID: entityID}
	ec := buildAndParse(t, cfg, issuer)
	if ec.Issuer != entityID {
		t.Errorf("iss: want %q, got %q", entityID, ec.Issuer)
	}
	if ec.Subject != entityID {
		t.Errorf("sub: want %q, got %q", entityID, ec.Subject)
	}
}

func TestBuild_DefaultLifetime(t *testing.T) {
	before := time.Now().Unix()
	ec := buildAndParse(t, Config{}, "https://idp.example.com/x")
	after := time.Now().Unix()

	if ec.IssuedAt < before || ec.IssuedAt > after {
		t.Errorf("iat=%d out of range [%d,%d]", ec.IssuedAt, before, after)
	}
	expectedExpiry := ec.IssuedAt + int64(DefaultLifetime.Seconds())
	// Allow ±2 s tolerance for test execution time.
	if diff := ec.ExpiresAt - expectedExpiry; diff < -2 || diff > 2 {
		t.Errorf("exp=%d, want ~%d (diff=%d)", ec.ExpiresAt, expectedExpiry, diff)
	}
}

func TestBuild_CustomLifetime(t *testing.T) {
	lifetime := 6 * time.Hour
	ec := buildAndParse(t, Config{Lifetime: lifetime}, "https://idp.example.com/x")
	expected := ec.IssuedAt + int64(lifetime.Seconds())
	if diff := ec.ExpiresAt - expected; diff < -2 || diff > 2 {
		t.Errorf("exp=%d, want ~%d (diff=%d)", ec.ExpiresAt, expected, diff)
	}
}

// ── Build: JWKS ───────────────────────────────────────────────────────────────

func TestBuild_JWKSContainsPublicKeyOnly(t *testing.T) {
	ec := buildAndParse(t, Config{}, "https://idp.example.com/x")
	if len(ec.JWKS) == 0 {
		t.Fatal("JWKS is empty")
	}
	var jwksObj map[string]any
	if err := json.Unmarshal(ec.JWKS, &jwksObj); err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}
	keys, _ := jwksObj["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("JWKS.keys is empty")
	}
	k := keys[0].(map[string]any)
	// Must be RSA public key — no "d" (private exponent).
	if _, hasD := k["d"]; hasD {
		t.Error("JWKS must not expose private key component 'd'")
	}
	if k["kid"] != testKID {
		t.Errorf("JWKS kid: want %q, got %v", testKID, k["kid"])
	}
	if k["use"] != "sig" {
		t.Errorf("JWKS use: want sig, got %v", k["use"])
	}
	if k["alg"] != "RS256" {
		t.Errorf("JWKS alg: want RS256, got %v", k["alg"])
	}
}

// ── Build: openid_provider metadata ──────────────────────────────────────────

func TestBuild_OPMetadataEndpoints(t *testing.T) {
	issuer := "https://idp.example.com/myorg"
	ec := buildAndParse(t, Config{}, issuer)
	op := ec.Metadata.OpenIDProvider
	if op == nil {
		t.Fatal("openid_provider metadata is nil")
	}
	checks := map[string]string{
		"issuer":                 op.Issuer,
		"authorization_endpoint": op.AuthorizationEndpoint,
		"token_endpoint":         op.TokenEndpoint,
		"userinfo_endpoint":      op.UserinfoEndpoint,
		"jwks_uri":               op.JWKSURI,
		"federation_reg_endpoint": op.FederationRegistrationEndpoint,
	}
	for name, got := range checks {
		if !strings.HasPrefix(got, issuer) {
			t.Errorf("%s: want prefix %q, got %q", name, issuer, got)
		}
	}
}

func TestBuild_OPMetadata_ClientRegistrationTypes(t *testing.T) {
	ec := buildAndParse(t, Config{}, "https://idp.example.com/x")
	op := ec.Metadata.OpenIDProvider
	if op == nil {
		t.Fatal("openid_provider is nil")
	}
	types := map[string]bool{}
	for _, rt := range op.ClientRegistrationTypesSupported {
		types[rt] = true
	}
	if !types["automatic"] {
		t.Error("missing 'automatic' in client_registration_types_supported")
	}
	if !types["explicit"] {
		t.Error("missing 'explicit' in client_registration_types_supported")
	}
}

func TestBuild_OPMetadata_ResponseTypes(t *testing.T) {
	ec := buildAndParse(t, Config{}, "https://idp.example.com/x")
	op := ec.Metadata.OpenIDProvider
	if len(op.ResponseTypesSupported) == 0 {
		t.Error("response_types_supported is empty")
	}
	found := false
	for _, rt := range op.ResponseTypesSupported {
		if rt == "code" {
			found = true
		}
	}
	if !found {
		t.Error("'code' missing from response_types_supported")
	}
}

func TestBuild_OPMetadata_IDTokenAlgs(t *testing.T) {
	ec := buildAndParse(t, Config{}, "https://idp.example.com/x")
	op := ec.Metadata.OpenIDProvider
	if len(op.IDTokenSigningAlgValuesSupported) == 0 {
		t.Error("id_token_signing_alg_values_supported is empty")
	}
	found := false
	for _, alg := range op.IDTokenSigningAlgValuesSupported {
		if alg == "RS256" {
			found = true
		}
	}
	if !found {
		t.Error("RS256 missing from id_token_signing_alg_values_supported")
	}
}

// ── Build: federation_entity metadata ────────────────────────────────────────

func TestBuild_FederationEntityMetadata(t *testing.T) {
	cfg := Config{
		OrganizationName: "Università di Roma",
		Contacts:         []string{"admin@uniroma.it"},
		HomepageURI:      "https://www.uniroma.it",
		LogoURI:          "https://www.uniroma.it/logo.png",
	}
	ec := buildAndParse(t, cfg, "https://idp.uniroma.it/x")
	fe := ec.Metadata.FederationEntity
	if fe == nil {
		t.Fatal("federation_entity metadata is nil")
	}
	if fe.OrganizationName != cfg.OrganizationName {
		t.Errorf("organization_name: want %q, got %q", cfg.OrganizationName, fe.OrganizationName)
	}
	if len(fe.Contacts) == 0 || fe.Contacts[0] != "admin@uniroma.it" {
		t.Errorf("contacts: unexpected %v", fe.Contacts)
	}
	if fe.HomepageURI != cfg.HomepageURI {
		t.Errorf("homepage_uri: want %q, got %q", cfg.HomepageURI, fe.HomepageURI)
	}
	if fe.LogoURI != cfg.LogoURI {
		t.Errorf("logo_uri: want %q, got %q", cfg.LogoURI, fe.LogoURI)
	}
}

func TestBuild_FederationEntityMetadata_EmptyOptional(t *testing.T) {
	ec := buildAndParse(t, Config{}, "https://idp.example.com/x")
	fe := ec.Metadata.FederationEntity
	if fe == nil {
		t.Fatal("federation_entity metadata is nil")
	}
	// Empty config → blank organisation fields, nil/empty contacts.
	if fe.OrganizationName != "" {
		t.Errorf("expected empty organization_name, got %q", fe.OrganizationName)
	}
}

// ── Build: authority_hints ────────────────────────────────────────────────────

func TestBuild_AuthorityHints_Propagated(t *testing.T) {
	hints := []string{"https://registry.idem.garr.it", "https://edugain.org"}
	cfg := Config{AuthorityHints: hints}
	ec := buildAndParse(t, cfg, "https://idp.example.com/x")
	if len(ec.AuthorityHints) != len(hints) {
		t.Fatalf("authority_hints: want %d, got %d", len(hints), len(ec.AuthorityHints))
	}
	for i, h := range hints {
		if ec.AuthorityHints[i] != h {
			t.Errorf("authority_hints[%d]: want %q, got %q", i, h, ec.AuthorityHints[i])
		}
	}
}

func TestBuild_AuthorityHints_EmptyOmitted(t *testing.T) {
	ec := buildAndParse(t, Config{}, "https://idp.example.com/x")
	if len(ec.AuthorityHints) != 0 {
		t.Errorf("expected empty authority_hints, got %v", ec.AuthorityHints)
	}
}

// ── Build: JWS protected header ───────────────────────────────────────────────

func TestBuild_JWSHeader_TypeIsEntityStatement(t *testing.T) {
	raw, err := Build(Config{}, "https://idp.example.com/x", testKey, testKID, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	msg, err := jws.Parse(raw)
	if err != nil {
		t.Fatalf("parse JWS: %v", err)
	}
	if len(msg.Signatures()) == 0 {
		t.Fatal("no signatures")
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()
	typ, _ := hdr.Get("typ")
	if typ != "entity-statement+jwt" {
		t.Errorf("typ header: want entity-statement+jwt, got %v", typ)
	}
}

func TestBuild_JWSHeader_KIDPresent(t *testing.T) {
	raw, err := Build(Config{}, "https://idp.example.com/x", testKey, testKID, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	msg, _ := jws.Parse(raw)
	hdr := msg.Signatures()[0].ProtectedHeaders()
	if hdr.KeyID() != testKID {
		t.Errorf("kid: want %q, got %q", testKID, hdr.KeyID())
	}
}

// ── Build: content-type constant ─────────────────────────────────────────────

func TestContentType_Value(t *testing.T) {
	if ContentType != "application/entity-statement+jwt" {
		t.Errorf("ContentType: want application/entity-statement+jwt, got %q", ContentType)
	}
}
