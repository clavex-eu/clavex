package oid4w_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// stubSigner is a minimal MetadataSigner backed by an RSA key.
type stubSigner struct {
	priv *rsa.PrivateKey
}

func newStubSigner(t *testing.T) *stubSigner {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &stubSigner{priv: priv}
}

func (s *stubSigner) Algorithm() jwa.SignatureAlgorithm { return jwa.PS256 }
func (s *stubSigner) KID() string                       { return "test-kid-1" }
func (s *stubSigner) CryptoSigner() crypto.Signer       { return s.priv }

func TestSignIssuerMetadata_IsCompactJWT(t *testing.T) {
	meta := &oid4w.CredentialIssuerMetadata{
		CredentialIssuer:   "https://issuer.example.com",
		CredentialEndpoint: "https://issuer.example.com/credential",
		CredentialConfigurationsSupported: map[string]*oid4w.CredentialConfigurationMeta{
			"test-cred": {Format: "dc+sd-jwt", VCT: "urn:test:cred:1"},
		},
	}

	signed, err := oid4w.SignIssuerMetadata(meta, newStubSigner(t))
	if err != nil {
		t.Fatalf("SignIssuerMetadata: %v", err)
	}

	// A compact JWS has exactly two '.' characters.
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 dot-separated parts, got %d", len(parts))
	}
}

func TestSignIssuerMetadata_TypHeader(t *testing.T) {
	meta := &oid4w.CredentialIssuerMetadata{
		CredentialIssuer:                  "https://issuer.example.com",
		CredentialEndpoint:                "https://issuer.example.com/credential",
		CredentialConfigurationsSupported: map[string]*oid4w.CredentialConfigurationMeta{},
	}

	signed, err := oid4w.SignIssuerMetadata(meta, newStubSigner(t))
	if err != nil {
		t.Fatalf("SignIssuerMetadata: %v", err)
	}

	// Parse the JWS without signature verification and check the typ header.
	msg, err := jws.Parse([]byte(signed))
	if err != nil {
		t.Fatalf("jws.Parse: %v", err)
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()
	if hdr.Type() != "openidvci-issuer-metadata+jwt" {
		t.Fatalf("expected typ=openidvci-issuer-metadata+jwt, got %q", hdr.Type())
	}
	if hdr.KeyID() != "test-kid-1" {
		t.Fatalf("expected kid=test-kid-1, got %q", hdr.KeyID())
	}
}

func TestSignIssuerMetadata_ClaimsPresent(t *testing.T) {
	signer := newStubSigner(t)
	meta := &oid4w.CredentialIssuerMetadata{
		CredentialIssuer:                  "https://issuer.example.com",
		CredentialEndpoint:                "https://issuer.example.com/credential",
		CredentialConfigurationsSupported: map[string]*oid4w.CredentialConfigurationMeta{},
	}

	signed, err := oid4w.SignIssuerMetadata(meta, signer)
	if err != nil {
		t.Fatalf("SignIssuerMetadata: %v", err)
	}

	// Verify signature and parse claims.
	tok, err := jwt.Parse([]byte(signed),
		jwt.WithKey(jwa.PS256, &signer.priv.PublicKey),
		jwt.WithValidate(false),
	)
	if err != nil {
		t.Fatalf("jwt.Parse: %v", err)
	}

	if tok.Issuer() != "https://issuer.example.com" {
		t.Errorf("iss: want %q, got %q", "https://issuer.example.com", tok.Issuer())
	}

	// credential_issuer claim must be present in the payload.
	ci, ok := tok.Get("credential_issuer")
	if !ok {
		t.Fatal("credential_issuer claim missing from JWT payload")
	}
	if ci != "https://issuer.example.com" {
		t.Errorf("credential_issuer: want %q, got %v", "https://issuer.example.com", ci)
	}

	// credential_endpoint must be present.
	if _, ok := tok.Get("credential_endpoint"); !ok {
		t.Fatal("credential_endpoint claim missing from JWT payload")
	}
}
