package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// genCert produces a self-signed cert + key PEM for the given SAN and validity.
func genCert(t *testing.T, dnsName string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestValidateBYOCert_Valid(t *testing.T) {
	now := time.Now()
	cert, key := genCert(t, "auth.acme.com", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	exp, err := validateBYOCert(cert, key, "auth.acme.com")
	if err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
	if !exp.After(now) {
		t.Errorf("expiry should be in the future: %v", exp)
	}
}

func TestValidateBYOCert_WrongDomain(t *testing.T) {
	now := time.Now()
	cert, key := genCert(t, "auth.acme.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := validateBYOCert(cert, key, "auth.evil.com"); err == nil {
		t.Error("cert for a different domain must be rejected")
	}
}

func TestValidateBYOCert_Expired(t *testing.T) {
	now := time.Now()
	cert, key := genCert(t, "auth.acme.com", now.Add(-48*time.Hour), now.Add(-time.Hour))
	if _, err := validateBYOCert(cert, key, "auth.acme.com"); err == nil {
		t.Error("expired cert must be rejected")
	}
}

func TestValidateBYOCert_NotYetValid(t *testing.T) {
	now := time.Now()
	cert, key := genCert(t, "auth.acme.com", now.Add(24*time.Hour), now.Add(48*time.Hour))
	if _, err := validateBYOCert(cert, key, "auth.acme.com"); err == nil {
		t.Error("not-yet-valid cert must be rejected")
	}
}

func TestValidateBYOCert_MismatchedKey(t *testing.T) {
	now := time.Now()
	cert, _ := genCert(t, "auth.acme.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	_, otherKey := genCert(t, "auth.acme.com", now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := validateBYOCert(cert, otherKey, "auth.acme.com"); err == nil {
		t.Error("cert with a mismatched key must be rejected")
	}
}

func TestValidateBYOCert_Garbage(t *testing.T) {
	if _, err := validateBYOCert("not a pem", "neither", "x.com"); err == nil {
		t.Error("garbage input must be rejected")
	}
}
