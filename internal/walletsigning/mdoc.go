package walletsigning

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	secretcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/models"
)

const encryptedPrefix = "wallet-key:v1:"

func EncryptKey(enc *secretcrypto.Encryptor, key string) (string, error) {
	if enc == nil {
		return "", errors.New("wallet key encryption unavailable")
	}
	ciphertext, err := enc.Encrypt(key)
	if err != nil {
		return "", err
	}
	return encryptedPrefix + ciphertext, nil
}

// Certificates validates a DS leaf and an optional leaf-first CA chain, whose
// last certificate is the operator-supplied root. This checks configuration
// consistency, not whether an external wallet trusts that root.
func Certificates(leafPEM string, caPEM *string, sandbox bool) (*x509.Certificate, [][]byte, error) {
	leaves, err := parseCertificates(leafPEM, 1)
	if err != nil || len(leaves) != 1 {
		return nil, nil, errors.New("provide exactly one DS certificate")
	}
	leaf := leaves[0]
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	now := time.Now()
	if !ok || pub.Curve != elliptic.P256() || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, nil, errors.New("DS certificate must be a current P-256 signing leaf")
	}
	chain := [][]byte{leaf.Raw}
	if caPEM == nil || strings.TrimSpace(*caPEM) == "" {
		if !sandbox || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
			return nil, nil, errors.New("provide the IACA certificate chain")
		}
		return leaf, chain, nil
	}
	cas, err := parseCertificates(*caPEM, 7)
	if err != nil || len(cas) == 0 {
		return nil, nil, errors.New("invalid IACA certificate chain")
	}
	root := cas[len(cas)-1]
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, nil, errors.New("IACA chain must end with a self-signed CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	previous := leaf
	for i, ca := range cas {
		if !ca.IsCA || previous.CheckSignatureFrom(ca) != nil {
			return nil, nil, errors.New("invalid DS certificate chain order")
		}
		if i < len(cas)-1 {
			intermediates.AddCert(ca)
			chain = append(chain, ca.Raw)
		}
		previous = ca
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, nil, errors.New("DS certificate chain is not currently valid")
	}
	return leaf, chain, nil
}

func parseCertificates(raw string, limit int) ([]*x509.Certificate, error) {
	if len(raw) > 256*1024 {
		return nil, errors.New("certificate size limit exceeded")
	}
	out := []*x509.Certificate{}
	seen := map[string]bool{}
	for rest := bytes.TrimSpace([]byte(raw)); len(rest) > 0; {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("only certificate PEM blocks are accepted")
		}
		b, tail := pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(out) >= limit || seen[string(b.Bytes)] {
			return nil, errors.New("invalid certificate PEM")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, errors.New("invalid certificate")
		}
		seen[string(b.Bytes)] = true
		out = append(out, c)
		rest = bytes.TrimSpace(tail)
	}
	return out, nil
}

func LocalKey(certPEM, keyPEM string) (crypto.Signer, error) {
	if len(keyPEM) > 64*1024 {
		return nil, errors.New("DS key size limit exceeded")
	}
	raw := bytes.TrimSpace([]byte(keyPEM))
	if !bytes.HasPrefix(raw, []byte("-----BEGIN PRIVATE KEY-----")) && !bytes.HasPrefix(raw, []byte("-----BEGIN EC PRIVATE KEY-----")) {
		return nil, errors.New("invalid DS private key PEM")
	}
	b, rest := pem.Decode(raw)
	if b == nil || len(bytes.TrimSpace(rest)) != 0 || len(b.Headers) != 0 || (b.Type != "PRIVATE KEY" && b.Type != "EC PRIVATE KEY") {
		return nil, errors.New("provide exactly one unencrypted DS private key")
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, errors.New("DS certificate/key mismatch")
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("DS signing requires P-256")
	}
	return key, nil
}

func ResolveMdoc(rec *models.OrgMdocIssuer, enc *secretcrypto.Encryptor, registry *Registry) (crypto.Signer, [][]byte, error) {
	leaf, chain, err := Certificates(rec.DSCertificatePEM, rec.IACACertificatePEM, true)
	if err != nil {
		return nil, nil, err
	}
	if rec.VaultSignerRef != "" {
		if rec.DSPrivateKeyPEM != nil && *rec.DSPrivateKeyPEM != "" {
			return nil, nil, errors.New("ambiguous DS signing configuration")
		}
		key, err := registry.Resolve(rec.OrgID, rec.VaultSignerRef, leaf.PublicKey)
		return key, chain, err
	}
	if rec.DSPrivateKeyPEM == nil {
		return nil, nil, errors.New("DS key unavailable")
	}
	raw := *rec.DSPrivateKeyPEM
	if strings.HasPrefix(raw, encryptedPrefix) {
		ciphertext := strings.TrimPrefix(raw, encryptedPrefix)
		if enc == nil || !secretcrypto.IsEncrypted(ciphertext) {
			return nil, nil, errors.New("encrypted DS key unavailable")
		}
		raw, err = enc.Decrypt(ciphertext)
		if err != nil {
			return nil, nil, errors.New("DS key decryption failed")
		}
	}
	key, err := LocalKey(rec.DSCertificatePEM, raw)
	return key, chain, err
}

// PublicCertificate parses one strictly public leaf for administration views,
// including expired certificates; it does not establish trust or signing validity.
func PublicCertificate(raw string) (*x509.Certificate, error) {
	certs, err := parseCertificates(raw, 1)
	if err != nil || len(certs) != 1 {
		return nil, errors.New("invalid public DS certificate")
	}
	return certs[0], nil
}

// MdocExpiry bounds credential validity by every configured certificate.
func MdocExpiry(rec *models.OrgMdocIssuer) (time.Time, error) {
	leaf, _, err := Certificates(rec.DSCertificatePEM, rec.IACACertificatePEM, true)
	if err != nil {
		return time.Time{}, err
	}
	expiry := leaf.NotAfter
	if rec.IACACertificatePEM != nil && strings.TrimSpace(*rec.IACACertificatePEM) != "" {
		cas, err := parseCertificates(*rec.IACACertificatePEM, 7)
		if err != nil {
			return time.Time{}, err
		}
		for _, ca := range cas {
			if ca.NotAfter.Before(expiry) {
				expiry = ca.NotAfter
			}
		}
	}
	return expiry, nil
}
