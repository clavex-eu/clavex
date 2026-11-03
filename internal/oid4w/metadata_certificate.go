package oid4w

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

// CertificateMetadataSigner separates metadata signing from OIDC and credential
// signing. Wallets must independently establish trust in the configured root.
type CertificateMetadataSigner struct {
	key          crypto.Signer
	certificates []*x509.Certificate
	algorithm    jwa.SignatureAlgorithm
	kid          string
}

// LoadCertificateMetadataSigner reads a leaf-first PEM chain including its root
// and matching private key. It never generates a replacement on failure.
func LoadCertificateMetadataSigner(certFile, keyFile string) (*CertificateMetadataSigner, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("metadata signing requires both certificate and key files")
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read metadata certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read metadata signing key: %w", err)
	}
	defer clear(keyPEM)
	return newCertificateMetadataSigner(certPEM, keyPEM)
}

func newCertificateMetadataSigner(certPEM, keyPEM []byte) (*CertificateMetadataSigner, error) {
	if len(certPEM) > 256*1024 || len(keyPEM) > 64*1024 {
		return nil, errors.New("metadata signing material exceeds size limit")
	}
	var certificates []*x509.Certificate
	seen := make(map[string]bool)
	for rest := bytes.TrimSpace(certPEM); len(rest) != 0; {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("metadata chain must contain only certificates")
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(certificates) >= 8 {
			return nil, errors.New("invalid metadata certificate chain")
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid metadata certificate")
		}
		fingerprint := sha256.Sum256(parsed.Raw)
		identity := hex.EncodeToString(fingerprint[:])
		if seen[identity] {
			return nil, errors.New("duplicate certificate in metadata chain")
		}
		seen[identity] = true
		certificates = append(certificates, parsed)
		rest = bytes.TrimSpace(tail)
	}
	if len(certificates) < 2 {
		return nil, errors.New("metadata chain must include a leaf and its root")
	}
	if bytes.Count(certPEM, []byte("-----BEGIN CERTIFICATE-----")) != len(certificates) {
		return nil, errors.New("invalid extra certificate material")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("invalid metadata signing key or certificate/key mismatch")
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported metadata signing key")
	}
	s := &CertificateMetadataSigner{key: key, certificates: certificates}
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 256:
			s.algorithm = jwa.ES256
		case 384:
			s.algorithm = jwa.ES384
		case 521:
			s.algorithm = jwa.ES512
		default:
			return nil, errors.New("unsupported metadata EC curve")
		}
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("metadata RSA key must be at least 2048 bits")
		}
		s.algorithm = jwa.PS256
	default:
		return nil, errors.New("unsupported metadata signing key type")
	}
	hash := sha256.Sum256(certificates[0].Raw)
	s.kid = hex.EncodeToString(hash[:])
	if _, err := s.validate(""); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *CertificateMetadataSigner) Algorithm() jwa.SignatureAlgorithm { return s.algorithm }
func (s *CertificateMetadataSigner) KID() string                       { return s.kid }
func (s *CertificateMetadataSigner) CryptoSigner() crypto.Signer       { return s.key }

// RootCertificatePEM exposes only the configured public trust anchor.
func (s *CertificateMetadataSigner) RootCertificatePEM() []byte {
	root := s.certificates[len(s.certificates)-1]
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
}

// CertificateValidity exposes the intersection of the public chain's validity
// windows for consumers that retain only its public verification key.
func (s *CertificateMetadataSigner) CertificateValidity() (time.Time, time.Time) {
	start, end := s.certificates[0].NotBefore, s.certificates[0].NotAfter
	for _, c := range s.certificates {
		if c.NotBefore.After(start) {
			start = c.NotBefore
		}
		if c.NotAfter.Before(end) {
			end = c.NotAfter
		}
	}
	return start, end
}

// MetadataCertificateChain revalidates the chain and issuer hostname at request
// time, excluding the trust anchor from the transmitted x5c.
func (s *CertificateMetadataSigner) MetadataCertificateChain(issuer string) (*cert.Chain, time.Time, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, time.Time{}, errors.New("certificate metadata signing requires an HTTPS issuer")
	}
	expires, err := s.validate(u.Hostname())
	if err != nil {
		return nil, time.Time{}, err
	}
	var chain cert.Chain
	for _, c := range s.certificates[:len(s.certificates)-1] {
		if err := chain.AddString(base64.StdEncoding.EncodeToString(c.Raw)); err != nil {
			return nil, time.Time{}, err
		}
	}
	return &chain, expires, nil
}

func (s *CertificateMetadataSigner) validate(host string) (time.Time, error) {
	leaf, root := s.certificates[0], s.certificates[len(s.certificates)-1]
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || root.CheckSignatureFrom(root) != nil {
		return time.Time{}, errors.New("metadata chain requires a signing leaf and self-signed CA root")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	expires := leaf.NotAfter
	for i, c := range s.certificates {
		if c.NotAfter.Before(expires) {
			expires = c.NotAfter
		}
		if i > 0 {
			if err := s.certificates[i-1].CheckSignatureFrom(c); err != nil {
				return time.Time{}, errors.New("metadata chain is not ordered leaf first")
			}
			if i < len(s.certificates)-1 {
				intermediates.AddCert(c)
			}
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return time.Time{}, fmt.Errorf("metadata signing certificate validation: %w", err)
	}
	return expires, nil
}
