package oid4w

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// CertificateCredentialSigner adapts a dedicated certificate key to the legacy
// credential signing interface. It is never used to issue OAuth/OIDC tokens.
type CertificateCredentialSigner struct{ *CertificateMetadataSigner }

func LoadCertificateCredentialSigner(certFile, keyFile string) (*CertificateCredentialSigner, error) {
	s, err := LoadCertificateMetadataSigner(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if s.Algorithm() != jwa.ES256 && s.Algorithm() != jwa.PS256 {
		return nil, errors.New("credential certificate must use P-256 ECDSA or RSA")
	}
	return &CertificateCredentialSigner{s}, nil
}

func (s *CertificateCredentialSigner) PrivateKey() *rsa.PrivateKey {
	key, _ := s.key.(*rsa.PrivateKey)
	return key
}
func (s *CertificateCredentialSigner) PublicKey() *rsa.PublicKey {
	key, _ := s.key.Public().(*rsa.PublicKey)
	return key
}
func (s *CertificateCredentialSigner) Rotate() error {
	return errors.New("certificate signing keys are rotated through external certificate configuration")
}
func (s *CertificateCredentialSigner) JWKS() []byte {
	key, err := jwk.FromRaw(s.key.Public())
	if err != nil {
		return nil
	}
	if err = key.Set(jwk.KeyIDKey, s.KID()); err != nil {
		return nil
	}
	set := jwk.NewSet()
	if err = set.AddKey(key); err != nil {
		return nil
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		return nil
	}
	return encoded
}

// Revalidate immediately before signing, including paths that do not have an
// HTTP request. An expired configured certificate must never yield a credential
// silently signed without its certificate chain.
func (s *CertificateCredentialSigner) CryptoSigner() crypto.Signer {
	return validatingCredentialKey{s.CertificateMetadataSigner}
}

type validatingCredentialKey struct{ signer *CertificateMetadataSigner }

func (k validatingCredentialKey) Public() crypto.PublicKey { return k.signer.key.Public() }
func (k validatingCredentialKey) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, err := k.signer.validate(""); err != nil {
		return nil, err
	}
	return k.signer.key.Sign(random, digest, opts)
}
