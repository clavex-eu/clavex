package oidc

// AWSSigner implements the Signer interface by delegating signing operations to
// AWS KMS.  The RSA private key never leaves KMS; the Clavex process only holds
// the public key (fetched via kms:GetPublicKey at startup).
//
// KMS key requirements:
//   - Key type: RSA_2048 or RSA_4096
//   - Key usage: SIGN_VERIFY
//   - Signing algorithm: RSASSA_PSS_SHA_256
//
// Configuration (set via env or config file):
//   CLAVEX_AUTH_AWS_KMS_KEY_ID   KMS key ID or ARN
//   CLAVEX_AUTH_AWS_KMS_REGION   AWS region (default: AWS_REGION or AWS_DEFAULT_REGION)
//
// Standard AWS credential chain is used (IAM role, ~/.aws/credentials, env vars).

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

// AWSKMSConfig holds the AWS KMS connection parameters.
type AWSKMSConfig struct {
	KeyID  string // KMS key ID or ARN
	Region string // AWS region; falls back to AWS_REGION env var if empty
}

// AWSSigner signs JWTs via AWS KMS.
type AWSSigner struct {
	cfg    AWSKMSConfig
	client *kms.Client

	mu        sync.RWMutex
	publicKey *rsa.PublicKey
	kid       string
	jwks      []byte
}

// NewAWSSigner creates an AWSSigner and fetches the public key from KMS.
func NewAWSSigner(ctx context.Context, cfg AWSKMSConfig) (*AWSSigner, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws signer: load AWS config: %w", err)
	}

	s := &AWSSigner{
		cfg:    cfg,
		client: kms.NewFromConfig(awsCfg),
	}
	if err := s.loadPublicKey(ctx); err != nil {
		return nil, fmt.Errorf("aws signer: load public key from KMS: %w", err)
	}
	return s, nil
}

// ── Signer interface ──────────────────────────────────────────────────────────

// PrivateKey returns nil — the private key never leaves KMS.
func (s *AWSSigner) PrivateKey() *rsa.PrivateKey { return nil }

func (s *AWSSigner) PublicKey() *rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publicKey
}

func (s *AWSSigner) KID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kid
}

func (s *AWSSigner) JWKS() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwks
}

func (s *AWSSigner) Algorithm() jwa.SignatureAlgorithm { return jwa.PS256 }

// CryptoSigner returns a crypto.Signer whose Sign() method calls AWS KMS.
func (s *AWSSigner) CryptoSigner() crypto.Signer { return &awsCryptoSigner{parent: s} }

// Rotate is a no-op for AWS KMS — key rotation is managed in KMS directly.
// Reload the public key from KMS to pick up a new version after manual rotation.
func (s *AWSSigner) Rotate() error {
	return s.loadPublicKey(context.Background())
}

// ── AWS KMS helpers ───────────────────────────────────────────────────────────

func (s *AWSSigner) loadPublicKey(ctx context.Context) error {
	out, err := s.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(s.cfg.KeyID),
	})
	if err != nil {
		return err
	}

	// out.PublicKey is DER-encoded SubjectPublicKeyInfo (PKIX).
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return fmt.Errorf("parse KMS public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("KMS key must be RSA, got %T", pub)
	}

	kid := computeKID(rsaPub)
	jwksJSON, err := buildJWKS(rsaPub, kid)
	if err != nil {
		return fmt.Errorf("build JWKS from KMS key: %w", err)
	}

	s.mu.Lock()
	s.publicKey = rsaPub
	s.kid = kid
	s.jwks = jwksJSON
	s.mu.Unlock()
	return nil
}

// signDigest calls kms:Sign with RSASSA_PSS_SHA_256 and a pre-hashed digest.
func (s *AWSSigner) signDigest(ctx context.Context, digest []byte) ([]byte, error) {
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.cfg.KeyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	return out.Signature, nil
}

// ── awsCryptoSigner ───────────────────────────────────────────────────────────

type awsCryptoSigner struct {
	parent *AWSSigner
}

func (a *awsCryptoSigner) Public() crypto.PublicKey {
	return a.parent.PublicKey()
}

// Sign delegates to AWS KMS.  digest is SHA-256(signingInput) as computed by jwx.
func (a *awsCryptoSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return a.parent.signDigest(context.Background(), digest)
}

// Ensure *AWSSigner satisfies Signer at compile time.
var _ Signer = (*AWSSigner)(nil)
