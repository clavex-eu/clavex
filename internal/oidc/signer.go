package oidc

import (
	"crypto"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

// Signer abstracts RSA signing-key access for JWT production.
//
// Current implementations:
//   - *KeySet       — file-backed; loads the key from a PEM file at startup.
//   - *DBSigner     — database-backed; encrypted key persisted via migration 000127.
//
// Planned implementations (not yet shipped):
//   - VaultSigner   — delegates signing to HashiCorp Vault Transit; private key
//                     never leaves Vault.
//   - AWSSigner     — delegates signing to AWS KMS; private key never leaves KMS.
//
// Note: PrivateKey() is part of this interface for backward compatibility with
// the ~20 call sites that assemble JWTs directly.  Vault/KMS backends should
// return nil from PrivateKey() and override those call sites with a Sign() method
// in a future revision.
type Signer interface {
	// PrivateKey returns the current RSA private signing key.
	// Vault/KMS backends may return nil here; callers must check.
	PrivateKey() *rsa.PrivateKey

	// PublicKey returns the RSA public key corresponding to the active key.
	PublicKey() *rsa.PublicKey

	// KID returns the active key identifier.
	KID() string

	// JWKS returns the current public key set as a JSON document suitable for
	// serving at /.well-known/jwks.json.  Includes retired keys within their
	// 24-hour grace period.
	JWKS() []byte

	// Algorithm returns the signing algorithm (PS256 for all current backends).
	Algorithm() jwa.SignatureAlgorithm

	// CryptoSigner returns a crypto.Signer backed by the active key.
	// For file/DB backends this wraps the in-process RSA private key.
	// For Vault/KMS backends this returns a remote-signing adapter that
	// delegates every Sign() call to the external service, so the private
	// key material never enters the Clavex process.
	//
	// jwt.WithKey(alg, signer.CryptoSigner()) in the token issuance path
	// instead of jwt.WithKey(alg, signer.PrivateKey()) allows all four
	// backends to share the same signing code.
	CryptoSigner() crypto.Signer

	// Rotate generates a new signing key, activates it, and retires the
	// previous one.  Callers that hold a cached reference to PrivateKey() or
	// KID() must re-read those values after a successful Rotate().
	Rotate() error
}

// Ensure *KeySet satisfies Signer at compile time.
var _ Signer = (*KeySet)(nil)
