package oidc

// DBSigner implements the Signer interface with RSA signing keys stored in
// PostgreSQL, encrypted at rest with AES-256-GCM using a Key Encryption Key.
//
// On startup, NewDBSigner loads the active key from the database.  If none
// exists, a new RSA-2048 key is generated, encrypted, and inserted.
//
// Rotate() atomically:
//  1. Retires the current active key (sets retired_at, expires_at = now+24h).
//  2. Generates a new RSA-2048 key, encrypts it with the KEK, inserts it as active.
//  3. Re-loads all JWKS keys (active + retired within grace window) from the DB.
//
// The 24-hour grace period keeps the retired key's public key in JWKS so
// outstanding tokens signed with the old kid remain verifiable.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	clavexcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

// DBSigner implements Signer using keys persisted in PostgreSQL.
// It is safe for concurrent use.
type DBSigner struct {
	mu   sync.RWMutex
	repo *repository.SigningKeyRepository
	enc  *clavexcrypto.Encryptor // AES-256-GCM with the KEK

	// cached active key state
	privateKey *rsa.PrivateKey
	kid        string
	jwks       []byte // JSON: active + retired-within-grace public keys
}

// NewDBSigner creates a DBSigner backed by pool, using kek (32 raw bytes) to
// encrypt/decrypt signing key material stored in the database.
//
// If no active signing key is found, a fresh RSA-2048 key is generated and
// persisted so the server can start without any manual key provisioning.
func NewDBSigner(ctx context.Context, pool *pgxpool.Pool, kek [32]byte) (*DBSigner, error) {
	s := &DBSigner{
		repo: repository.NewSigningKeyRepository(pool),
		enc:  clavexcrypto.NewEncryptorFromKey(kek),
	}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads the active key (and JWKS keys) from the database.
// If no active key exists, it bootstraps one.
func (s *DBSigner) load(ctx context.Context) error {
	row, err := s.repo.GetActive(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.bootstrap(ctx)
	}
	if err != nil {
		return fmt.Errorf("db signer: load active key: %w", err)
	}

	priv, err := s.decryptKey(row.KeyEnc)
	if err != nil {
		return fmt.Errorf("db signer: decrypt active key (kid=%s): %w", row.KID, err)
	}

	jwksJSON, err := s.buildJWKSFromDB(ctx)
	if err != nil {
		return fmt.Errorf("db signer: build JWKS: %w", err)
	}

	s.mu.Lock()
	s.privateKey = priv
	s.kid = row.KID
	s.jwks = jwksJSON
	s.mu.Unlock()
	return nil
}

// bootstrap generates a new RSA-2048 key and stores it as the first active key.
func (s *DBSigner) bootstrap(ctx context.Context) error {
	priv, kid, keyEnc, err := s.generateAndEncrypt()
	if err != nil {
		return fmt.Errorf("db signer: bootstrap generate key: %w", err)
	}

	if err := s.repo.Insert(ctx, kid, "PS256", keyEnc); err != nil {
		return fmt.Errorf("db signer: bootstrap insert key: %w", err)
	}

	jwksJSON, err := buildJWKS(&priv.PublicKey, kid)
	if err != nil {
		return fmt.Errorf("db signer: build JWKS after bootstrap: %w", err)
	}

	s.mu.Lock()
	s.privateKey = priv
	s.kid = kid
	s.jwks = jwksJSON
	s.mu.Unlock()
	return nil
}

// Rotate retires the current active key and promotes a freshly generated key.
// The retired key's public key remains in JWKS for 24 hours so existing tokens
// (signed with the old kid) can still be verified during the grace period.
func (s *DBSigner) Rotate() error {
	ctx := context.Background()

	priv, kid, keyEnc, err := s.generateAndEncrypt()
	if err != nil {
		return fmt.Errorf("db signer: rotate generate key: %w", err)
	}

	// Retire the current active key before inserting the new one.
	if err := s.repo.RetireActive(ctx); err != nil {
		return fmt.Errorf("db signer: retire active key: %w", err)
	}

	if err := s.repo.Insert(ctx, kid, "PS256", keyEnc); err != nil {
		return fmt.Errorf("db signer: insert new key: %w", err)
	}

	jwksJSON, err := s.buildJWKSFromDB(ctx)
	if err != nil {
		return fmt.Errorf("db signer: rebuild JWKS after rotate: %w", err)
	}

	s.mu.Lock()
	s.privateKey = priv
	s.kid = kid
	s.jwks = jwksJSON
	s.mu.Unlock()
	return nil
}

// PrivateKey returns the active RSA private key for token signing.
func (s *DBSigner) PrivateKey() *rsa.PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.privateKey
}

// PublicKey returns the active RSA public key.
func (s *DBSigner) PublicKey() *rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &s.privateKey.PublicKey
}

// KID returns the key identifier for the active signing key.
func (s *DBSigner) KID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kid
}

// JWKS returns the current JWKS JSON (active + retired-within-grace public keys).
func (s *DBSigner) JWKS() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwks
}

// Algorithm returns PS256.
func (s *DBSigner) Algorithm() jwa.SignatureAlgorithm {
	return jwa.PS256
}

// CryptoSigner returns the active private key as a crypto.Signer.
// *rsa.PrivateKey already satisfies crypto.Signer.
func (s *DBSigner) CryptoSigner() crypto.Signer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.privateKey
}

// ── helpers ───────────────────────────────────────────────────────────────────

// generateAndEncrypt creates a new RSA-2048 key, derives its kid, and
// returns the key along with the AES-256-GCM encrypted PKCS#8 DER bytes.
func (s *DBSigner) generateAndEncrypt() (*rsa.PrivateKey, string, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", nil, fmt.Errorf("generate RSA key: %w", err)
	}

	kid := computeKID(&priv.PublicKey)

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", nil, fmt.Errorf("marshal PKCS8: %w", err)
	}

	keyEnc, err := s.enc.EncryptBytes(der)
	if err != nil {
		return nil, "", nil, fmt.Errorf("encrypt key: %w", err)
	}

	return priv, kid, keyEnc, nil
}

// decryptKey decrypts an AES-256-GCM PKCS#8 DER blob stored in the database.
func (s *DBSigner) decryptKey(keyEnc []byte) (*rsa.PrivateKey, error) {
	der, err := s.enc.DecryptBytes(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}

	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key must be RSA, got %T", key)
	}
	return priv, nil
}

// buildJWKSFromDB fetches all JWKS-eligible keys from the DB (active +
// retired within the grace window) and assembles a JWKS JSON document.
func (s *DBSigner) buildJWKSFromDB(ctx context.Context) ([]byte, error) {
	rows, err := s.repo.GetJWKSKeys(ctx)
	if err != nil {
		return nil, err
	}

	entries := make([]rsaKeyEntry, 0, len(rows))
	for _, row := range rows {
		priv, err := s.decryptKey(row.KeyEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt key (kid=%s): %w", row.KID, err)
		}
		entries = append(entries, rsaKeyEntry{pub: &priv.PublicKey, kid: row.KID})
	}

	return marshalJWKS(entries), nil
}

// DecodeKEK decodes a base64url-encoded 32-byte Key Encryption Key from config.
// Returns an error if the input is empty, invalid base64url, or not exactly 32 bytes.
func DecodeKEK(s string) ([32]byte, error) {
	var kek [32]byte
	if s == "" {
		return kek, fmt.Errorf("key_encryption_key is required when key_backend=db")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// also try standard base64 in case the user used +/= instead of -_
		b, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return kek, fmt.Errorf("key_encryption_key: invalid base64: %w", err)
		}
	}
	if len(b) != 32 {
		return kek, fmt.Errorf("key_encryption_key: must be exactly 32 bytes, got %d", len(b))
	}
	copy(kek[:], b)
	return kek, nil
}

// compile-time check that DBSigner satisfies the Signer interface.
var _ Signer = (*DBSigner)(nil)
