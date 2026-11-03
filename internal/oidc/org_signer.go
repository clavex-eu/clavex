package oidc

// OrgSignerCache resolves per-organisation signing keys into fresh request
// snapshots. The historical type name is retained for callers. Database state
// is checked on every Resolve to observe rotations from every replica.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	clavexcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/rs/zerolog/log"
)

// ── OrgDBSigner ───────────────────────────────────────────────────────────────

// OrgDBSigner implements Signer for a single organisation's key stored in the
// signing_keys table (org_id IS NOT NULL).
type OrgDBSigner struct {
	mu               sync.RWMutex
	repo             *repository.SigningKeyRepository
	enc              *clavexcrypto.Encryptor
	orgID            uuid.UUID
	privateKey       *rsa.PrivateKey
	kid              string
	jwks             []byte
	verificationJWKS []byte
}

func newOrgDBSigner(ctx context.Context, repo *repository.SigningKeyRepository, enc *clavexcrypto.Encryptor, orgID uuid.UUID) (*OrgDBSigner, error) {
	s := &OrgDBSigner{repo: repo, enc: enc, orgID: orgID}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *OrgDBSigner) load(ctx context.Context) error {
	row, err := s.repo.GetActiveForOrg(ctx, s.orgID)
	if err != nil {
		return err // pgx.ErrNoRows if no org key
	}

	priv, err := s.decryptKey(row.KeyEnc)
	if err != nil {
		return fmt.Errorf("org signer (org=%s): decrypt key (kid=%s): %w", s.orgID, row.KID, err)
	}

	jwksJSON, err := s.buildJWKSFromDB(ctx)
	if err != nil {
		return fmt.Errorf("org signer (org=%s): build JWKS: %w", s.orgID, err)
	}

	verificationJWKS, err := s.buildVerificationJWKS(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.privateKey = priv
	s.kid = row.KID
	s.jwks = jwksJSON
	s.verificationJWKS = verificationJWKS
	s.mu.Unlock()
	return nil
}

// Rotate generates a new RSA-2048 key for this org, retires the old one, and
// reloads the in-memory state.
func (s *OrgDBSigner) Rotate() error {
	ctx := context.Background()
	_, kid, encrypted, err := s.generateAndEncrypt()
	if err != nil {
		return err
	}
	if _, err = s.repo.ReplaceForOrg(ctx, s.orgID, repository.OrgKeyReplacement{KID: kid, Algorithm: "PS256", KeyEnc: encrypted, RejectImported: true}); err != nil {
		return err
	}
	return s.load(ctx)
}

// VerificationJWKS includes only this tenant's signing keys, never the global
// transition keys published for legacy external consumers.
func (s *OrgDBSigner) VerificationJWKS() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.verificationJWKS
}

func (s *OrgDBSigner) buildVerificationJWKS(ctx context.Context) ([]byte, error) {
	rows, err := s.repo.GetJWKSKeysForOrg(ctx, s.orgID)
	if err != nil {
		return nil, err
	}
	entries := make([]rsaKeyEntry, 0, len(rows))
	for _, row := range rows {
		if row.OrgID == nil || *row.OrgID != s.orgID {
			continue
		}
		key, err := s.decryptKey(row.KeyEnc)
		if err != nil {
			return nil, err
		}
		entries = append(entries, rsaKeyEntry{pub: &key.PublicKey, kid: row.KID})
	}
	return marshalJWKS(entries), nil
}

func (s *OrgDBSigner) PrivateKey() *rsa.PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.privateKey
}

func (s *OrgDBSigner) PublicKey() *rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &s.privateKey.PublicKey
}

func (s *OrgDBSigner) KID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kid
}

func (s *OrgDBSigner) JWKS() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwks
}

func (s *OrgDBSigner) Algorithm() jwa.SignatureAlgorithm { return jwa.PS256 }

func (s *OrgDBSigner) CryptoSigner() crypto.Signer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.privateKey
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (s *OrgDBSigner) generateAndEncrypt() (*rsa.PrivateKey, string, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", nil, fmt.Errorf("generate RSA key: %w", err)
	}
	kid := computeKID(&priv.PublicKey)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", nil, fmt.Errorf("marshal PKCS8 key: %w", err)
	}
	keyEnc, err := s.enc.EncryptBytes(der)
	if err != nil {
		return nil, "", nil, fmt.Errorf("encrypt key: %w", err)
	}
	return priv, kid, keyEnc, nil
}

func (s *OrgDBSigner) decryptKey(keyEnc []byte) (*rsa.PrivateKey, error) {
	der, err := s.enc.DecryptBytes(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt key material: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 key: %w", err)
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not RSA (got %T)", key)
	}
	return priv, nil
}

func (s *OrgDBSigner) buildJWKSFromDB(ctx context.Context) ([]byte, error) {
	rows, err := s.repo.GetJWKSKeysForOrg(ctx, s.orgID)
	if err != nil {
		return nil, err
	}
	entries := make([]rsaKeyEntry, 0, len(rows))
	for _, row := range rows {
		priv, err := s.decryptKey(row.KeyEnc)
		if err != nil {
			continue // best effort
		}
		entries = append(entries, rsaKeyEntry{pub: &priv.PublicKey, kid: row.KID})
	}
	if len(entries) == 0 {
		// Fallback: use in-memory public key (happens during bootstrap)
		s.mu.RLock()
		if s.privateKey != nil {
			entries = append(entries, rsaKeyEntry{pub: &s.privateKey.PublicKey, kid: s.kid})
		}
		s.mu.RUnlock()
	}
	return marshalJWKS(entries), nil
}

// Ensure *OrgDBSigner satisfies Signer at compile time.
var _ Signer = (*OrgDBSigner)(nil)

// ── OrgSignerCache ────────────────────────────────────────────────────────────

// OrgSignerCache provisions independent tenant keys and resolves their current
// signing/verification state. Global keys are used only in the explicit legacy
// mode for a tenant with no key, never after a load/decryption failure.
type OrgSignerCache struct {
	global        Signer
	mu            sync.RWMutex
	repo          *repository.SigningKeyRepository
	enc           *clavexcrypto.Encryptor
	autoProvision bool
}

// NewOrgSignerCache enables tenant-key provisioning and strict resolution.
func NewOrgSignerCache(global Signer, repo *repository.SigningKeyRepository, enc *clavexcrypto.Encryptor) *OrgSignerCache {
	return &OrgSignerCache{
		global:        global,
		repo:          repo,
		enc:           enc,
		autoProvision: true,
	}
}

// DisableAutoProvision reverts For() to the legacy behaviour of falling back to
// the shared global signer for orgs without a key. Intended for tests and
// staged rollout only; production should keep auto-provisioning on. Returns the
// receiver for chaining.
func (c *OrgSignerCache) DisableAutoProvision() *OrgSignerCache {
	c.mu.Lock()
	c.autoProvision = false
	c.mu.Unlock()
	return c
}

// NewOrgSignerCacheFromKEK is a convenience constructor for the key_backend=db case.
// It creates a SigningKeyRepository from pool and derives the Encryptor from kek.
func NewOrgSignerCacheFromKEK(pool *pgxpool.Pool, kek [32]byte, global Signer) *OrgSignerCache {
	return NewOrgSignerCache(
		global,
		repository.NewSigningKeyRepository(pool),
		clavexcrypto.NewEncryptorFromKey(kek),
	)
}

// For is retained for older internal callers. Request handlers use Resolve so
// errors can be returned without dereferencing an unavailable signer.
func (c *OrgSignerCache) For(ctx context.Context, orgID uuid.UUID) Signer {
	signer, err := c.Resolve(ctx, orgID)
	if err != nil {
		log.Error().Err(err).Msg("org signer unavailable")
		return nil
	}
	return signer
}

// Resolve rechecks database state on each request. A fresh immutable snapshot
// observes rotations from every replica and excludes keys after grace expiry.
// Database/decryption failures never silently select the installation key.
func (c *OrgSignerCache) Resolve(ctx context.Context, orgID uuid.UUID) (Signer, error) {
	signer, err := newOrgDBSigner(ctx, c.repo, c.enc, orgID)
	if err == nil {
		return signer, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	c.mu.RLock()
	auto := c.autoProvision
	c.mu.RUnlock()
	if !auto {
		return c.global, nil
	}
	tmp := &OrgDBSigner{repo: c.repo, enc: c.enc, orgID: orgID}
	_, kid, keyEnc, err := tmp.generateAndEncrypt()
	if err != nil {
		return nil, err
	}
	if _, err = c.repo.ReplaceForOrg(ctx, orgID, repository.OrgKeyReplacement{KID: kid, Algorithm: "PS256", KeyEnc: keyEnc, ProvisionOnly: true}); err != nil {
		return nil, err
	}
	return newOrgDBSigner(ctx, c.repo, c.enc, orgID)
}

// GenerateForOrg creates a new RSA-2048 signing key for orgID, persists it in
// the DB in one transaction, retaining the previous key during grace.
// Returns the new kid.
func (c *OrgSignerCache) GenerateForOrg(ctx context.Context, orgID uuid.UUID) (string, error) {
	return c.generateForOrg(ctx, orgID, true)
}

func (c *OrgSignerCache) generateForOrg(ctx context.Context, orgID uuid.UUID, protectImported bool) (string, error) {
	tmp := &OrgDBSigner{repo: c.repo, enc: c.enc, orgID: orgID}
	_, kid, keyEnc, err := tmp.generateAndEncrypt()
	if err != nil {
		return "", err
	}
	if _, err = c.repo.ReplaceForOrg(ctx, orgID, repository.OrgKeyReplacement{KID: kid, Algorithm: "PS256", KeyEnc: keyEnc, RejectImported: protectImported}); err != nil {
		return "", err
	}
	return kid, nil
}

// RotateForOrg rotates an org's OIDC signing key: it generates a fresh key,
// retiring the previous one into the JWKS grace window (via GenerateForOrg) so
// outstanding tokens stay verifiable. Used by the scheduled key-rotation worker.
func (c *OrgSignerCache) RotateForOrg(ctx context.Context, orgID uuid.UUID) (string, error) {
	return c.GenerateForOrg(ctx, orgID)
}

// ImportForOrg stores a caller-supplied RSA private key as the BYOK key for
// orgID. pkcs8DER must be a PKCS#8-encoded RSA private key (≥ 2048 bits).
// Returns the derived kid.
func (c *OrgSignerCache) ImportForOrg(ctx context.Context, orgID uuid.UUID, pkcs8DER []byte) (string, error) {
	key, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
	if err != nil {
		return "", fmt.Errorf("parse PKCS8 key: %w", err)
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key must be RSA, got %T", key)
	}
	if bits := priv.N.BitLen(); bits < 2048 {
		return "", fmt.Errorf("RSA key too short (%d bits); minimum 2048", bits)
	}

	kid := computeKID(&priv.PublicKey)
	keyEnc, err := c.enc.EncryptBytes(pkcs8DER)
	if err != nil {
		return "", fmt.Errorf("encrypt imported key: %w", err)
	}

	if _, err = c.repo.ReplaceForOrg(ctx, orgID, repository.OrgKeyReplacement{KID: kid, Algorithm: "PS256", KeyEnc: keyEnc, Source: "imported"}); err != nil {
		return "", err
	}

	return kid, nil
}

// RemoveForOrg restores a generated tenant key without deleting the retired
// keys needed to validate outstanding tokens. It never selects a global key.
func (c *OrgSignerCache) RemoveForOrg(ctx context.Context, orgID uuid.UUID) error {
	_, err := c.generateForOrg(ctx, orgID, false)
	return err
}
