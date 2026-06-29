package oidc

// OrgSignerCache manages per-organisation signing keys (BYOK).
//
// When an organisation has registered its own RSA signing key via the BYOK API,
// the OIDCHandler uses that key instead of the global installation key.
// The cache avoids a database round-trip on every token issuance.
//
// Usage:
//   cache := NewOrgSignerCache(globalSigner, signingKeyRepo, encryptor)
//   signer := cache.For(ctx, org.ID)   // returns org key or global fallback

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
	mu         sync.RWMutex
	repo       *repository.SigningKeyRepository
	enc        *clavexcrypto.Encryptor
	orgID      uuid.UUID
	privateKey *rsa.PrivateKey
	kid        string
	jwks       []byte
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

	s.mu.Lock()
	s.privateKey = priv
	s.kid = row.KID
	s.jwks = jwksJSON
	s.mu.Unlock()
	return nil
}

// Rotate generates a new RSA-2048 key for this org, retires the old one, and
// reloads the in-memory state.
func (s *OrgDBSigner) Rotate() error {
	ctx := context.Background()

	priv, kid, keyEnc, err := s.generateAndEncrypt()
	if err != nil {
		return fmt.Errorf("org signer: rotate generate key: %w", err)
	}

	if err := s.repo.RetireActiveForOrg(ctx, s.orgID); err != nil {
		return fmt.Errorf("org signer: retire active key: %w", err)
	}
	if err := s.repo.InsertForOrg(ctx, s.orgID, kid, "PS256", keyEnc); err != nil {
		return fmt.Errorf("org signer: insert new key: %w", err)
	}

	jwksJSON, err := s.buildJWKSFromDB(ctx)
	if err != nil {
		return fmt.Errorf("org signer: rebuild JWKS after rotate: %w", err)
	}

	s.mu.Lock()
	s.privateKey = priv
	s.kid = kid
	s.jwks = jwksJSON
	s.mu.Unlock()
	return nil
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

// OrgSignerCache lazily loads and caches per-org OrgDBSigners.
// Callers receive the global Signer for orgs that have not registered a BYOK key.
type OrgSignerCache struct {
	global Signer
	mu     sync.RWMutex
	cache  map[uuid.UUID]*OrgDBSigner
	repo   *repository.SigningKeyRepository
	enc    *clavexcrypto.Encryptor
}

// NewOrgSignerCache creates a cache backed by the given repository and encryptor.
// global is returned for any org that has no own signing key.
func NewOrgSignerCache(global Signer, repo *repository.SigningKeyRepository, enc *clavexcrypto.Encryptor) *OrgSignerCache {
	return &OrgSignerCache{
		global: global,
		cache:  make(map[uuid.UUID]*OrgDBSigner),
		repo:   repo,
		enc:    enc,
	}
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

// For returns the org-specific Signer if the org has a BYOK key, otherwise the
// global Signer. The result is cached after the first successful load.
func (c *OrgSignerCache) For(ctx context.Context, orgID uuid.UUID) Signer {
	c.mu.RLock()
	if s, ok := c.cache[orgID]; ok {
		c.mu.RUnlock()
		return s
	}
	c.mu.RUnlock()

	s, err := newOrgDBSigner(ctx, c.repo, c.enc, orgID)
	if err != nil {
		// org has no own key (pgx.ErrNoRows) or transient DB error — use global
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Str("org_id", orgID.String()).Msg("org_signer: load key")
		}
		return c.global
	}

	c.mu.Lock()
	c.cache[orgID] = s
	c.mu.Unlock()
	return s
}

// Invalidate removes an org's entry from the cache so that the next call to
// For() reloads from the database. Call this after uploading or rotating a
// BYOK key.
func (c *OrgSignerCache) Invalidate(orgID uuid.UUID) {
	c.mu.Lock()
	delete(c.cache, orgID)
	c.mu.Unlock()
}

// GenerateForOrg creates a new RSA-2048 signing key for orgID, persists it in
// the DB (retiring any previous org key first), and updates the cache.
// Returns the new kid.
func (c *OrgSignerCache) GenerateForOrg(ctx context.Context, orgID uuid.UUID) (string, error) {
	// Temporary signer to reuse generateAndEncrypt helper.
	tmp := &OrgDBSigner{repo: c.repo, enc: c.enc, orgID: orgID}
	priv, kid, keyEnc, err := tmp.generateAndEncrypt()
	if err != nil {
		return "", err
	}

	// Retire any existing org key first.
	_ = c.repo.RetireActiveForOrg(ctx, orgID)

	if err := c.repo.InsertForOrg(ctx, orgID, kid, "PS256", keyEnc); err != nil {
		return "", fmt.Errorf("org signer: insert generated key: %w", err)
	}

	// Build JWKS for new key only (grace period keys will be loaded next time).
	jwksJSON, err := buildJWKS(&priv.PublicKey, kid)
	if err != nil {
		return "", fmt.Errorf("org signer: build JWKS: %w", err)
	}

	tmp.mu.Lock()
	tmp.privateKey = priv
	tmp.kid = kid
	tmp.jwks = jwksJSON
	tmp.mu.Unlock()

	c.mu.Lock()
	c.cache[orgID] = tmp
	c.mu.Unlock()
	return kid, nil
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

	_ = c.repo.RetireActiveForOrg(ctx, orgID)

	if err := c.repo.InsertForOrg(ctx, orgID, kid, "PS256", keyEnc); err != nil {
		return "", fmt.Errorf("org signer: insert imported key: %w", err)
	}

	jwksJSON, err := buildJWKS(&priv.PublicKey, kid)
	if err != nil {
		return "", fmt.Errorf("org signer: build JWKS: %w", err)
	}

	s := &OrgDBSigner{repo: c.repo, enc: c.enc, orgID: orgID}
	s.privateKey = priv
	s.kid = kid
	s.jwks = jwksJSON

	c.mu.Lock()
	c.cache[orgID] = s
	c.mu.Unlock()
	return kid, nil
}

// RemoveForOrg hard-deletes all signing keys for an org (reverts to global key).
func (c *OrgSignerCache) RemoveForOrg(ctx context.Context, orgID uuid.UUID) error {
	if err := c.repo.DeleteAllForOrg(ctx, orgID); err != nil {
		return err
	}
	c.Invalidate(orgID)
	return nil
}
