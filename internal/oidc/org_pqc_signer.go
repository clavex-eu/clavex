package oidc

// org_pqc_signer.go — per-organisation Post-Quantum (ML-DSA-65) signing keys.
//
// This is the PQC mirror of OrgDBSigner / OrgSignerCache (org_signer.go): the
// same lazy cache, the same auto-provision-by-default behaviour, the same
// shared signing_keys table (pqc_algorithm IS NOT NULL, org_id scoping). Every
// organisation gets its own PQC key for free; there is no shared global PQC key
// for new orgs.
//
// Like the global PQCSigner it stays "passive": JWKObject publishes the org's
// single active PQC public key for discovery. It does not sign real tokens yet
// (pending IANA JWT PQC algorithm registration — see docs/PQC-ROADMAP.md). The
// per-org isolation is orthogonal to when signing becomes "real".

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	clavexcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// PQCKeyProvider is the read surface shared by the global *PQCSigner and a
// per-org *OrgPQCSigner, so the cache can return either interchangeably.
type PQCKeyProvider interface {
	KID() string
	JWKObject() []byte
	Sign(ctx context.Context, msg []byte) ([]byte, error)
	Verify(msg, sig []byte) bool
	PublicKeyBytes() []byte
}

// ── OrgPQCSigner ──────────────────────────────────────────────────────────────

// OrgPQCSigner implements PQCKeyProvider for a single organisation's ML-DSA-65
// key stored in the signing_keys table (org_id IS NOT NULL, pqc_algorithm set).
type OrgPQCSigner struct {
	mu     sync.RWMutex
	repo   *repository.SigningKeyRepository
	enc    *clavexcrypto.Encryptor
	orgID  uuid.UUID
	priv   *mldsa65.PrivateKey
	pub    *mldsa65.PublicKey
	kid    string
	jwkObj []byte
}

func newOrgPQCSigner(ctx context.Context, repo *repository.SigningKeyRepository, enc *clavexcrypto.Encryptor, orgID uuid.UUID) (*OrgPQCSigner, error) {
	s := &OrgPQCSigner{repo: repo, enc: enc, orgID: orgID}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *OrgPQCSigner) load(ctx context.Context) error {
	row, err := s.repo.GetActivePQCForOrg(ctx, s.orgID)
	if err != nil {
		return err // pgx.ErrNoRows if no org PQC key
	}

	priv, pub, err := s.decryptKey(row.KeyEnc)
	if err != nil {
		return fmt.Errorf("org pqc signer (org=%s): decrypt key (kid=%s): %w", s.orgID, row.KID, err)
	}

	s.mu.Lock()
	s.priv = priv
	s.pub = pub
	s.kid = row.KID
	s.jwkObj = buildPQCJWKObject(pub, row.KID)
	s.mu.Unlock()
	return nil
}

func (s *OrgPQCSigner) KID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kid
}

func (s *OrgPQCSigner) JWKObject() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwkObj
}

func (s *OrgPQCSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	s.mu.RLock()
	priv := s.priv
	s.mu.RUnlock()
	if priv == nil {
		return nil, errors.New("org pqc signer: no private key loaded")
	}
	var sig [mldsa65.SignatureSize]byte
	if err := mldsa65.SignTo(priv, msg, nil, true, sig[:]); err != nil {
		return nil, fmt.Errorf("org pqc signer: sign: %w", err)
	}
	return sig[:], nil
}

func (s *OrgPQCSigner) Verify(msg, sig []byte) bool {
	s.mu.RLock()
	pub := s.pub
	s.mu.RUnlock()
	return mldsa65.Verify(pub, msg, nil, sig)
}

func (s *OrgPQCSigner) PublicKeyBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pub.Bytes()
}

func (s *OrgPQCSigner) generateAndEncrypt() (*mldsa65.PublicKey, *mldsa65.PrivateKey, string, []byte, error) {
	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("generate ML-DSA-65 key: %w", err)
	}
	kid := computePQCKID(pub)
	keyEnc, err := s.enc.EncryptBytes(priv.Bytes())
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("encrypt PQC key: %w", err)
	}
	return pub, priv, kid, keyEnc, nil
}

func (s *OrgPQCSigner) decryptKey(keyEnc []byte) (*mldsa65.PrivateKey, *mldsa65.PublicKey, error) {
	raw, err := s.enc.DecryptBytes(keyEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt: %w", err)
	}
	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(raw); err != nil {
		return nil, nil, fmt.Errorf("unmarshal ML-DSA-65 private key: %w", err)
	}
	pub, ok := priv.Public().(*mldsa65.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected public key type %T", priv.Public())
	}
	return &priv, pub, nil
}

// Ensure both PQC signers satisfy the shared interface at compile time.
var (
	_ PQCKeyProvider = (*OrgPQCSigner)(nil)
	_ PQCKeyProvider = (*PQCSigner)(nil)
)

// ── OrgPQCSignerCache ─────────────────────────────────────────────────────────

// OrgPQCSignerCache lazily loads and caches per-org OrgPQCSigners.
//
// Per-org PQC isolation is the DEFAULT: the first time an org's PQC key is
// requested it is lazily provisioned (see For). The global *PQCSigner is only
// used as a fallback for transient errors, or when auto-provisioning has been
// explicitly disabled (tests / staged rollout).
type OrgPQCSignerCache struct {
	global        *PQCSigner
	mu            sync.RWMutex
	cache         map[uuid.UUID]*OrgPQCSigner
	repo          *repository.SigningKeyRepository
	enc           *clavexcrypto.Encryptor
	autoProvision bool
}

// NewOrgPQCSignerCache creates a cache backed by the given repository and
// encryptor. Auto-provisioning is on by default.
func NewOrgPQCSignerCache(global *PQCSigner, repo *repository.SigningKeyRepository, enc *clavexcrypto.Encryptor) *OrgPQCSignerCache {
	return &OrgPQCSignerCache{
		global:        global,
		cache:         make(map[uuid.UUID]*OrgPQCSigner),
		repo:          repo,
		enc:           enc,
		autoProvision: true,
	}
}

// NewOrgPQCSignerCacheFromKEK builds the cache from a raw KEK.
func NewOrgPQCSignerCacheFromKEK(pool *pgxpool.Pool, kek [32]byte, global *PQCSigner) *OrgPQCSignerCache {
	return NewOrgPQCSignerCache(
		global,
		repository.NewSigningKeyRepository(pool),
		clavexcrypto.NewEncryptorFromKey(kek),
	)
}

// DisableAutoProvision reverts For() to falling back to the shared global PQC
// signer for orgs without a key. Intended for tests / staged rollout only.
func (c *OrgPQCSignerCache) DisableAutoProvision() *OrgPQCSignerCache {
	c.mu.Lock()
	c.autoProvision = false
	c.mu.Unlock()
	return c
}

// For returns the org-specific PQC signer for orgID, provisioning one lazily if
// the org has none (auto-provision default). The global signer is only a
// fallback: transient load error, failed provision, or auto-provision disabled.
func (c *OrgPQCSignerCache) For(ctx context.Context, orgID uuid.UUID) PQCKeyProvider {
	c.mu.RLock()
	if s, ok := c.cache[orgID]; ok {
		c.mu.RUnlock()
		return s
	}
	auto := c.autoProvision
	c.mu.RUnlock()

	s, err := newOrgPQCSigner(ctx, c.repo, c.enc, orgID)
	if err == nil {
		c.mu.Lock()
		c.cache[orgID] = s
		c.mu.Unlock()
		return s
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("org_pqc_signer: load key")
		return c.global
	}

	if !auto {
		return c.global
	}

	if _, gerr := c.GenerateForOrg(ctx, orgID); gerr != nil {
		// Lost a race with a concurrent provision? Try to load the winner.
		if s2, lerr := newOrgPQCSigner(ctx, c.repo, c.enc, orgID); lerr == nil {
			c.mu.Lock()
			c.cache[orgID] = s2
			c.mu.Unlock()
			return s2
		}
		log.Error().Err(gerr).Str("org_id", orgID.String()).Msg("org_pqc_signer: auto-provision key")
		return c.global
	}

	c.mu.RLock()
	provisioned := c.cache[orgID]
	c.mu.RUnlock()
	if provisioned == nil {
		return c.global
	}
	return provisioned
}

// Invalidate drops the cached signer for orgID (forces a reload on next For).
func (c *OrgPQCSignerCache) Invalidate(orgID uuid.UUID) {
	c.mu.Lock()
	delete(c.cache, orgID)
	c.mu.Unlock()
}

// GenerateForOrg mints a fresh ML-DSA-65 key for orgID, retiring any existing
// one, and caches the new signer. Returns the new kid.
//
// Note: unlike OIDC there is no ImportForOrg. "Bring your own PQC key material"
// is deliberately out of scope while the PQC/JOSE standards are immature (no
// stable IANA algorithm, no interop for external ML-DSA custody); orgs get a
// generated key only. Revisit alongside dual-signing.
func (c *OrgPQCSignerCache) GenerateForOrg(ctx context.Context, orgID uuid.UUID) (string, error) {
	tmp := &OrgPQCSigner{repo: c.repo, enc: c.enc, orgID: orgID}
	pub, priv, kid, keyEnc, err := tmp.generateAndEncrypt()
	if err != nil {
		return "", err
	}

	// Retire any existing org PQC key first (partial unique index allows one).
	_ = c.repo.RetireActivePQCForOrg(ctx, orgID)

	if err := c.repo.InsertPQCForOrg(ctx, orgID, kid, PQCJWAAlgorithm, PQCAlgorithmMLDSA65, keyEnc, pub.Bytes()); err != nil {
		return "", fmt.Errorf("org pqc signer: insert generated key: %w", err)
	}

	tmp.mu.Lock()
	tmp.priv = priv
	tmp.pub = pub
	tmp.kid = kid
	tmp.jwkObj = buildPQCJWKObject(pub, kid)
	tmp.mu.Unlock()

	c.mu.Lock()
	c.cache[orgID] = tmp
	c.mu.Unlock()
	return kid, nil
}

// RotateForOrg rotates an org's PQC key (generate + retire old). Used by the
// scheduled key-rotation worker.
func (c *OrgPQCSignerCache) RotateForOrg(ctx context.Context, orgID uuid.UUID) (string, error) {
	return c.GenerateForOrg(ctx, orgID)
}
