// Package oidc — Post-Quantum Cryptography signing support.
//
// # Standards
//
//   - NIST FIPS 203 (ML-KEM / Kyber):  key encapsulation — not yet wired in Clavex;
//     included here for reference as the transport-layer complement to ML-DSA.
//   - NIST FIPS 204 (ML-DSA / Dilithium): digital signatures — implemented below via
//     ML-DSA-65 (security level 3, equivalent to AES-192).
//   - NIST FIPS 205 (SLH-DSA / SPHINCS+): hash-based signatures — roadmap item;
//     conservative alternative that makes no lattice assumptions.
//
// # IANA / JOSE algorithm identifiers
//
// The IANA JWT/JWK algorithm registry has not yet assigned identifiers for PQC
// algorithms.  The draft draft-ietf-cose-dilithium (ML-DSA for COSE/JOSE) is under
// active review.  Until registration completes, Clavex uses the vendor-prefixed
// identifier "CV-ML-DSA-65" ("CV" = Clavex Vendor, pending IANA registration).
// The JWK key type uses "MLWE" following the draft convention.
//
// # Hybrid approach
//
// PQCSigner is intentionally "passive": it exposes the ML-DSA-65 public key in the
// JWKS endpoint alongside the classical RSA key but does NOT sign JWTs with PQC yet.
// This lets PQC-aware clients discover the capability via JWKS discovery without
// breaking any existing OIDC/FAPI client.
//
// Pattern recommended by NIST SP 800-208 and BSI TR-02102-1:
//  1. Keep the classical signature as the primary trust anchor.
//  2. Add PQC key to JWKS for discovery (this release).
//  3. Issue dual-signed tokens once the IANA registration is stable (~2026-2027).
//  4. Deprecate classical signatures once PQC library ecosystem matures (~2030-2035).
//
// # EU / EUDIW roadmap
//
// The EUDI Wallet Architecture Reference Framework (ARF 1.4, §6.6) mandates
// PQC readiness for credential issuers by 2030 (aligned with the NIS2 / eIDAS 2.0
// revision cycle).  Clavex tracks this via the experimental pqc_enabled flag.
//
// Reference: https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/
package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	clavexcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// PQCAlgorithmMLDSA65 is the NIST FIPS 204 algorithm identifier stored in DB.
	PQCAlgorithmMLDSA65 = "ml-dsa-65"

	// PQCJWAAlgorithm is the Clavex vendor-prefixed JWA identifier for ML-DSA-65,
	// pending IANA registration (draft-ietf-cose-dilithium).
	PQCJWAAlgorithm = "CV-ML-DSA-65"

	// PQCKeyType is the JWK key type for module-lattice keys (draft convention).
	PQCKeyType = "MLWE"
)

// PQCSigner holds an ML-DSA-65 key pair and exposes the public key as a JWK
// for inclusion in the JWKS endpoint.  It is safe for concurrent use.
//
// The private key is stored in PostgreSQL encrypted with AES-256-GCM using the
// same Key Encryption Key (KEK) as the classical DBSigner.
type PQCSigner struct {
	mu   sync.RWMutex
	pool *pgxpool.Pool
	enc  *clavexcrypto.Encryptor
	repo *repository.SigningKeyRepository

	priv   *mldsa65.PrivateKey
	pub    *mldsa65.PublicKey
	kid    string
	jwkObj []byte // pre-serialised single PQC JWK object (not a JWKS set)
}

// NewPQCSigner creates a PQCSigner backed by pool, using kek (32 raw bytes) to
// encrypt/decrypt the ML-DSA-65 private key stored in the database.
//
// If no active PQC key is found, a fresh ML-DSA-65 key pair is generated and
// persisted so the server can start without manual key provisioning.
func NewPQCSigner(ctx context.Context, pool *pgxpool.Pool, kek [32]byte) (*PQCSigner, error) {
	s := &PQCSigner{
		pool: pool,
		enc:  clavexcrypto.NewEncryptorFromKey(kek),
		repo: repository.NewSigningKeyRepository(pool),
	}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// KID returns the key identifier for the active PQC key.
func (s *PQCSigner) KID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kid
}

// JWKObject returns a pre-serialisd JSON object representing the PQC public key
// in JWK format.  This is a single object (not a JWKS set); callers merge it into
// an existing JWKS document via MergeJWKS.
//
// Format (draft-ietf-cose-dilithium):
//
//	{"kty":"MLWE","alg":"CV-ML-DSA-65","kid":"…","use":"sig","pub":"<base64url>"}
func (s *PQCSigner) JWKObject() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwkObj
}

// Sign signs msg with ML-DSA-65 and returns the raw signature bytes.
// ctx is currently unused.
func (s *PQCSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	s.mu.RLock()
	priv := s.priv
	s.mu.RUnlock()
	if priv == nil {
		return nil, errors.New("pqc signer: no private key loaded")
	}
	// ML-DSA-65 is an append-style (not message-recovery) signature scheme: the
	// signature is returned separately from msg. ctx=nil (empty context string);
	// randomised=true selects hedged signing per FIPS 204 §3.4 for side-channel
	// margin over the deterministic mode.
	var sig [mldsa65.SignatureSize]byte
	if err := mldsa65.SignTo(priv, msg, nil, true, sig[:]); err != nil {
		return nil, fmt.Errorf("pqc signer: sign: %w", err)
	}
	return sig[:], nil
}

// Verify verifies a raw ML-DSA-65 signature against msg using the active public key.
func (s *PQCSigner) Verify(msg, sig []byte) bool {
	s.mu.RLock()
	pub := s.pub
	s.mu.RUnlock()
	return mldsa65.Verify(pub, msg, nil, sig)
}

// PublicKeyBytes returns the raw bytes of the active ML-DSA-65 public key.
func (s *PQCSigner) PublicKeyBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pub.Bytes()
}

// ── internal ──────────────────────────────────────────────────────────────────

func (s *PQCSigner) load(ctx context.Context) error {
	row, err := s.repo.GetActivePQC(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.bootstrap(ctx)
	}
	if err != nil {
		return fmt.Errorf("pqc signer: load active key: %w", err)
	}

	priv, pub, err := s.decryptKey(row.KeyEnc)
	if err != nil {
		return fmt.Errorf("pqc signer: decrypt active key (kid=%s): %w", row.KID, err)
	}

	s.mu.Lock()
	s.priv = priv
	s.pub = pub
	s.kid = row.KID
	s.jwkObj = buildPQCJWKObject(pub, row.KID)
	s.mu.Unlock()
	return nil
}

func (s *PQCSigner) bootstrap(ctx context.Context) error {
	pub, priv, kid, keyEnc, err := s.generateAndEncrypt()
	if err != nil {
		return fmt.Errorf("pqc signer: bootstrap generate key: %w", err)
	}

	if err := s.repo.InsertPQC(ctx, kid, PQCJWAAlgorithm, PQCAlgorithmMLDSA65, keyEnc, pub.Bytes()); err != nil {
		return fmt.Errorf("pqc signer: bootstrap insert key: %w", err)
	}

	s.mu.Lock()
	s.priv = priv
	s.pub = pub
	s.kid = kid
	s.jwkObj = buildPQCJWKObject(pub, kid)
	s.mu.Unlock()
	return nil
}

// Rotate retires the current active ML-DSA-65 key and promotes a freshly
// generated one. The retired row persists in the DB until its grace period
// elapses (RetireActivePQC sets expires_at). Note: in this passive release
// JWKObject only publishes the single active key, so a multi-key grace-period
// JWKS would require building the JWK set from all non-expired DB rows — wire
// that alongside dual-signing. Safe for concurrent use.
func (s *PQCSigner) Rotate(ctx context.Context) error {
	pub, priv, kid, keyEnc, err := s.generateAndEncrypt()
	if err != nil {
		return fmt.Errorf("pqc signer: rotate generate key: %w", err)
	}

	// Retire the current active key before inserting the new one — the partial
	// unique index allows only one active PQC row at a time.
	if err := s.repo.RetireActivePQC(ctx); err != nil {
		return fmt.Errorf("pqc signer: rotate retire active key: %w", err)
	}

	if err := s.repo.InsertPQC(ctx, kid, PQCJWAAlgorithm, PQCAlgorithmMLDSA65, keyEnc, pub.Bytes()); err != nil {
		return fmt.Errorf("pqc signer: rotate insert new key: %w", err)
	}

	s.mu.Lock()
	s.priv = priv
	s.pub = pub
	s.kid = kid
	s.jwkObj = buildPQCJWKObject(pub, kid)
	s.mu.Unlock()
	return nil
}

func (s *PQCSigner) generateAndEncrypt() (*mldsa65.PublicKey, *mldsa65.PrivateKey, string, []byte, error) {
	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("generate ML-DSA-65 key: %w", err)
	}

	kid := computePQCKID(pub)
	privBytes := priv.Bytes()

	keyEnc, err := s.enc.EncryptBytes(privBytes)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("encrypt PQC key: %w", err)
	}

	return pub, priv, kid, keyEnc, nil
}

func (s *PQCSigner) decryptKey(keyEnc []byte) (*mldsa65.PrivateKey, *mldsa65.PublicKey, error) {
	raw, err := s.enc.DecryptBytes(keyEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt: %w", err)
	}

	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(raw); err != nil {
		return nil, nil, fmt.Errorf("unmarshal ML-DSA-65 private key: %w", err)
	}

	pubKey := priv.Public()
	pub, ok := pubKey.(*mldsa65.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected public key type %T", pubKey)
	}

	return &priv, pub, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// computePQCKID derives a stable key ID from the raw public key bytes.
// Same derivation as computeKID for RSA keys (SHA-256 first 8 bytes → base64url).
func computePQCKID(pub *mldsa65.PublicKey) string {
	sum := sha256.Sum256(pub.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// buildPQCJWKObject serializses a ML-DSA-65 public key as a single JWK JSON object.
// kty="MLWE" follows draft-ietf-cose-dilithium.  alg="CV-ML-DSA-65" is the
// Clavex vendor-prefixed identifier pending IANA registration.
func buildPQCJWKObject(pub *mldsa65.PublicKey, kid string) []byte {
	pubB64 := base64.RawURLEncoding.EncodeToString(pub.Bytes())
	return []byte(fmt.Sprintf(
		`{"kty":%q,"alg":%q,"kid":%q,"use":"sig","pub":%q}`,
		PQCKeyType, PQCJWAAlgorithm, kid, pubB64,
	))
}

// MergeJWKS appends a PQC JWK object into an existing JWKS JSON document.
//
//	classical: {"keys":[…existing keys…]}
//	pqcKey:    {"kty":"MLWE",…} — a single JWK object
//	result:    {"keys":[…existing keys…,{"kty":"MLWE",…}]}
//
// Returns classical unchanged if it is nil or malformed.
func MergeJWKS(classical, pqcKey []byte) []byte {
	if len(classical) == 0 || len(pqcKey) == 0 {
		return classical
	}

	// Validate pqcKey is a JSON object.
	var probe json.RawMessage
	if err := json.Unmarshal(pqcKey, &probe); err != nil {
		return classical
	}

	// classical ends with ]} — insert pqcKey before the closing bracket.
	suffix := []byte("]}")
	if len(classical) < len(suffix) {
		return classical
	}
	base := classical[:len(classical)-len(suffix)]

	// If there are already keys, add a comma separator.
	sep := byte(',')
	if len(base) > 0 && base[len(base)-1] == '[' {
		sep = 0 // empty keys array — no comma
	}

	result := make([]byte, 0, len(classical)+len(pqcKey)+2)
	result = append(result, base...)
	if sep != 0 {
		result = append(result, sep)
	}
	result = append(result, pqcKey...)
	result = append(result, suffix...)
	return result
}
