package oidc

// EncKeySet manages the OP's request-object encryption key: an RSA key whose
// public half is published in the OP JWKS with use=enc so relying parties can
// encrypt their JAR request objects (RFC 9101 §6.2, OpenID Federation §12) to
// it, and whose private half decrypts those JWEs at the authorization endpoint.
//
// It mirrors DBSigner: the private key is stored in the signing_keys table
// (key_use='enc') encrypted at rest with AES-256-GCM under the KEK. On startup
// the active key is loaded, or a fresh RSA-2048 key is generated and persisted
// so the server starts without manual provisioning.
//
// Rotate() retires the active key and promotes a new one. Retired keys are kept
// (within the grace window) only for DECRYPTION: an RP that already fetched the
// previously published key may still encrypt to it until it re-reads the OP
// JWKS. Only the active key is published, so new RPs always use the current key.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	clavexcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

// EncKeyAlgorithm is the JWE key-management algorithm advertised and used for
// request-object encryption. RSA-OAEP-256 (RSAES-OAEP w/ SHA-256) is the FAPI
// and OpenID Federation recommended asymmetric key-wrap algorithm.
const EncKeyAlgorithm = "RSA-OAEP-256"

// EncContentAlgorithm is the JWE content-encryption algorithm advertised in OP
// metadata (request_object_encryption_enc_values_supported).
const EncContentAlgorithm = "A256GCM"

// EncKeySet holds the OP's active request-object encryption key plus any
// retired keys still within the decryption grace window. Safe for concurrent use.
type EncKeySet struct {
	mu   sync.RWMutex
	repo *repository.SigningKeyRepository
	enc  *clavexcrypto.Encryptor // AES-256-GCM with the KEK

	activeKey *rsa.PrivateKey
	kid       string
	// decryptKeys holds the active key plus retired-within-grace keys, newest
	// first, so an in-flight request object encrypted to a just-rotated key
	// still decrypts.
	decryptKeys []*rsa.PrivateKey
	jwkObject   []byte // single active public JWK object (use=enc) for JWKS merge
}

// NewEncKeySet creates an EncKeySet backed by pool, using kek (32 raw bytes) to
// encrypt/decrypt the RSA private key stored in the database.
func NewEncKeySet(ctx context.Context, pool *pgxpool.Pool, kek [32]byte) (*EncKeySet, error) {
	s := &EncKeySet{
		repo: repository.NewSigningKeyRepository(pool),
		enc:  clavexcrypto.NewEncryptorFromKey(kek),
	}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads the active encryption key (and the grace-window decrypt set) from
// the database, bootstrapping a fresh key if none exists.
func (s *EncKeySet) load(ctx context.Context) error {
	row, err := s.repo.GetActiveEnc(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.bootstrap(ctx)
	}
	if err != nil {
		return fmt.Errorf("enc keyset: load active key: %w", err)
	}

	priv, err := s.decryptKeyBlob(row.KeyEnc)
	if err != nil {
		return fmt.Errorf("enc keyset: decrypt active key (kid=%s): %w", row.KID, err)
	}

	decryptKeys, err := s.loadDecryptKeys(ctx)
	if err != nil {
		return fmt.Errorf("enc keyset: load decrypt keys: %w", err)
	}

	s.mu.Lock()
	s.activeKey = priv
	s.kid = row.KID
	s.decryptKeys = decryptKeys
	s.jwkObject = buildEncJWKObject(&priv.PublicKey, row.KID)
	s.mu.Unlock()
	return nil
}

// bootstrap generates a fresh RSA-2048 key and stores it as the first active
// encryption key.
func (s *EncKeySet) bootstrap(ctx context.Context) error {
	priv, kid, keyEnc, err := s.generateAndEncrypt()
	if err != nil {
		return fmt.Errorf("enc keyset: bootstrap generate key: %w", err)
	}

	if err := s.repo.InsertEnc(ctx, kid, EncKeyAlgorithm, keyEnc); err != nil {
		return fmt.Errorf("enc keyset: bootstrap insert key: %w", err)
	}

	s.mu.Lock()
	s.activeKey = priv
	s.kid = kid
	s.decryptKeys = []*rsa.PrivateKey{priv}
	s.jwkObject = buildEncJWKObject(&priv.PublicKey, kid)
	s.mu.Unlock()
	return nil
}

// Rotate retires the current active encryption key and promotes a freshly
// generated one. The retired key remains in the decrypt set for the grace
// window so request objects encrypted to the old public key still decrypt.
func (s *EncKeySet) Rotate(ctx context.Context) error {
	priv, kid, keyEnc, err := s.generateAndEncrypt()
	if err != nil {
		return fmt.Errorf("enc keyset: rotate generate key: %w", err)
	}

	if err := s.repo.RetireActiveEnc(ctx); err != nil {
		return fmt.Errorf("enc keyset: rotate retire active key: %w", err)
	}

	if err := s.repo.InsertEnc(ctx, kid, EncKeyAlgorithm, keyEnc); err != nil {
		return fmt.Errorf("enc keyset: rotate insert new key: %w", err)
	}

	decryptKeys, err := s.loadDecryptKeys(ctx)
	if err != nil {
		return fmt.Errorf("enc keyset: rotate reload decrypt keys: %w", err)
	}

	s.mu.Lock()
	s.activeKey = priv
	s.kid = kid
	s.decryptKeys = decryptKeys
	s.jwkObject = buildEncJWKObject(&priv.PublicKey, kid)
	s.mu.Unlock()
	return nil
}

// DecryptJWE decrypts a compact JWE request object, trying the active key first
// and then any retired-within-grace keys. It returns the decrypted plaintext
// (the inner signed/unsecured request-object JWT) as a string.
func (s *EncKeySet) DecryptJWE(compact string) (string, error) {
	s.mu.RLock()
	keys := s.decryptKeys
	s.mu.RUnlock()

	if len(keys) == 0 {
		return "", errors.New("enc keyset: no decryption key available")
	}

	buf := []byte(compact)
	var lastErr error
	for _, priv := range keys {
		// Accept both RSA-OAEP-256 (advertised) and RSA-OAEP for leniency; the
		// JWE header selects the actual algorithm.
		for _, alg := range []jwa.KeyEncryptionAlgorithm{jwa.RSA_OAEP_256, jwa.RSA_OAEP} {
			plaintext, err := jwe.Decrypt(buf, jwe.WithKey(alg, priv))
			if err == nil {
				return string(plaintext), nil
			}
			lastErr = err
		}
	}
	return "", fmt.Errorf("enc keyset: decrypt request object: %w", lastErr)
}

// KID returns the key identifier of the active encryption key.
func (s *EncKeySet) KID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kid
}

// JWKObject returns the active encryption public key as a single JWK JSON object
// (use=enc). Callers merge it into the OP JWKS via MergeJWKS.
func (s *EncKeySet) JWKObject() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwkObject
}

// ── internal ──────────────────────────────────────────────────────────────────

// loadDecryptKeys fetches all enc keys in the grace window (active + retired)
// and returns their decrypted RSA private keys for the decrypt set.
func (s *EncKeySet) loadDecryptKeys(ctx context.Context) ([]*rsa.PrivateKey, error) {
	rows, err := s.repo.GetEncJWKSKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]*rsa.PrivateKey, 0, len(rows))
	for _, row := range rows {
		priv, err := s.decryptKeyBlob(row.KeyEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt key (kid=%s): %w", row.KID, err)
		}
		keys = append(keys, priv)
	}
	return keys, nil
}

func (s *EncKeySet) generateAndEncrypt() (*rsa.PrivateKey, string, []byte, error) {
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

func (s *EncKeySet) decryptKeyBlob(keyEnc []byte) (*rsa.PrivateKey, error) {
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
		return nil, fmt.Errorf("encryption key must be RSA, got %T", key)
	}
	return priv, nil
}

// buildEncJWKObject serialises an RSA public key as a single JWK JSON object
// tagged use=enc with the advertised key-management algorithm.
func buildEncJWKObject(pub *rsa.PublicKey, kid string) []byte {
	enc := func(i *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(i.Bytes())
	}
	var sb strings.Builder
	e := big.NewInt(int64(pub.E))
	fmt.Fprintf(&sb, `{"kty":"RSA","use":"enc","alg":%q,"kid":%q,"n":%q,"e":%q}`,
		EncKeyAlgorithm, kid, enc(pub.N), enc(e))
	return []byte(sb.String())
}
