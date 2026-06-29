// Package crypto provides AES-256-GCM authenticated encryption for secrets
// stored in the database (LDAP bind passwords, SCIM push bearer tokens,
// webhook signing secrets).
//
// Wire format (base64url-encoded, no padding):
//
//	<version(1)> <nonce(12)> <ciphertext+tag(n+16)>
//
// Version byte is always 0x01 so we can migrate to a new scheme in the future
// without breaking existing ciphertext.
//
// Key derivation: SHA-256(adminSecret) → 32-byte AES key. This avoids storing a
// separate key while producing a stable, size-correct key from any AdminSecret.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const (
	versionByte = byte(0x01)
	nonceSize   = 12
)

// Encryptor encrypts and decrypts short secret strings (passwords, tokens).
// It is safe for concurrent use.
type Encryptor struct {
	key [32]byte
}

// NewEncryptor creates an Encryptor whose key is SHA-256(masterSecret).
// masterSecret should be at least 32 bytes of entropy (e.g. auth.admin_secret).
func NewEncryptor(masterSecret string) *Encryptor {
	return &Encryptor{key: sha256.Sum256([]byte(masterSecret))}
}

// Encrypt returns a compact, versioned, base64url ciphertext string.
// The plaintext may be empty — the result is still authenticated.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key[:])
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Layout: version(1) | nonce(12) | ciphertext+tag(n+16)
	buf := make([]byte, 1+nonceSize+len(ct))
	buf[0] = versionByte
	copy(buf[1:], nonce)
	copy(buf[1+nonceSize:], ct)

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Decrypt decodes and authenticates a ciphertext produced by Encrypt.
// Returns the original plaintext or an error if the ciphertext is invalid or tampered.
func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	// Support legacy plaintext values (not yet migrated).
	// Heuristic: a valid encrypted value is base64url and starts with
	// the encoded version byte. Anything not matching is returned as-is.
	// After running the migration all values will be encrypted.
	buf, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil || len(buf) < 1+nonceSize+16 || buf[0] != versionByte {
		// Not our format — return plaintext as-is (pre-migration value).
		return ciphertext, nil
	}

	block, err := aes.NewCipher(e.key[:])
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonce := buf[1 : 1+nonceSize]
	ct := buf[1+nonceSize:]

	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: authentication failed")
	}
	return string(plain), nil
}

// IsEncrypted returns true if the string looks like a value produced by Encrypt.
// Useful in migration scripts to skip already-encrypted values.
func IsEncrypted(s string) bool {
	if s == "" {
		return false
	}
	buf, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(buf) >= 1+nonceSize+16 && buf[0] == versionByte
}

// NeedsEncryption returns true when the value is a non-empty plaintext that has
// not yet been encrypted. Inverse of IsEncrypted, ignoring the empty string case.
func NeedsEncryption(s string) bool {
	return s != "" && !IsEncrypted(s) && !strings.HasPrefix(s, "$argon2") // never re-encrypt password hashes
}

// NewEncryptorFromKey creates an Encryptor from a raw 32-byte AES key without
// any additional key derivation. Use when the caller already holds a
// cryptographically strong key (e.g. a KEK from configuration).
func NewEncryptorFromKey(key [32]byte) *Encryptor {
	return &Encryptor{key: key}
}

// EncryptBytes encrypts arbitrary binary data with AES-256-GCM and returns the
// wire format: nonce(12) || ciphertext+tag.  This is intended for BYTEA
// columns in the database (e.g. encrypted private key material).
func (e *Encryptor) EncryptBytes(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key[:])
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, plaintext, nil)

	buf := make([]byte, nonceSize+len(ct))
	copy(buf, nonce)
	copy(buf[nonceSize:], ct)
	return buf, nil
}

// DecryptBytes decrypts binary data produced by EncryptBytes.
func (e *Encryptor) DecryptBytes(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize+16 {
		return nil, fmt.Errorf("decrypt: ciphertext too short")
	}

	block, err := aes.NewCipher(e.key[:])
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]

	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: authentication failed")
	}
	return plain, nil
}
