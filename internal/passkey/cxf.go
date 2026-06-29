// Package passkey implements the FIDO Alliance Credential Exchange Format (CXF)
// for passkey portability between password managers and identity providers.
//
// Specification reference: https://fidoalliance.org/specs/fido-2-0-id-20180227/
// and the 2023/2024 Credential Exchange draft.
//
// Security design:
//   - AES-256-GCM authenticated encryption prevents tampering.
//   - PBKDF2-SHA256 with 600 000 iterations (NIST SP 800-63B compliant).
//   - A fresh 32-byte salt and 12-byte nonce are generated per export.
//   - No private-key material ever leaves the authenticator hardware;
//     this package only handles the server-side registration records.
package passkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	cxfVersion          = "1.0"
	cxfEncryptedVersion = "clavex-cxf-1.0"
	cxfAlgorithm        = "AES-256-GCM"
	cxfKDF              = "PBKDF2-SHA256"
	kdfIterations       = 600_000
	saltSize            = 32
	nonceSize           = 12 // 96-bit GCM nonce
	keySize             = 32 // 256-bit AES key
)

// ─── CXF plain-text document ────────────────────────────────────────

// Document is the top-level CXF plain-text envelope.
type Document struct {
	Type        string       `json:"type"`         // "credential-exchange"
	Version     string       `json:"version"`      // "1.0"
	Title       string       `json:"title"`        // human label
	ExportedAt  time.Time    `json:"exported_at"`
	Issuer      string       `json:"issuer"`       // RP base URL
	Credentials []Credential `json:"credentials"`
}

// Credential is a single passkey entry in the CXF document.
// It contains only the server-side registration record; the private key
// never leaves the authenticator.
type Credential struct {
	// WebAuthn fields.
	Type            string   `json:"type"`              // "webauthn.create"
	CredentialID    string   `json:"credential_id"`     // base64url
	UserHandle      string   `json:"user_handle"`       // base64url opaque user ID
	UserName        string   `json:"user_name"`
	UserDisplayName string   `json:"user_display_name"`
	RPID            string   `json:"rp_id"`
	RPName          string   `json:"rp_name,omitempty"`
	PublicKey       string   `json:"public_key"`        // base64url COSE-encoded
	Algorithm       int      `json:"algorithm"`         // COSE algorithm e.g. -7 (ES256)
	AAGUID          string   `json:"aaguid,omitempty"`
	Transports      []string `json:"transports,omitempty"`
	SignCount        uint32   `json:"sign_count"`

	// Clavex metadata.
	Name       string     `json:"name"`                    // user-given credential name
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	IsImported bool       `json:"is_imported"`
}

// ─── Encrypted bundle ────────────────────────────────────────────────

// EncryptedBundle wraps a CXF document in AES-256-GCM encryption.
// The recipient must supply the same password to decrypt.
type EncryptedBundle struct {
	Type       string `json:"type"`       // "credential-exchange-encrypted"
	Version    string `json:"version"`    // "clavex-cxf-1.0"
	Algorithm  string `json:"algorithm"`  // "AES-256-GCM"
	KDF        string `json:"kdf"`        // "PBKDF2-SHA256"
	Iterations int    `json:"iterations"` // 600 000
	Salt       string `json:"salt"`       // base64url, 32 bytes
	IV         string `json:"iv"`         // base64url, 12 bytes
	Ciphertext string `json:"ciphertext"` // base64url, authenticated ciphertext + tag
}

// ─── Encryption helpers ──────────────────────────────────────────────

// Encrypt serialises doc to JSON and encrypts it with AES-256-GCM,
// deriving the key from password via PBKDF2-SHA256.
func Encrypt(doc *Document, password string) (*EncryptedBundle, error) {
	plaintext, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("cxf: marshal: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("cxf: rand salt: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cxf: rand nonce: %w", err)
	}

	key := deriveKey(password, salt)
	ciphertext, err := aesgcmEncrypt(key, nonce, plaintext)
	if err != nil {
		return nil, fmt.Errorf("cxf: encrypt: %w", err)
	}

	return &EncryptedBundle{
		Type:       "credential-exchange-encrypted",
		Version:    cxfEncryptedVersion,
		Algorithm:  cxfAlgorithm,
		KDF:        cxfKDF,
		Iterations: kdfIterations,
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

// Decrypt unwraps an EncryptedBundle using password.
func Decrypt(bundle *EncryptedBundle, password string) (*Document, error) {
	salt, err := base64.RawURLEncoding.DecodeString(bundle.Salt)
	if err != nil {
		return nil, fmt.Errorf("cxf: decode salt: %w", err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(bundle.IV)
	if err != nil {
		return nil, fmt.Errorf("cxf: decode nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(bundle.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("cxf: decode ciphertext: %w", err)
	}

	key := deriveKey(password, salt)
	plaintext, err := aesgcmDecrypt(key, nonce, ciphertext)
	if err != nil {
		// Return a generic error to avoid oracle attacks.
		return nil, fmt.Errorf("cxf: decryption failed — wrong password or corrupted file")
	}

	var doc Document
	if err := json.Unmarshal(plaintext, &doc); err != nil {
		return nil, fmt.Errorf("cxf: parse decrypted document: %w", err)
	}
	return &doc, nil
}

// ─── Low-level crypto ────────────────────────────────────────────────

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, kdfIterations, keySize, sha256.New)
}

func aesgcmEncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Seal appends ciphertext || GCM-tag to dst.
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

func aesgcmDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ─── Document constructors ────────────────────────────────────────────

// NewDocument returns an empty CXF document.
func NewDocument(title, issuer string) *Document {
	return &Document{
		Type:        "credential-exchange",
		Version:     cxfVersion,
		Title:       title,
		ExportedAt:  time.Now().UTC(),
		Issuer:      issuer,
		Credentials: []Credential{},
	}
}
