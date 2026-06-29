package passkey

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── NewDocument ───────────────────────────────────────────────────────────────

func TestNewDocument_Fields(t *testing.T) {
	doc := NewDocument("My Passkeys", "https://example.com")
	assert.Equal(t, "credential-exchange", doc.Type)
	assert.Equal(t, cxfVersion, doc.Version)
	assert.Equal(t, "My Passkeys", doc.Title)
	assert.Equal(t, "https://example.com", doc.Issuer)
	assert.Empty(t, doc.Credentials)
	assert.WithinDuration(t, time.Now().UTC(), doc.ExportedAt, 5*time.Second)
}

// ── Encrypt / Decrypt round-trip ──────────────────────────────────────────────

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	doc := NewDocument("Export", "https://id.example.com")
	doc.Credentials = append(doc.Credentials, Credential{
		Type:         "webauthn.create",
		CredentialID: "abc123",
		UserName:     "alice",
		RPID:         "example.com",
		PublicKey:    "coseKeyBase64",
		Algorithm:    -7,
		SignCount:     42,
		Name:         "My YubiKey",
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
	})

	bundle, err := Encrypt(doc, "correct-horse-battery-staple")
	require.NoError(t, err)
	require.NotNil(t, bundle)

	got, err := Decrypt(bundle, "correct-horse-battery-staple")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, doc.Type, got.Type)
	assert.Equal(t, doc.Title, got.Title)
	assert.Equal(t, doc.Issuer, got.Issuer)
	require.Len(t, got.Credentials, 1)
	assert.Equal(t, "alice", got.Credentials[0].UserName)
	assert.Equal(t, "coseKeyBase64", got.Credentials[0].PublicKey)
	assert.EqualValues(t, 42, got.Credentials[0].SignCount)
}

func TestEncryptDecrypt_WrongPassword_Fails(t *testing.T) {
	doc := NewDocument("Test", "https://example.com")
	bundle, err := Encrypt(doc, "correct-password")
	require.NoError(t, err)

	_, err = Decrypt(bundle, "wrong-password")
	assert.Error(t, err, "decryption with wrong password must fail")
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestEncryptDecrypt_EmptyDocument(t *testing.T) {
	doc := NewDocument("Empty", "https://example.com")
	bundle, err := Encrypt(doc, "pw")
	require.NoError(t, err)

	got, err := Decrypt(bundle, "pw")
	require.NoError(t, err)
	assert.Empty(t, got.Credentials)
}

// ── EncryptedBundle fields ────────────────────────────────────────────────────

func TestEncryptBundle_MetadataFields(t *testing.T) {
	doc := NewDocument("Meta", "https://example.com")
	bundle, err := Encrypt(doc, "pw")
	require.NoError(t, err)

	assert.Equal(t, "credential-exchange-encrypted", bundle.Type)
	assert.Equal(t, cxfEncryptedVersion, bundle.Version)
	assert.Equal(t, cxfAlgorithm, bundle.Algorithm)
	assert.Equal(t, cxfKDF, bundle.KDF)
	assert.Equal(t, kdfIterations, bundle.Iterations)
	assert.NotEmpty(t, bundle.Salt)
	assert.NotEmpty(t, bundle.IV)
	assert.NotEmpty(t, bundle.Ciphertext)
}

func TestEncryptBundle_UniqueNonceAndSaltPerCall(t *testing.T) {
	doc := NewDocument("Nonce", "https://example.com")
	b1, err := Encrypt(doc, "pw")
	require.NoError(t, err)
	b2, err := Encrypt(doc, "pw")
	require.NoError(t, err)

	assert.NotEqual(t, b1.Salt, b2.Salt, "each Encrypt call must use a fresh salt")
	assert.NotEqual(t, b1.IV, b2.IV, "each Encrypt call must use a fresh nonce")
	assert.NotEqual(t, b1.Ciphertext, b2.Ciphertext, "different nonce/salt → different ciphertext")
}

func TestEncryptBundle_IsValidJSON(t *testing.T) {
	doc := NewDocument("JSON", "https://example.com")
	bundle, err := Encrypt(doc, "pw")
	require.NoError(t, err)

	raw, err := json.Marshal(bundle)
	require.NoError(t, err)
	assert.True(t, json.Valid(raw))
}

// ── Tamper resistance ─────────────────────────────────────────────────────────

func TestDecrypt_TamperedCiphertext_Fails(t *testing.T) {
	doc := NewDocument("Tamper", "https://example.com")
	bundle, err := Encrypt(doc, "pw")
	require.NoError(t, err)

	// Flip a byte in the middle of the base64url ciphertext.
	ct := []byte(bundle.Ciphertext)
	ct[len(ct)/2] ^= 0xFF
	bundle.Ciphertext = string(ct)

	_, err = Decrypt(bundle, "pw")
	assert.Error(t, err, "tampered ciphertext must fail GCM authentication")
}

func TestDecrypt_TamperedSalt_Fails(t *testing.T) {
	doc := NewDocument("Tamper", "https://example.com")
	bundle, err := Encrypt(doc, "pw")
	require.NoError(t, err)

	// Change the salt → wrong key derived → decryption fails.
	original := bundle.Salt
	bundle.Salt = strings.Repeat("A", len(original))

	_, err = Decrypt(bundle, "pw")
	assert.Error(t, err)
}

func TestDecrypt_InvalidBase64Salt_Fails(t *testing.T) {
	bundle := &EncryptedBundle{Salt: "not-valid-base64!!!", IV: "YWJj", Ciphertext: "YWJj"}
	_, err := Decrypt(bundle, "pw")
	assert.Error(t, err)
}

func TestDecrypt_InvalidBase64IV_Fails(t *testing.T) {
	bundle := &EncryptedBundle{Salt: "YWJj", IV: "not-valid-base64!!!", Ciphertext: "YWJj"}
	_, err := Decrypt(bundle, "pw")
	assert.Error(t, err)
}

// ── deriveKey / aesgcm ────────────────────────────────────────────────────────

func TestDeriveKey_Length(t *testing.T) {
	key := deriveKey("password", []byte("saltsaltsaltsaltsaltsaltsaltsalt"))
	assert.Len(t, key, keySize, "derived key must be 32 bytes for AES-256")
}

func TestDeriveKey_Deterministic(t *testing.T) {
	salt := []byte("fixed-salt-value-fixed-salt-valu")
	k1 := deriveKey("password", salt)
	k2 := deriveKey("password", salt)
	assert.Equal(t, k1, k2)
}

func TestDeriveKey_DifferentPasswords(t *testing.T) {
	salt := []byte("fixed-salt-value-fixed-salt-valu")
	k1 := deriveKey("password1", salt)
	k2 := deriveKey("password2", salt)
	assert.NotEqual(t, k1, k2)
}

func TestAesgcmEncryptDecrypt(t *testing.T) {
	salt := make([]byte, saltSize)
	key := deriveKey("pw", salt)
	nonce := make([]byte, nonceSize)
	plaintext := []byte("hello world")

	ciphertext, err := aesgcmEncrypt(key, nonce, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := aesgcmDecrypt(key, nonce, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
