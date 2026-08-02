package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── generateDeviceSecret ─────────────────────────────────────────────────────

func TestGenerateDeviceSecret_Format(t *testing.T) {
	raw, err := generateDeviceSecret()
	require.NoError(t, err)
	// 32 random bytes hex-encoded = 64 lowercase hex characters.
	assert.Len(t, raw, 64)
	assert.Regexp(t, `^[0-9a-f]{64}$`, raw)
}

func TestGenerateDeviceSecret_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		raw, err := generateDeviceSecret()
		require.NoError(t, err)
		seen[raw] = struct{}{}
	}
	assert.Len(t, seen, 200, "200 draws from a 256-bit space must never collide")
}

// ── hashDeviceSecret ─────────────────────────────────────────────────────────

func TestHashDeviceSecret_Deterministic(t *testing.T) {
	h1 := hashDeviceSecret("abc123")
	h2 := hashDeviceSecret("abc123")
	assert.Equal(t, h1, h2)
}

func TestHashDeviceSecret_IsSHA256Hex(t *testing.T) {
	h := hashDeviceSecret("abc123")
	assert.Len(t, h, 64)
	assert.Regexp(t, `^[0-9a-f]{64}$`, h)

	sum := sha256.Sum256([]byte("abc123"))
	assert.Equal(t, hex.EncodeToString(sum[:]), h)
}

func TestHashDeviceSecret_DifferentInputsDifferentHashes(t *testing.T) {
	assert.NotEqual(t, hashDeviceSecret("secret-a"), hashDeviceSecret("secret-b"))
}

// ── DeviceEnrollmentSecret.VerifySecret ──────────────────────────────────────
//
// secretHash is unexported and populated only by LockPendingSecretForDeviceTx
// in production; tests in this package can set it directly to exercise
// VerifySecret without a database.

func TestVerifySecret_CorrectSecretMatches(t *testing.T) {
	raw := "the-one-time-bootstrap-secret"
	s := DeviceEnrollmentSecret{secretHash: hashDeviceSecret(raw)}
	assert.True(t, s.VerifySecret(raw))
}

func TestVerifySecret_WrongSecretDoesNotMatch(t *testing.T) {
	s := DeviceEnrollmentSecret{secretHash: hashDeviceSecret("the-real-secret")}
	assert.False(t, s.VerifySecret("a-guessed-secret"))
}

func TestVerifySecret_EmptyGuessDoesNotMatchNonEmptyHash(t *testing.T) {
	s := DeviceEnrollmentSecret{secretHash: hashDeviceSecret("the-real-secret")}
	assert.False(t, s.VerifySecret(""))
}
