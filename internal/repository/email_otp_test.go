package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── generateSixDigitCode ──────────────────────────────────────────────────────

func TestGenerateSixDigitCode_Format(t *testing.T) {
	re := regexp.MustCompile(`^\d{6}$`)
	for i := 0; i < 100; i++ {
		code, err := generateSixDigitCode()
		require.NoError(t, err)
		assert.True(t, re.MatchString(code),
			"code %q must be exactly 6 decimal digits", code)
	}
}

func TestGenerateSixDigitCode_Range(t *testing.T) {
	const iterations = 1000
	for i := 0; i < iterations; i++ {
		code, err := generateSixDigitCode()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, code, "000000")
		assert.LessOrEqual(t, code, "999999")
	}
}

func TestGenerateSixDigitCode_Uniqueness(t *testing.T) {
	// With a 10^6 key space, 200 draws have a birthday-collision probability of
	// < 2% — a flaky-free threshold for detecting a broken RNG.
	seen := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		code, err := generateSixDigitCode()
		require.NoError(t, err)
		seen[code] = struct{}{}
	}
	assert.Greater(t, len(seen), 50, "200 codes should not collapse to 50 unique values")
}

// ── hashEmailOTP ─────────────────────────────────────────────────────────────

func TestHashEmailOTP_Deterministic(t *testing.T) {
	h1 := hashEmailOTP("123456")
	h2 := hashEmailOTP("123456")
	assert.Equal(t, h1, h2, "same input must always produce the same hash")
}

func TestHashEmailOTP_IsSHA256Hex(t *testing.T) {
	h := hashEmailOTP("000000")
	// SHA-256 hex is always exactly 64 lowercase hex characters.
	assert.Len(t, h, 64)
	assert.Regexp(t, `^[0-9a-f]{64}$`, h)

	// Cross-check against stdlib.
	sum := sha256.Sum256([]byte("000000"))
	expected := hex.EncodeToString(sum[:])
	assert.Equal(t, expected, h)
}

func TestHashEmailOTP_DifferentCodes(t *testing.T) {
	// Two different codes must produce different hashes — trivial but catches
	// a constant-return bug.
	assert.NotEqual(t, hashEmailOTP("000000"), hashEmailOTP("999999"))
}
