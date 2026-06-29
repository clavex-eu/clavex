package session

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestOTPIdentHash_DeterministicAndCaseInsensitive(t *testing.T) {
	a := otpIdentHash("org1", "User@Example.com")
	b := otpIdentHash("org1", "  user@example.com ")
	require.Equal(t, a, b, "hash must be case- and whitespace-insensitive")
	require.NotEqual(t, a, otpIdentHash("org2", "user@example.com"), "different org must not collide")
	require.Len(t, a, 32) // 16 bytes hex
}

// OTPSendAllowed exercises Redis SetNX/INCR/TTL, so it needs a real Redis.
// Skipped unless TEST_REDIS_URL is set (e.g. redis://localhost:6379/1).
func otpRedis(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set; skipping Redis-backed OTP throttle test")
	}
	opt, err := redis.ParseURL(url)
	require.NoError(t, err)
	c := redis.NewClient(opt)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestOTPSendAllowed_CooldownAndHourlyCap(t *testing.T) {
	rdb := otpRedis(t)
	store := NewStore(rdb)
	ctx := context.Background()
	org := uuid.NewString()
	email := "idor-" + uuid.NewString() + "@e.com"

	// First send allowed.
	ok, _ := store.OTPSendAllowed(ctx, "email", org, email)
	require.True(t, ok)

	// Immediate resend refused by the min-interval cooldown.
	ok, retry := store.OTPSendAllowed(ctx, "email", org, email)
	require.False(t, ok)
	require.Greater(t, retry.Seconds(), 0.0)

	// A different address is independent.
	ok, _ = store.OTPSendAllowed(ctx, "email", org, "other-"+email)
	require.True(t, ok)

	// Hourly cap: clear the cooldown key between attempts to simulate elapsed
	// intervals, and confirm the (otpSendHourlyCap+1)-th send is refused.
	idh := otpIdentHash(org, email)
	cdKey := prefixOTPSendCD + "email:" + org + ":" + idh
	allowedCount := 1 // first send above already counted toward the hourly cap
	for i := 0; i < otpSendHourlyCap+2; i++ {
		rdb.Del(ctx, cdKey)
		if ok, _ := store.OTPSendAllowed(ctx, "email", org, email); ok {
			allowedCount++
		}
	}
	require.Equal(t, otpSendHourlyCap, allowedCount, "no more than the hourly cap may be allowed")
}
