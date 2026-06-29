// Package lockout implements Clavex Guard — adaptive login lockout whose
// duration scales with the real-time risk score.
//
// # How it works
//
//  1. Before password verification the handler calls [Guard.IsLocked].
//     If a lockout key exists in Redis the login is rejected with a human-readable
//     "try again in N minutes" message without revealing whether the account exists.
//
//  2. After a failed password the handler calls [Guard.RecordFailure] passing the
//     current risk score (0-100).  The score is mapped to a "band" that defines
//     how many failures trigger a lockout and for how long.
//
//  3. After a successful login the handler calls [Guard.ClearFailures] to reset
//     the counter so legitimate users are never permanently penalised.
//
// # Redis key schema
//
//	clavex:guard:{orgID}:{emailHash}:fails  — INCR counter; expire = maxLockout + 5 min
//	clavex:guard:{orgID}:{emailHash}:locked — presence = locked; TTL = lockout duration
//
// The email is hashed with SHA-256 so it is never stored in plain text in Redis.
//
// # Default bands (override per-org via PUT /api/v1/organizations/:id/lockout)
//
//	score   0–29  → 5 failures  → 30 s
//	score  30–59  → 3 failures  → 5 min
//	score  60–79  → 2 failures  → 15 min
//	score  80–100 → 1 failure   → 60 min + optional admin alert
package lockout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// Band maps a risk-score range to a lockout policy.
type Band struct {
	ScoreMin    int `json:"score_min"`
	ScoreMax    int `json:"score_max"`
	MaxAttempts int `json:"max_attempts"`
	LockoutSecs int `json:"lockout_seconds"`
}

// DefaultBands is the fallback policy used when an org has no custom config.
var DefaultBands = []Band{
	{ScoreMin: 0, ScoreMax: 29, MaxAttempts: 5, LockoutSecs: 30},
	{ScoreMin: 30, ScoreMax: 59, MaxAttempts: 3, LockoutSecs: 300},
	{ScoreMin: 60, ScoreMax: 79, MaxAttempts: 2, LockoutSecs: 900},
	{ScoreMin: 80, ScoreMax: 100, MaxAttempts: 1, LockoutSecs: 3600},
}

// BandsLoader is the function signature used to load per-org lockout bands.
// Guard stores a reference to this function; the concrete implementation lives
// in repository.LockoutRepository to avoid a circular import.
// A nil function makes Guard use DefaultBands for every org.
type BandsLoader func(ctx context.Context, orgID string) []Band

const (
	failsKeyFmt  = "clavex:guard:%s:%s:fails"
	lockedKeyFmt = "clavex:guard:%s:%s:locked"
)

// Guard is the Redis-backed lockout service. Create one with [New] and share it
// for the lifetime of the process.
type Guard struct {
	rdb    redis.UniversalClient
	loader BandsLoader // may be nil → DefaultBands always used
}

// New creates a Guard. loader may be nil; in that case DefaultBands are used
// for every organization.
func New(rdb redis.UniversalClient, loader BandsLoader) *Guard {
	return &Guard{rdb: rdb, loader: loader}
}

// emailHash returns a short, deterministic Redis-safe key derived from the
// (orgID, email) pair. The email is lower-cased before hashing so
// "User@Example.com" and "user@example.com" map to the same bucket.
func (g *Guard) emailHash(orgID, email string) string {
	h := sha256.Sum256([]byte(orgID + ":" + strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(h[:16]) // 32 hex chars — collision probability negligible
}

func (g *Guard) bands(ctx context.Context, orgID string) []Band {
	if g.loader != nil {
		return g.loader(ctx, orgID)
	}
	return DefaultBands
}

// bandForScore returns the band whose score range contains score.
// Falls back to the highest-score band if none matches (defensive).
func bandForScore(bands []Band, score int) Band {
	for _, b := range bands {
		if score >= b.ScoreMin && score <= b.ScoreMax {
			return b
		}
	}
	if len(bands) > 0 {
		return bands[len(bands)-1]
	}
	return DefaultBands[0]
}

// maxLockoutDuration returns the longest lockout across all bands.
func maxLockoutDuration(bands []Band) time.Duration {
	max := 0
	for _, b := range bands {
		if b.LockoutSecs > max {
			max = b.LockoutSecs
		}
	}
	return time.Duration(max) * time.Second
}

// IsLocked returns (remaining, true) when the account is locked, or (0, false)
// when it is free. Errors are absorbed and treated as "not locked" (fail-open).
func (g *Guard) IsLocked(ctx context.Context, orgID, email string) (time.Duration, bool) {
	key := fmt.Sprintf(lockedKeyFmt, orgID, g.emailHash(orgID, email))
	ttl, err := g.rdb.TTL(ctx, key).Result()
	if err != nil {
		log.Warn().Err(err).Msg("lockout: redis TTL error; treating as unlocked")
		return 0, false
	}
	if ttl > 0 {
		return ttl, true
	}
	return 0, false
}

// RecordFailure increments the failure counter for the (orgID, email) pair and
// applies a lockout if the band threshold is exceeded.
//
// riskScore is the 0-100 score from risk.Scorer (pass 0 when unavailable — the
// lowest band is still applied so an attacker with a clean IP gets 5 attempts).
//
// Returns the lockout duration that was just applied (0 = not yet locked).
// Errors are absorbed (fail-open) so a Redis outage never blocks the auth flow.
func (g *Guard) RecordFailure(ctx context.Context, orgID, email string, riskScore int) time.Duration {
	hash := g.emailHash(orgID, email)
	failsKey := fmt.Sprintf(failsKeyFmt, orgID, hash)
	lockedKey := fmt.Sprintf(lockedKeyFmt, orgID, hash)

	bands := g.bands(ctx, orgID)
	band := bandForScore(bands, riskScore)

	count, err := g.rdb.Incr(ctx, failsKey).Result()
	if err != nil {
		log.Warn().Err(err).Msg("lockout: redis INCR error; skipping lockout")
		return 0
	}

	// Keep the counter alive long enough to outlast the longest possible lockout.
	maxExp := maxLockoutDuration(bands) + 5*time.Minute
	g.rdb.Expire(ctx, failsKey, maxExp) //nolint:errcheck

	if int(count) >= band.MaxAttempts {
		dur := time.Duration(band.LockoutSecs) * time.Second
		if err := g.rdb.Set(ctx, lockedKey, "1", dur).Err(); err != nil {
			log.Warn().Err(err).Msg("lockout: redis SET error; lockout not applied")
			return 0
		}
		return dur
	}
	return 0
}

// ClearFailures removes both the failure counter and any active lockout key.
// Call this on every successful login so legitimate users never accumulate
// historical failures that would trigger a future lockout.
func (g *Guard) ClearFailures(ctx context.Context, orgID, email string) {
	hash := g.emailHash(orgID, email)
	g.rdb.Del(ctx, //nolint:errcheck
		fmt.Sprintf(failsKeyFmt, orgID, hash),
		fmt.Sprintf(lockedKeyFmt, orgID, hash),
	)
}

// FormatDuration formats a lockout duration into a human-readable message.
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		secs := int(d.Seconds())
		if secs == 1 {
			return "1 second"
		}
		return fmt.Sprintf("%d seconds", secs)
	}
	mins := int(d.Minutes())
	if mins == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", mins)
}
