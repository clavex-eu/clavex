package middleware

// Per-org rate limiting using a Redis sliding-window counter.
//
// Key schema:
//   clavex:rl:{org_slug}:{kind}:{identifier}
//
// where:
//   kind        = "login" | "token" | "global"
//   identifier  = IP address (for login/global) or client_id (for token)
//
// The window is always 60 seconds. The limit is looked up from the
// org_rate_limits table (via the repository), with a short in-process cache
// to avoid one DB round-trip per request.
//
// If Redis is unavailable the middleware allows the request through and logs
// a warning — rate limiting is a best-effort control, not a hard dependency.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	rlPrefix   = "clavex:rl:"
	windowSecs = 60
	cacheTTL   = 30 * time.Second // how long to cache per-org limits in memory
)

// OrgRateLimiter holds the Redis client and an in-process cache of per-org limits.
type OrgRateLimiter struct {
	rdb   redis.UniversalClient
	repo  *repository.LoginHistoryRepository
	mu    sync.RWMutex
	cache map[uuid.UUID]*cachedLimits
}

type cachedLimits struct {
	loginPerIPPerMin     int
	tokenPerClientPerMin int
	globalPerIPPerMin    int
	endpointLimits       map[string]int // path key → req/min; nil = not loaded
	expiresAt            time.Time
}

// NewOrgRateLimiter creates a limiter backed by Redis and the DB for config.
func NewOrgRateLimiter(rdb redis.UniversalClient, repo *repository.LoginHistoryRepository) *OrgRateLimiter {
	return &OrgRateLimiter{
		rdb:   rdb,
		repo:  repo,
		cache: make(map[uuid.UUID]*cachedLimits),
	}
}

// OrgLoginRateLimit returns an Echo middleware that enforces the per-org login
// rate limit (login attempts per IP per minute).
//
// orgSlugParam is the Echo route parameter name that carries the org slug
// (e.g. "org_slug" for /:org_slug/authorize).
// orgIDResolver resolves the slug to a UUID; it may be nil for paths where
// the orgID is already available in the context (admin routes use :org_id).
func (l *OrgRateLimiter) OrgLoginRateLimit(orgSlugParam string, resolve OrgResolver) echo.MiddlewareFunc {
	return l.orgRateLimit(orgSlugParam, resolve, "login", func(lim *cachedLimits) int {
		return lim.loginPerIPPerMin
	}, func(c echo.Context) string {
		return c.RealIP()
	})
}

// OrgTokenRateLimit enforces the per-org token endpoint rate limit.
func (l *OrgRateLimiter) OrgTokenRateLimit(orgSlugParam string, resolve OrgResolver) echo.MiddlewareFunc {
	return l.orgRateLimit(orgSlugParam, resolve, "token", func(lim *cachedLimits) int {
		return lim.tokenPerClientPerMin
	}, func(c echo.Context) string {
		// Use client_id form param as identifier (falls back to IP).
		if cid := c.FormValue("client_id"); cid != "" {
			return cid
		}
		return c.RealIP()
	})
}

// OrgGlobalRateLimit enforces the per-org global rate limit for any endpoint.
func (l *OrgRateLimiter) OrgGlobalRateLimit(orgSlugParam string, resolve OrgResolver) echo.MiddlewareFunc {
	return l.orgRateLimit(orgSlugParam, resolve, "global", func(lim *cachedLimits) int {
		return lim.globalPerIPPerMin
	}, func(c echo.Context) string {
		return c.RealIP()
	})
}

// OrgEndpointRateLimit returns an Echo middleware that enforces a per-endpoint
// rate limit configured in the org_rate_limits.endpoint_limits JSONB column.
//
// endpointKey is the key used in the JSONB map, e.g. "/elevate" or "/oid4vci/offers".
// If no limit is configured for the key, the middleware is a no-op (allows all requests).
// The identifier is always the client IP address.
func (l *OrgRateLimiter) OrgEndpointRateLimit(endpointKey, orgSlugParam string, resolve OrgResolver) echo.MiddlewareFunc {
	return l.orgRateLimit(orgSlugParam, resolve, "ep:"+endpointKey, func(lim *cachedLimits) int {
		if lim.endpointLimits == nil {
			return 0 // no endpoint limits configured — allow all
		}
		return lim.endpointLimits[endpointKey] // 0 = not configured = allow all
	}, func(c echo.Context) string {
		return c.RealIP()
	})
}

// OrgResolver maps an org slug (from the URL path) to a UUID.
// It is provided by the server wiring to avoid a circular dependency on the
// repository package from within the middleware package.
type OrgResolver func(ctx context.Context, slug string) (uuid.UUID, error)

// orgRateLimit is the shared implementation.
func (l *OrgRateLimiter) orgRateLimit(
	orgSlugParam string,
	resolve OrgResolver,
	kind string,
	getLimit func(*cachedLimits) int,
	getIdentifier func(echo.Context) string,
) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()

			// Resolve org UUID.
			var orgID uuid.UUID
			if resolve != nil {
				slug := c.Param(orgSlugParam)
				if slug == "" {
					return next(c)
				}
				id, err := resolve(ctx, slug)
				if err != nil {
					// Unknown org — let the handler return 404.
					return next(c)
				}
				orgID = id
			} else {
				// Direct org_id param (admin routes).
				id, err := uuid.Parse(c.Param(orgSlugParam))
				if err != nil {
					return next(c)
				}
				orgID = id
			}

			limits := l.getLimits(ctx, orgID)
			maxReq := getLimit(limits)
			if maxReq <= 0 {
				// No limit configured for this endpoint — allow.
				return next(c)
			}
			identifier := getIdentifier(c)
			key := fmt.Sprintf("%s%s:%s:%s", rlPrefix, orgID, kind, identifier)
			allowed, remaining, err := l.slidingWindow(ctx, key, maxReq)
			if err != nil {
				// Redis unavailable — allow through, log warning.
				log.Warn().Err(err).Str("key", key).Msg("rate-limit redis error; allowing request")
				return next(c)
			}

			c.Response().Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", maxReq))
			c.Response().Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			c.Response().Header().Set("X-RateLimit-Window", fmt.Sprintf("%ds", windowSecs))

			if !allowed {
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":             "too_many_requests",
					"error_description": fmt.Sprintf("rate limit exceeded: max %d requests per %d seconds", maxReq, windowSecs),
				})
			}
			return next(c)
		}
	}
}

// getLimits returns the cached limits for an org, refreshing from DB if stale.
func (l *OrgRateLimiter) getLimits(ctx context.Context, orgID uuid.UUID) *cachedLimits {
	l.mu.RLock()
	if cached, ok := l.cache[orgID]; ok && time.Now().Before(cached.expiresAt) {
		l.mu.RUnlock()
		return cached
	}
	l.mu.RUnlock()

	// Cache miss or expired — fetch from DB.
	rl, err := l.repo.GetOrgRateLimits(ctx, orgID)
	if err != nil || rl == nil {
		// Return defaults.
		return &cachedLimits{
			loginPerIPPerMin:     10,
			tokenPerClientPerMin: 60,
			globalPerIPPerMin:    120,
		}
	}

	c := &cachedLimits{
		loginPerIPPerMin:     rl.LoginPerIPPerMin,
		tokenPerClientPerMin: rl.TokenPerClientPerMin,
		globalPerIPPerMin:    rl.GlobalPerIPPerMin,
		endpointLimits:       rl.EndpointLimits,
		expiresAt:            time.Now().Add(cacheTTL),
	}
	l.mu.Lock()
	l.cache[orgID] = c
	l.mu.Unlock()
	return c
}

// slidingWindow implements a true Redis sliding-window counter using a sorted
// set keyed on the request timestamp (nanoseconds as score).
//
// Algorithm:
//   1. ZADD key NX <now_ns> <now_ns>   — record this request
//   2. ZREMRANGEBYSCORE key 0 <cutoff> — evict entries older than windowSecs
//   3. ZCARD key                       — count remaining entries
//   4. EXPIRE key windowSecs           — auto-clean the key after inactivity
//
// All four commands run in a single pipeline to minimise round-trips.
// Unlike INCR+EXPIRE this approach cannot be burst-attacked at window reset.
func (l *OrgRateLimiter) slidingWindow(ctx context.Context, key string, limit int) (bool, int, error) {
	now := time.Now().UnixNano()
	cutoff := float64(now - int64(windowSecs)*int64(time.Second))
	score := float64(now)
	member := strconv.FormatInt(now, 10)

	pipe := l.rdb.Pipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: score, Member: member})
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatFloat(cutoff, 'f', 0, 64))
	cardCmd := pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, windowSecs*time.Second)

	if _, err := pipe.Exec(ctx); err != nil {
		return true, limit, err
	}

	count := int(cardCmd.Val())
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	return count <= limit, remaining, nil
}

// InvalidateOrgCache removes a cached org limit entry, forcing a DB re-read
// on next request. Call this from the rate-limit config update endpoint.
func (l *OrgRateLimiter) InvalidateOrgCache(orgID uuid.UUID) {
	l.mu.Lock()
	delete(l.cache, orgID)
	l.mu.Unlock()
}
