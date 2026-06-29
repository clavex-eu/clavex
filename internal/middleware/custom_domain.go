package middleware

// CustomDomainResolver resolves an incoming Host header to the org_id that
// owns that custom domain.  Active custom domains are cached in Redis to avoid
// a DB round-trip on every request.
//
// Cache key schema:  clavex:custom_domain:{hostname}  → org_id (UUID string)
// Cache TTL:         5 minutes (refreshed on cache miss)
// Negative TTL:      30 seconds for unknown/inactive domains (avoids DB hammering)
//
// When a matching active domain is found, the context key "custom_domain_org_id"
// is set on the Echo context.  Downstream handlers can read it via
// GetCustomDomainOrgID(c).
//
// If the Host does not match any active custom domain, the middleware is a
// no-op — the request falls through to the normal :org_slug routing.

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	customDomainCacheTTL    = 5 * time.Minute
	customDomainNegativeTTL = 30 * time.Second
	customDomainNotFound    = "__not_found__"
)

const customDomainOrgKey contextKey = "custom_domain_org_id"

// CustomDomainResolver looks up the Host header against active custom domains.
type CustomDomainResolver struct {
	repo *repository.CustomDomainRepository
	rdb  redis.UniversalClient
}

// NewCustomDomainResolver creates a resolver backed by pool and rdb.
func NewCustomDomainResolver(repo *repository.CustomDomainRepository, rdb redis.UniversalClient) *CustomDomainResolver {
	return &CustomDomainResolver{repo: repo, rdb: rdb}
}

// Middleware returns an Echo middleware that resolves custom domains.
func (r *CustomDomainResolver) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			host := normaliseHost(c.Request().Host)
			if host == "" {
				return next(c)
			}

			orgID, err := r.resolve(c.Request().Context(), host)
			if err != nil || orgID == uuid.Nil {
				// Not a custom domain — pass through.
				return next(c)
			}

			c.Set(string(customDomainOrgKey), orgID)
			return next(c)
		}
	}
}

// GetCustomDomainOrgID retrieves the custom-domain org_id from the Echo context.
// Returns uuid.Nil if the request did not arrive via a custom domain.
func GetCustomDomainOrgID(c echo.Context) uuid.UUID {
	v := c.Get(string(customDomainOrgKey))
	if id, ok := v.(uuid.UUID); ok {
		return id
	}
	return uuid.Nil
}

// resolve returns the org_id for a given hostname, using Redis as a cache.
func (r *CustomDomainResolver) resolve(ctx context.Context, host string) (uuid.UUID, error) {
	cacheKey := "clavex:custom_domain:" + host

	// Check Redis cache first.
	cached, err := r.rdb.Get(ctx, cacheKey).Result()
	if err == nil {
		if cached == customDomainNotFound {
			return uuid.Nil, nil
		}
		id, parseErr := uuid.Parse(cached)
		if parseErr == nil {
			return id, nil
		}
	}

	// Cache miss — query the database.
	domain, dbErr := r.repo.GetByDomain(ctx, host)
	if errors.Is(dbErr, pgx.ErrNoRows) {
		// Cache the negative result.
		_ = r.rdb.Set(ctx, cacheKey, customDomainNotFound, customDomainNegativeTTL).Err()
		return uuid.Nil, nil
	}
	if dbErr != nil {
		log.Warn().Err(dbErr).Str("host", host).Msg("custom domain lookup error")
		return uuid.Nil, dbErr
	}

	if domain.Status != "active" {
		_ = r.rdb.Set(ctx, cacheKey, customDomainNotFound, customDomainNegativeTTL).Err()
		return uuid.Nil, nil
	}

	// Cache the positive result.
	_ = r.rdb.Set(ctx, cacheKey, domain.OrgID.String(), customDomainCacheTTL).Err()
	return domain.OrgID, nil
}

// normaliseHost strips the port from a Host header value and lower-cases it.
func normaliseHost(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		// No port — use as-is.
		h = host
	}
	return strings.ToLower(strings.TrimSpace(h))
}
