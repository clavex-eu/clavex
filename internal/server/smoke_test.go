package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// Fixed KEK so reruns against the same TEST_DATABASE_URL can decrypt the
// signing key bootstrapped on the first run.
var smokeKEK = [32]byte{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
}

// TestOrgScopedEndpointsNo500 is a smoke test over the real router: it hits
// every org-scoped GET endpoint with a seeded org and a super-admin token and
// asserts none return 5xx. It catches the class of bugs that compile fine but
// blow up at runtime — bad SQL (wrong table/column), nil derefs, panics — which
// unit tests and `go vet` miss (e.g. the lifecycle-report query against a
// non-existent table).
//
// 4xx is acceptable (missing sub-resource, unsupported query); 501 is too
// (a feature deliberately disabled on this server). Only 500/502/503/504 fail.
// Requires a migrated Postgres and a Redis; skipped otherwise.
//
//	TEST_DATABASE_URL=postgres://... TEST_REDIS_URL=redis://localhost:6379 \
//	  go test ./internal/server/ -run TestOrgScopedEndpointsNo500
func TestOrgScopedEndpointsNo500(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL required; skipping HTTP smoke test")
	}
	ctx := context.Background()

	poolCfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	// Mirror the app pool: migration 000017 moves tables into the identity /
	// sessions / audit schemas; without this search_path a raw DSN sees only
	// `public` and every query fails with "relation does not exist".
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path = identity, sessions, audit, public`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	ropt, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	rdb := redis.NewClient(ropt)
	t.Cleanup(func() { _ = rdb.Close() })

	keys, err := oidc.NewDBSigner(ctx, pool, smokeKEK)
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.Auth.AdminSecret = "smoke-test-admin-secret-at-least-32ch!!"

	srv := New(cfg, pool, rdb, keys)

	org, err := repository.NewOrgRepository(pool).Create(
		ctx, "smoke-"+uuid.NewString(), "smoke-"+uuid.NewString(), nil)
	require.NoError(t, err)

	// super_admin bypasses RequireOrgAccess and per-resource permission checks.
	claims := jwt.MapClaims{
		"sub":            uuid.NewString(),
		"email":          "smoke@example.com",
		"org_id":         org.ID.String(),
		"org_slug":       org.Slug,
		"is_admin":       true,
		"is_super_admin": true,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(cfg.Auth.AdminSecret))
	require.NoError(t, err)

	tested := 0
	for _, r := range srv.echo.Routes() {
		if r.Method != http.MethodGet || !strings.Contains(r.Path, ":org_id") {
			continue
		}
		// Skip long-lived SSE / streaming endpoints: they block until the
		// request context is cancelled (by design) and would otherwise hang
		// the suite. A "no 500" smoke check isn't meaningful for them.
		if strings.HasSuffix(r.Path, "/stream") {
			continue
		}
		path := concreteSmokePath(r.Path, org.ID.String())
		// Per-request timeout so any endpoint that blocks (e.g. another stream
		// we forgot to skip) fails this request instead of the whole suite.
		reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(reqCtx)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.echo.ServeHTTP(rec, req)
		cancel()
		tested++
		// 501 Not Implemented is a deliberate "feature disabled on this server"
		// response (e.g. FGA when no OpenFGA backend is wired) — not a crash.
		if rec.Code >= 500 && rec.Code != http.StatusNotImplemented {
			t.Errorf("GET %s (route %s) -> %d\n%s", path, r.Path, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
	require.NotZero(t, tested, "no org-scoped GET routes were exercised")
	t.Logf("smoke-tested %d org-scoped GET endpoints", tested)
}

// concreteSmokePath fills a route template: :org_id → the seeded org, any other
// :param → a random uuid, wildcard → a placeholder.
func concreteSmokePath(tmpl, orgID string) string {
	parts := strings.Split(tmpl, "/")
	for i, p := range parts {
		switch {
		case p == ":org_id":
			parts[i] = orgID
		case strings.HasPrefix(p, ":"):
			parts[i] = uuid.NewString()
		case strings.HasPrefix(p, "*"):
			parts[i] = "x"
		}
	}
	return strings.Join(parts, "/")
}
