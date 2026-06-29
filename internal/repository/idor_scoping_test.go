package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Cross-tenant (IDOR) scoping regression harness.
//
// These tests assert that the org-scoped repository methods reject a leaf
// resource that belongs to a DIFFERENT organization (returning pgx.ErrNoRows),
// while still serving the owning org. They guard against the systemic IDOR class
// where an admin of org B could read/mutate org A's resources by their globally
// unique leaf id.
//
// The tests require a migrated Postgres reachable via TEST_DATABASE_URL and are
// skipped otherwise (e.g. in pure-unit CI). Run with:
//
//	TEST_DATABASE_URL=postgres://...@localhost/clavex_test go test ./internal/repository/ -run TestIDOR
func idorPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed IDOR scoping tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	// Mirror the app pool: migration 000017 moves tables into the identity /
	// sessions / audit schemas, so without this search_path queries against a
	// raw DSN see only `public` and fail with "relation does not exist".
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path = identity, sessions, audit, public`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// twoOrgs creates two distinct organizations with unique slugs and returns them.
func twoOrgs(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (orgA, orgB uuid.UUID) {
	t.Helper()
	orgs := NewOrgRepository(pool)
	a, err := orgs.Create(ctx, "idor-A-"+uuid.NewString(), "idor-a-"+uuid.NewString(), nil)
	require.NoError(t, err)
	b, err := orgs.Create(ctx, "idor-B-"+uuid.NewString(), "idor-b-"+uuid.NewString(), nil)
	require.NoError(t, err)
	return a.ID, b.ID
}

func TestIDOR_Clients_CrossOrgRejected(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	repo := NewClientRepository(pool)

	cl, _, err := repo.Create(ctx, orgA, "idor-client-"+uuid.NewString(), "c", []string{"https://app/cb"}, false)
	require.NoError(t, err)

	// Same org: succeeds.
	got, err := repo.GetForOrg(ctx, cl.ClientID, orgA)
	require.NoError(t, err)
	require.Equal(t, cl.ClientID, got.ClientID)

	// Cross org: every scoped method must reject with ErrNoRows.
	_, err = repo.GetForOrg(ctx, cl.ClientID, orgB)
	require.ErrorIs(t, err, pgx.ErrNoRows)

	_, err = repo.Update(ctx, cl.ClientID, orgB, ptr("hacked"), nil, nil, nil, nil, nil, nil)
	require.ErrorIs(t, err, pgx.ErrNoRows)

	_, err = repo.RotateSecret(ctx, cl.ClientID, orgB)
	require.ErrorIs(t, err, pgx.ErrNoRows)

	require.ErrorIs(t, repo.Delete(ctx, cl.ClientID, orgB), pgx.ErrNoRows)

	// The client must still exist (cross-org delete was a no-op).
	_, err = repo.GetForOrg(ctx, cl.ClientID, orgA)
	require.NoError(t, err)
}

func TestIDOR_Users_CrossOrgRejected(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	repo := NewUserRepository(pool)

	u, err := repo.Create(ctx, orgA, "idor-"+uuid.NewString()+"@e.com", ptr("F"), ptr("L"))
	require.NoError(t, err)

	_, err = repo.GetForOrg(ctx, u.ID, orgA)
	require.NoError(t, err)

	_, err = repo.GetForOrg(ctx, u.ID, orgB)
	require.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestIDOR_Groups_CrossEntityRejected(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	groups := NewGroupRepository(pool)
	users := NewUserRepository(pool)

	g, err := groups.Create(ctx, orgA, "g-"+uuid.NewString(), "")
	require.NoError(t, err)
	uB, err := users.Create(ctx, orgB, "idor-"+uuid.NewString()+"@e.com", nil, nil)
	require.NoError(t, err)
	roleA, err := users.CreateRole(ctx, orgA, "r-"+uuid.NewString(), nil)
	require.NoError(t, err)

	// Group owned by A is invisible to B.
	_, err = groups.GetForOrg(ctx, g.ID, orgB)
	require.ErrorIs(t, err, pgx.ErrNoRows)
	_, err = groups.GetForOrg(ctx, g.ID, orgA)
	require.NoError(t, err)

	// A user from org B is not "in" org A — cannot be added to org A's group.
	ok, err := groups.UserInOrg(ctx, uB.ID, orgA)
	require.NoError(t, err)
	require.False(t, ok)

	// Role of org A belongs to A, not B.
	ok, err = groups.RoleInOrg(ctx, roleA.ID, orgB)
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = groups.RoleInOrg(ctx, roleA.ID, orgA)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestIDOR_ClientScopes_CrossOrgRejected(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	scopes := NewClientScopeRepository(pool)
	clients := NewClientRepository(pool)

	sc, err := scopes.Create(ctx, orgA, "scope-"+uuid.NewString(), nil, "openid-connect", false)
	require.NoError(t, err)
	clA, _, err := clients.Create(ctx, orgA, "idor-client-"+uuid.NewString(), "c", []string{"https://app/cb"}, false)
	require.NoError(t, err)

	_, err = scopes.GetForOrg(ctx, sc.ID, orgB)
	require.ErrorIs(t, err, pgx.ErrNoRows)

	// Client of org A is not in org B.
	ok, err := scopes.ClientInOrg(ctx, clA.ClientID, orgB)
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = scopes.ClientInOrg(ctx, clA.ClientID, orgA)
	require.NoError(t, err)
	require.True(t, ok)
}

func ptr[T any](v T) *T { return &v }
