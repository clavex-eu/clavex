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

// TestIDOR_Webhooks_CrossOrgMutationRejected guards the webhook mutation path:
// Update/Delete must reject a webhook id owned by a different org. Regression for
// the IDOR where an org-B admin could PATCH/DELETE org-A's webhook (incl. its
// signing secret) by passing the leaf id under their own :org_id.
func TestIDOR_Webhooks_CrossOrgMutationRejected(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	repo := NewWebhookRepository(pool)

	wh, err := repo.Create(ctx, orgA, "https://a.example/hook", []string{"user.created"}, "s3cr3t")
	require.NoError(t, err)

	// Cross-org update is rejected (no row matches id + orgB).
	_, err = repo.Update(ctx, wh.ID, orgB, ptr("https://evil/hook"), nil, nil, nil)
	require.ErrorIs(t, err, pgx.ErrNoRows)

	// Cross-org delete is rejected.
	err = repo.Delete(ctx, wh.ID, orgB)
	require.ErrorIs(t, err, pgx.ErrNoRows)

	// Owning org still succeeds.
	_, err = repo.Update(ctx, wh.ID, orgA, ptr("https://a.example/hook2"), nil, nil, nil)
	require.NoError(t, err)
	require.NoError(t, repo.Delete(ctx, wh.ID, orgA))
}

// TestIDOR_SigningKeys_PerOrgIsolation guards BYOK per-org signing keys: one
// org's active key must never be returned when querying under another org. A
// cross-org key read would enable token forgery for the victim org.
func TestIDOR_SigningKeys_PerOrgIsolation(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	repo := NewSigningKeyRepository(pool)

	kid := "kid-" + uuid.NewString()
	require.NoError(t, repo.InsertForOrg(ctx, orgA, kid, "PS256", []byte("enc-key-bytes")))

	// orgA sees its key; orgB does not (no active key for orgB).
	got, err := repo.GetActiveForOrg(ctx, orgA)
	require.NoError(t, err)
	require.Equal(t, kid, got.KID)

	_, err = repo.GetActiveForOrg(ctx, orgB)
	require.ErrorIs(t, err, pgx.ErrNoRows)
}

// TestIDOR_SAMLSP_CrossOrgDeleteRejected guards SAML SP deletion: DeleteSP must
// reject an SP id owned by a different org. Regression for the IDOR where an
// org-B admin could DELETE org-A's SAML service provider by its id.
func TestIDOR_SAMLSP_CrossOrgDeleteRejected(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	repo := NewSAMLRepository(pool)

	sp, err := repo.CreateSP(ctx, CreateSAMLSPParams{
		OrgID:        orgA,
		EntityID:     "urn:sp:" + uuid.NewString(),
		Name:         "sp-A",
		ACSURL:       "https://a.example/acs",
		NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
	})
	require.NoError(t, err)

	// Cross-org delete is rejected.
	require.ErrorIs(t, repo.DeleteSP(ctx, sp.ID, orgB), pgx.ErrNoRows)
	// Owning org succeeds.
	require.NoError(t, repo.DeleteSP(ctx, sp.ID, orgA))
}

// TestIDOR_MFA_CrossUserDeleteRejected guards self-service MFA credential
// deletion: DeleteForUserInOrg must reject a credential owned by another user.
// Regression for the IDOR where a user could delete another user's credential.
func TestIDOR_MFA_CrossUserDeleteRejected(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	users := NewUserRepository(pool)
	repo := NewMFARepository(pool)

	victim, err := users.Create(ctx, orgA, "victim-"+uuid.NewString()+"@t.local", nil, nil)
	require.NoError(t, err)
	attacker, err := users.Create(ctx, orgB, "attacker-"+uuid.NewString()+"@t.local", nil, nil)
	require.NoError(t, err)

	cred, err := repo.CreateTOTP(ctx, victim.ID, "victim-totp", map[string]interface{}{"secret": "x"})
	require.NoError(t, err)

	// Attacker (different user, different org) cannot delete the victim's cred.
	require.ErrorIs(t, repo.DeleteForUserInOrg(ctx, cred.ID, attacker.ID, orgB), pgx.ErrNoRows)
	// Wrong org for the right user is also rejected.
	require.ErrorIs(t, repo.DeleteForUserInOrg(ctx, cred.ID, victim.ID, orgB), pgx.ErrNoRows)
	// Owner in the correct org succeeds.
	require.NoError(t, repo.DeleteForUserInOrg(ctx, cred.ID, victim.ID, orgA))
}

func ptr[T any](v T) *T { return &v }
