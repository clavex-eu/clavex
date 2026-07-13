package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestGetJWKSKeysForOrg_IncludesGlobalDuringGrace verifies that an org's JWKS
// key set contains its own active key PLUS the global (org_id IS NULL) key while
// the global key is within its grace window, and excludes a global key whose
// grace has expired. This is the token-continuity guarantee for the switch to
// per-org signing keys. Requires TEST_DATABASE_URL (skipped otherwise).
func TestGetJWKSKeysForOrg_IncludesGlobalDuringGrace(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, _ := twoOrgs(t, ctx, pool)
	repo := NewSigningKeyRepository(pool)

	// Org's own active key.
	orgKID := "orgk-" + uuid.NewString()
	require.NoError(t, repo.InsertForOrg(ctx, orgA, orgKID, "PS256", []byte("org-enc")))

	// A global key retired but still within grace (visible), and one expired
	// (hidden). Insert directly — retired rows are not subject to the
	// one-active-global index; kids are unique via uuid.
	graceKID := "grace-" + uuid.NewString()
	expiredKID := "expired-" + uuid.NewString()
	// Clean up the global (org_id IS NULL) rows we inject so they do not leak
	// into other parallel packages' JWKS assertions.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM signing_keys WHERE kid = ANY($1)`, []string{graceKID, expiredKID})
	})
	_, err := pool.Exec(ctx, `
		INSERT INTO signing_keys (kid, algorithm, key_enc, status, org_id, retired_at, expires_at)
		VALUES ($1, 'PS256', $2, 'retired', NULL, NOW(), NOW() + INTERVAL '1 hour')`,
		graceKID, []byte("g-enc"))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO signing_keys (kid, algorithm, key_enc, status, org_id, retired_at, expires_at)
		VALUES ($1, 'PS256', $2, 'retired', NULL, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour')`,
		expiredKID, []byte("e-enc"))
	require.NoError(t, err)

	rows, err := repo.GetJWKSKeysForOrg(ctx, orgA)
	require.NoError(t, err)

	kids := make(map[string]bool, len(rows))
	for _, r := range rows {
		kids[r.KID] = true
	}
	require.True(t, kids[orgKID], "org's own key must be published")
	require.True(t, kids[graceKID], "global key within grace must be published for continuity")
	require.False(t, kids[expiredKID], "global key past its grace window must not be published")
}
