package oidc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/stretchr/testify/require"
)

func TestTenantRotationContinuityAndReplicaRefresh(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()
	org := newTestOrg(t, ctx, pool)
	global := newStubSigner(t, "global")
	first := NewOrgSignerCacheFromKEK(pool, testKEK(), global)
	second := NewOrgSignerCacheFromKEK(pool, testKEK(), global)
	old, err := first.Resolve(ctx, org)
	require.NoError(t, err)
	tc := &TokenConfig{Keys: old, Issuer: "https://issuer.invalid/tenant", AccessTokenTTL: time.Hour}
	token, _, err := tc.IssueAccessToken("client", "openid", nil, nil, nil)
	require.NoError(t, err)
	stale, err := second.Resolve(ctx, org)
	require.NoError(t, err)
	require.Equal(t, old.KID(), stale.KID())
	kid, err := first.RotateForOrg(ctx, org)
	require.NoError(t, err)
	require.NotEqual(t, old.KID(), kid)
	refreshed, err := second.Resolve(ctx, org)
	require.NoError(t, err)
	require.Equal(t, kid, refreshed.KID())
	tc.Keys = refreshed
	_, _, _, err = tc.VerifyAccessToken(token)
	require.NoError(t, err, "old token must remain valid during grace")
	newToken, _, err := tc.IssueAccessToken("client", "openid", nil, nil, nil)
	require.NoError(t, err)
	_, _, _, err = tc.VerifyAccessToken(newToken)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE signing_keys SET expires_at=NOW()-INTERVAL '1 second' WHERE org_id=$1 AND kid=$2`, org, old.KID())
	require.NoError(t, err)
	tc.Keys, err = second.Resolve(ctx, org)
	require.NoError(t, err)
	_, _, _, err = tc.VerifyAccessToken(token)
	require.Error(t, err, "expired grace key must disappear on every replica")
	_, _, _, err = tc.VerifyAccessToken(newToken)
	require.NoError(t, err)
	other := newTestOrg(t, ctx, pool)
	tc.Keys, err = second.Resolve(ctx, other)
	require.NoError(t, err)
	_, _, _, err = tc.VerifyAccessToken(newToken)
	require.Error(t, err, "another tenant cannot verify the token even with the same issuer string")
}

func TestTenantRotationKeepsPQCAndRollsBackOnInsertFailure(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()
	org := newTestOrg(t, ctx, pool)
	cache := NewOrgSignerCacheFromKEK(pool, testKEK(), newStubSigner(t, "global"))
	rsa, err := cache.Resolve(ctx, org)
	require.NoError(t, err)
	pqc := NewOrgPQCSignerCacheFromKEK(pool, testKEK(), stubGlobalPQC("global-pqc"))
	pqcKey, err := pqc.Resolve(ctx, org)
	require.NoError(t, err)
	rsaKid, err := cache.RotateForOrg(ctx, org)
	require.NoError(t, err)
	require.NotEqual(t, rsa.KID(), rsaKid)
	gotPQC, err := pqc.Resolve(ctx, org)
	require.NoError(t, err)
	require.Equal(t, pqcKey.KID(), gotPQC.KID())
	_, err = pqc.RotateForOrg(ctx, org)
	require.NoError(t, err)
	gotRSA, err := cache.Resolve(ctx, org)
	require.NoError(t, err)
	require.Equal(t, rsaKid, gotRSA.KID())
	repo := repository.NewSigningKeyRepository(pool)
	_, err = repo.ReplaceForOrg(ctx, org, repository.OrgKeyReplacement{KID: rsaKid, Algorithm: "PS256", KeyEnc: []byte("test")})
	require.Error(t, err, "duplicate KID must roll back retirement")
	row, err := repo.GetActiveForOrg(ctx, org)
	require.NoError(t, err)
	require.Equal(t, rsaKid, row.KID)
}

func TestTenantImportedKeyAndLoadFailuresNeverUseGlobal(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()
	org := newTestOrg(t, ctx, pool)
	cache := NewOrgSignerCacheFromKEK(pool, testKEK(), newStubSigner(t, "global"))
	kid, err := cache.ImportForOrg(ctx, org, testRSAPKCS8(t))
	require.NoError(t, err)
	_, err = cache.RotateForOrg(ctx, org)
	require.ErrorIs(t, err, repository.ErrImportedSigningKey)
	got, err := cache.Resolve(ctx, org)
	require.NoError(t, err)
	require.Equal(t, kid, got.KID())
	bad := NewOrgSignerCacheFromKEK(pool, [32]byte{99}, newStubSigner(t, "global"))
	signer, err := bad.Resolve(ctx, org)
	require.Error(t, err)
	require.Nil(t, signer)
	require.NoError(t, cache.RemoveForOrg(ctx, org))
	generated, err := cache.Resolve(ctx, org)
	require.NoError(t, err)
	require.NotEqual(t, kid, generated.KID())
	require.Contains(t, string(generated.JWKS()), kid)
}

func TestTenantConcurrentFirstUseKeepsOneKey(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()
	org := newTestOrg(t, ctx, pool)
	cache := NewOrgSignerCacheFromKEK(pool, testKEK(), newStubSigner(t, "global"))
	var wg sync.WaitGroup
	kids := make(chan string, 4)
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			s, err := cache.Resolve(ctx, org)
			if err != nil {
				errs <- err
				return
			}
			kids <- s.KID()
		})
	}
	wg.Wait()
	close(kids)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	unique := map[string]bool{}
	for kid := range kids {
		unique[kid] = true
	}
	require.Len(t, unique, 1)
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE org_id=$1 AND pqc_algorithm IS NULL AND key_use='sig'`, org).Scan(&count))
	require.Equal(t, 1, count)
}
