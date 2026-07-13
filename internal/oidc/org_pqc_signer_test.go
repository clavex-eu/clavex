package oidc

import (
	"context"
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// PQC per-org tests. Mirror the OIDC org-signer tests; require TEST_DATABASE_URL
// (skipped otherwise). They reuse orgSignerPool / testKEK / newTestOrg from
// org_signer_provision_test.go, and use a stub global PQCSigner (kid only) so
// they never touch the shared global PQC key in the CI database.
//
//	TEST_DATABASE_URL=postgres://...@localhost/clavex_test go test ./internal/oidc/ -run TestOrgPQC

// stubGlobalPQC returns a minimal *PQCSigner usable only as a fallback identity
// (its KID). For() never calls its DB-backed methods in these tests.
func stubGlobalPQC(kid string) *PQCSigner {
	return &PQCSigner{kid: kid}
}

// TestOrgPQC_ForAutoProvisions verifies For() mints a fresh per-org ML-DSA-65
// key instead of falling back to the global PQC signer.
func TestOrgPQC_ForAutoProvisions(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()

	cache := NewOrgPQCSignerCacheFromKEK(pool, testKEK(), stubGlobalPQC("global-pqc-stub"))
	orgID := newTestOrg(t, ctx, pool)

	s := cache.For(ctx, orgID)
	require.NotEqual(t, "global-pqc-stub", s.KID(), "org must publish its own PQC key, not the global fallback")

	repo := repository.NewSigningKeyRepository(pool)
	row, err := repo.GetActivePQCForOrg(ctx, orgID)
	require.NoError(t, err)
	require.Equal(t, s.KID(), row.KID)
	require.Equal(t, PQCAlgorithmMLDSA65, row.PQCAlgorithm)

	jwk := string(s.JWKObject())
	require.Contains(t, jwk, s.KID())
	require.Contains(t, jwk, PQCKeyType)
	require.False(t, strings.Contains(jwk, "global-pqc-stub"))
}

// TestOrgPQC_DisableAutoProvisionFallsBackToGlobal verifies the opt-out path.
func TestOrgPQC_DisableAutoProvisionFallsBackToGlobal(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()

	cache := NewOrgPQCSignerCacheFromKEK(pool, testKEK(), stubGlobalPQC("global-pqc-stub")).DisableAutoProvision()
	orgID := newTestOrg(t, ctx, pool)

	s := cache.For(ctx, orgID)
	require.Equal(t, "global-pqc-stub", s.KID(), "auto-provision disabled ⇒ global PQC signer")

	repo := repository.NewSigningKeyRepository(pool)
	_, err := repo.GetActivePQCForOrg(ctx, orgID)
	require.ErrorIs(t, err, pgx.ErrNoRows)
}

// TestOrgPQC_GenerateForOrgIsDistinctPerOrg verifies each org gets its own PQC
// key (the shape the backfill relies on).
func TestOrgPQC_GenerateForOrgIsDistinctPerOrg(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()
	repo := repository.NewSigningKeyRepository(pool)

	cache := NewOrgPQCSignerCacheFromKEK(pool, testKEK(), stubGlobalPQC("global-pqc-stub"))
	orgA := newTestOrg(t, ctx, pool)
	orgB := newTestOrg(t, ctx, pool)

	kidA, err := cache.GenerateForOrg(ctx, orgA)
	require.NoError(t, err)
	kidB, err := cache.GenerateForOrg(ctx, orgB)
	require.NoError(t, err)
	require.NotEqual(t, kidA, kidB)

	rowA, err := repo.GetActivePQCForOrg(ctx, orgA)
	require.NoError(t, err)
	require.Equal(t, kidA, rowA.KID)
	require.Contains(t, string(cache.For(ctx, orgB).JWKObject()), kidB)
}

// TestOrgPQC_RotateForOrgRetiresOld verifies rotation replaces the active key.
func TestOrgPQC_RotateForOrgRetiresOld(t *testing.T) {
	pool := orgSignerPool(t)
	ctx := context.Background()
	repo := repository.NewSigningKeyRepository(pool)

	cache := NewOrgPQCSignerCacheFromKEK(pool, testKEK(), stubGlobalPQC("global-pqc-stub"))
	orgID := newTestOrg(t, ctx, pool)

	kid1, err := cache.GenerateForOrg(ctx, orgID)
	require.NoError(t, err)

	kid2, err := cache.RotateForOrg(ctx, orgID)
	require.NoError(t, err)
	require.NotEqual(t, kid1, kid2, "rotation must mint a new kid")

	row, err := repo.GetActivePQCForOrg(ctx, orgID)
	require.NoError(t, err)
	require.Equal(t, kid2, row.KID)
}
