package repository

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// TestKeyRotation_OrgScopedOIDCIsolation verifies that OIDC rotation policy is
// per-org: one org's policy never leaks into another org's or into the global
// (PQC) scope, and vice versa. Requires TEST_DATABASE_URL (skipped otherwise).
func TestKeyRotation_OrgScopedOIDCIsolation(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, orgB := twoOrgs(t, ctx, pool)
	repo := NewKeyRotationPolicyRepository(pool)

	require.NoError(t, repo.UpsertForOrg(ctx, KeyKindOIDC, orgA, RotationPolicyScheduled, 30))
	require.NoError(t, repo.UpsertForOrg(ctx, KeyKindOIDC, orgB, RotationPolicyManual, 90))

	a, err := repo.GetForOrg(ctx, KeyKindOIDC, orgA)
	require.NoError(t, err)
	require.Equal(t, RotationPolicyScheduled, a.RotationPolicy)
	require.Equal(t, 30, a.IntervalDays)
	require.NotNil(t, a.OrgID)
	require.Equal(t, orgA, *a.OrgID)

	b, err := repo.GetForOrg(ctx, KeyKindOIDC, orgB)
	require.NoError(t, err)
	require.Equal(t, RotationPolicyManual, b.RotationPolicy)

	// Updating org A must not touch org B.
	require.NoError(t, repo.UpsertForOrg(ctx, KeyKindOIDC, orgA, RotationPolicyManual, 45))
	b, err = repo.GetForOrg(ctx, KeyKindOIDC, orgB)
	require.NoError(t, err)
	require.Equal(t, RotationPolicyManual, b.RotationPolicy)
	require.Equal(t, 90, b.IntervalDays)

	// The org-scoped OIDC policy must not appear as a global policy.
	_, err = repo.Get(ctx, KeyKindOIDC)
	require.ErrorIs(t, err, pgx.ErrNoRows)
}

// TestKeyRotation_GlobalPQCNotOrgVisible verifies the global PQC policy stays
// global and is not returned for any org scope.
func TestKeyRotation_GlobalPQCNotOrgVisible(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, _ := twoOrgs(t, ctx, pool)
	repo := NewKeyRotationPolicyRepository(pool)

	require.NoError(t, repo.Upsert(ctx, KeyKindPQC, RotationPolicyScheduled, 60))

	g, err := repo.Get(ctx, KeyKindPQC)
	require.NoError(t, err)
	require.Equal(t, RotationPolicyScheduled, g.RotationPolicy)
	require.Nil(t, g.OrgID)

	_, err = repo.GetForOrg(ctx, KeyKindPQC, orgA)
	require.ErrorIs(t, err, pgx.ErrNoRows)
}

// TestKeyRotation_ListDueReturnsPerOrgOIDC verifies a scheduled per-org OIDC
// policy that has never been rotated is reported due, carrying its OrgID.
func TestKeyRotation_ListDueReturnsPerOrgOIDC(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, _ := twoOrgs(t, ctx, pool)
	repo := NewKeyRotationPolicyRepository(pool)

	require.NoError(t, repo.UpsertForOrg(ctx, KeyKindOIDC, orgA, RotationPolicyScheduled, 1))

	due, err := repo.ListDue(ctx, time.Now())
	require.NoError(t, err)

	var found bool
	for _, p := range due {
		if p.OrgID != nil && *p.OrgID == orgA && p.KeyKind == KeyKindOIDC {
			found = true
		}
	}
	require.True(t, found, "scheduled never-rotated per-org OIDC policy must be due, with OrgID set")

	// After marking it rotated now, it is no longer due (interval 1 day).
	require.NoError(t, repo.MarkRotatedForOrg(ctx, KeyKindOIDC, orgA, time.Now()))
	due, err = repo.ListDue(ctx, time.Now())
	require.NoError(t, err)
	for _, p := range due {
		if p.OrgID != nil && *p.OrgID == orgA {
			t.Fatalf("just-rotated per-org OIDC policy should not be due")
		}
	}
}
