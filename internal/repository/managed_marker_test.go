package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// DB-backed tests for the declarative-management marker (migration 000179).
// Reuse idorPool / twoOrgs; skipped without TEST_DATABASE_URL.

// TestManagedMarker_AdoptPreserveRelease exercises the three transitions the
// update handlers rely on:
//   - an operator-stamped write (By set) records managed_by/managed_ref;
//   - a subsequent inactive marker (a UI/API request with no header) leaves the
//     existing marker untouched;
//   - an explicit release clears it without touching the resource.
func TestManagedMarker_AdoptPreserveRelease(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, _ := twoOrgs(t, ctx, pool)
	repo := NewClientRepository(pool)

	cl, _, err := repo.Create(ctx, orgA, "mm-client-"+uuid.NewString(), "c", []string{"https://app/cb"}, nil, nil, nil, nil, false)
	require.NoError(t, err)

	// Fresh client carries no marker.
	got, err := repo.GetForOrg(ctx, cl.ClientID, orgA)
	require.NoError(t, err)
	require.Nil(t, got.ManagedBy)
	require.Nil(t, got.ManagedRef)

	// Operator-stamped write adopts the resource.
	ref := "ClavexClient/clavex-operator-system/testclient"
	require.NoError(t, repo.SetManagedMarker(ctx, cl.ClientID, orgA, ManagedMarkerInput{By: "k8s-operator", Ref: ref}))
	got, err = repo.GetForOrg(ctx, cl.ClientID, orgA)
	require.NoError(t, err)
	require.NotNil(t, got.ManagedBy)
	require.Equal(t, "k8s-operator", *got.ManagedBy)
	require.NotNil(t, got.ManagedRef)
	require.Equal(t, ref, *got.ManagedRef)

	// An inactive marker (simulating a UI update without the header) is a no-op
	// and must not clear the existing marker.
	require.NoError(t, repo.SetManagedMarker(ctx, cl.ClientID, orgA, ManagedMarkerInput{}))
	got, err = repo.GetForOrg(ctx, cl.ClientID, orgA)
	require.NoError(t, err)
	require.NotNil(t, got.ManagedBy, "inactive marker must not clear an existing marker")
	require.Equal(t, "k8s-operator", *got.ManagedBy)

	// Explicit release disowns the resource.
	require.NoError(t, repo.SetManagedMarker(ctx, cl.ClientID, orgA, ManagedMarkerInput{Release: true}))
	got, err = repo.GetForOrg(ctx, cl.ClientID, orgA)
	require.NoError(t, err)
	require.Nil(t, got.ManagedBy, "release must clear managed_by")
	require.Nil(t, got.ManagedRef, "release must clear managed_ref")
}

// TestManagedMarker_EmptyRefStoresNull verifies an empty ref collapses to NULL
// (NULLIF) rather than persisting an empty string.
func TestManagedMarker_EmptyRefStoresNull(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	orgA, _ := twoOrgs(t, ctx, pool)
	repo := NewClientRepository(pool)

	cl, _, err := repo.Create(ctx, orgA, "mm-client-"+uuid.NewString(), "c", []string{"https://app/cb"}, nil, nil, nil, nil, false)
	require.NoError(t, err)

	require.NoError(t, repo.SetManagedMarker(ctx, cl.ClientID, orgA, ManagedMarkerInput{By: "k8s-operator"}))
	got, err := repo.GetForOrg(ctx, cl.ClientID, orgA)
	require.NoError(t, err)
	require.NotNil(t, got.ManagedBy)
	require.Nil(t, got.ManagedRef, "empty ref must store NULL, not an empty string")
}

// TestManagedMarker_TableAllowlist rejects a table outside the allowlist so a
// bad caller cannot interpolate an arbitrary identifier into the statement.
func TestManagedMarker_TableAllowlist(t *testing.T) {
	pool := idorPool(t)
	ctx := context.Background()
	err := ApplyManagedMarker(ctx, pool, "users", "id", uuid.New(), uuid.New(), ManagedMarkerInput{By: "x"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not in allowlist")
}
