package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestSeedFinalClientsIsScopedAtomicAndIdempotent(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = "identity,sessions,audit,public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	org, err := repository.NewOrgRepository(pool).Create(ctx, "Final seed test", orgSlug, nil)
	require.NoError(t, err)
	defer func() {
		_, err := pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org.ID)
		require.NoError(t, err)
	}()
	require.Error(t, seedFinalClients(ctx, pool, org.ID)) // not in conformance mode
	_, err = pool.Exec(ctx, `UPDATE organizations SET conformance_mode=true WHERE id=$1`, org.ID)
	require.NoError(t, err)
	repo := repository.NewClientRepository(pool)
	for _, id := range finalClientSources {
		_, _, err = repo.Create(ctx, org.ID, id, "Source", []string{"https://example.test/callback"}, nil, nil, nil, nil, true)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `UPDATE oidc_clients SET jwks='{"keys":[]}',metadata='{"keep":"source"}',require_par=true WHERE client_id=$1`, id)
		require.NoError(t, err)
	}
	// A conflicting pre-existing target must not be silently taken over.
	conflict := finalClientSources[len(finalClientSources)-1] + "-final"
	_, _, err = repo.Create(ctx, org.ID, conflict, "Existing unrelated", []string{"https://existing.example/callback"}, nil, nil, nil, nil, true)
	require.NoError(t, err)
	require.Error(t, seedFinalClients(ctx, pool, org.ID))
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM oidc_clients WHERE metadata ? 'conformance_final_source'`).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, repo.Delete(ctx, conflict, org.ID))
	require.NoError(t, seedFinalClients(ctx, pool, org.ID))
	require.NoError(t, seedFinalClients(ctx, pool, org.ID))
	for _, id := range finalClientSources {
		source, err := repo.GetByClientID(ctx, id)
		require.NoError(t, err)
		target, err := repo.GetByClientID(ctx, id+"-final")
		require.NoError(t, err)
		require.NotContains(t, source.Metadata, models.ClientAssertionProfileMetadataKey)
		require.Equal(t, "source", source.Metadata["keep"])
		require.Equal(t, models.ClientAssertionProfileFAPIFinal, target.Metadata[models.ClientAssertionProfileMetadataKey])
		require.Equal(t, id, target.Metadata["conformance_final_source"])
		require.Equal(t, source.JWKS, target.JWKS)
		require.Equal(t, source.RedirectURIs, target.RedirectURIs)
		require.True(t, target.RequirePAR)
	}
}
