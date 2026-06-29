package worker

// MDS3Worker periodically refreshes the local FIDO Alliance MDS3 catalog.
//
// The FIDO Alliance publishes a new JWT-signed catalog at
// https://mds3.fidoalliance.org approximately once per day. This worker:
//
//  1. Checks the local fido_mds_sync table for the last ETag/Last-Modified
//     headers from the previous successful fetch.
//  2. Issues a conditional GET (If-None-Match / If-Modified-Since) so that
//     we skip parsing on 304 Not Modified responses.
//  3. Parses + verifies the JWS signature of the returned BLOB.
//  4. Bulk-upserts all entries with an AAGUID into fido_mds_entries.
//  5. Updates the sync metadata row (entry count, last_no, http_etag, …).
//
// The worker runs once on startup (to clear any backlog from a cold start)
// and then on a configurable interval (default: 24 h).
//
// Multi-instance safety: the upsert is idempotent; concurrent workers simply
// write the same data. The sync row has no distributed lock; the last writer
// wins (acceptable for a catalog refresh).

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/mds3"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	mds3WorkerInterval = 24 * time.Hour
	// mds3InitialDelay is how long after startup before the first fetch.
	// Avoids thundering-herd if multiple instances start simultaneously.
	mds3InitialDelay = 5 * time.Second
)

// RunMDS3Worker starts the background MDS3 refresh goroutine.
// It blocks until ctx is cancelled. Call as `go RunMDS3Worker(ctx, pool)`.
func RunMDS3Worker(ctx context.Context, pool *pgxpool.Pool) {
	RunMDS3WorkerWithEndpoint(ctx, pool, "")
}

// RunMDS3WorkerWithEndpoint is like RunMDS3Worker but allows overriding the
// MDS3 endpoint URL (useful for testing with a local stub).
func RunMDS3WorkerWithEndpoint(ctx context.Context, pool *pgxpool.Pool, endpoint string) {
	RunMDS3WorkerFull(ctx, pool, endpoint, PolicyEnforcerDeps{Pool: pool})
}

// RunMDS3WorkerFull is the full-featured entry point that accepts policy
// enforcer dependencies so non-compliant credentials are revoked automatically
// after each catalog refresh.
func RunMDS3WorkerFull(ctx context.Context, pool *pgxpool.Pool, endpoint string, enforcerDeps PolicyEnforcerDeps) {
	repo := repository.NewMDSRepository(pool)
	client := mds3.New(endpoint)

	log.Info().Str("interval", mds3WorkerInterval.String()).Msg("mds3-worker: started")

	// Brief initial delay to let the server finish startup.
	select {
	case <-ctx.Done():
		return
	case <-time.After(mds3InitialDelay):
	}

	// Run once immediately.
	if runMDS3Sync(ctx, repo, client) {
		EnforcePoliciesAfterMDSRefresh(ctx, enforcerDeps)
	}

	ticker := time.NewTicker(mds3WorkerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("mds3-worker: stopping")
			return
		case <-ticker.C:
			if runMDS3Sync(ctx, repo, client) {
				EnforcePoliciesAfterMDSRefresh(ctx, enforcerDeps)
			}
		}
	}
}

// runMDS3Sync performs one fetch-and-upsert cycle.
// Returns true when the catalog was actually updated (entries upserted),
// false on 304 Not Modified, fetch error, or upsert error.
// The caller uses the return value to decide whether to run policy enforcement.
func runMDS3Sync(ctx context.Context, repo *repository.MDSRepository, client *mds3.Client) bool {
	log.Info().Msg("mds3-worker: starting sync")

	// Load cached HTTP headers for conditional GET.
	status, err := repo.GetSyncStatus(ctx)
	if err != nil {
		log.Error().Err(err).Msg("mds3-worker: failed to read sync status")
		return false
	}

	var etag, lastMod string
	if status.HTTPETag != nil {
		etag = *status.HTTPETag
	}
	if status.HTTPLastModified != nil {
		lastMod = *status.HTTPLastModified
	}

	blob, meta, err := client.Fetch(ctx, etag, lastMod)
	if err != nil {
		log.Error().Err(err).Msg("mds3-worker: fetch failed")
		_ = repo.UpdateSyncError(ctx, err.Error())
		return false
	}

	// nil blob = 304 Not Modified — nothing to update, but refresh the sync ts.
	if blob == nil {
		log.Info().Msg("mds3-worker: catalog unchanged (304)")
		_ = repo.UpdateSyncSuccess(ctx, status.EntryCount, status.LastNo, meta)
		// Even on 304, run enforcement: REVOKED status may have been in the previous
		// catalog and existing credentials may not have been checked yet (e.g. policy
		// was enabled after the last sync). Return true so enforcement always runs.
		return true
	}

	log.Info().
		Int("entries", len(blob.Entries)).
		Int64("no", blob.No).
		Str("next_update", blob.NextUpdate).
		Msg("mds3-worker: upserting entries")

	if err := repo.UpsertEntries(ctx, blob.Entries); err != nil {
		log.Error().Err(err).Msg("mds3-worker: upsert failed")
		_ = repo.UpdateSyncError(ctx, err.Error())
		return false
	}

	// Count only FIDO2 entries (those with an AAGUID) for the sync row.
	aaguidCount := 0
	for _, e := range blob.Entries {
		if e.AAGUID != "" {
			aaguidCount++
		}
	}

	if err := repo.UpdateSyncSuccess(ctx, aaguidCount, blob.No, meta); err != nil {
		log.Error().Err(err).Msg("mds3-worker: update sync metadata failed")
		return false
	}

	log.Info().
		Int("aaguid_entries", aaguidCount).
		Int64("no", blob.No).
		Msg("mds3-worker: sync complete")
	return true
}

// RunMDS3SyncOnce performs a single fetch-and-upsert on demand (e.g. triggered
// from the admin API). It does not block the caller — the caller is expected to
// run this in a goroutine. The endpoint parameter is optional; pass "" to use
// the default https://mds3.fidoalliance.org.
func RunMDS3SyncOnce(ctx context.Context, pool *pgxpool.Pool, endpoint string) {
	repo := repository.NewMDSRepository(pool)
	client := mds3.New(endpoint)
	runMDS3Sync(ctx, repo, client)
}
