package worker

// EntityEventsProjectionWorker folds entity_events rows into the
// entity_events_projection read-model.
//
// # Why this exists
//
// entity_events is an append-only event store: every mutation writes a row
// there atomically (inside the same transaction). The projection worker
// periodically replays new events and merges them into entity_events_projection,
// which provides O(1) "current state" reads without replaying the entire event log.
//
// Consistency model: eventual. The projection may lag behind the live event store
// by up to projectionWorkerInterval. For queries that need the latest state, callers
// should use SnapshotFromEvents directly. The projection is suitable for dashboards,
// SCIM exports, and access reviews where a few minutes of lag is acceptable.
//
// Multi-instance safety: the upsert uses ON CONFLICT DO UPDATE, so multiple
// instances processing the same batch is safe — they will each write the same
// folded state and the last writer wins idempotently.

import (
	"context"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	projectionWorkerInterval = 5 * time.Minute
	projectionBatchSize      = 500
)

// RunEntityEventsProjectionWorker starts the projection folding goroutine.
// Blocks until ctx is cancelled. Call as `go RunEntityEventsProjectionWorker(ctx, pool)`.
func RunEntityEventsProjectionWorker(ctx context.Context, pool *pgxpool.Pool) {
	repo := repository.NewEntityEventsRepository(pool)

	log.Info().
		Str("interval", projectionWorkerInterval.String()).
		Int("batch_size", projectionBatchSize).
		Msg("entity-events-projection-worker: started")

	// Run immediately on startup to fold any backlog that accumulated
	// while the server was down.
	runProjectionCycle(ctx, repo)

	ticker := time.NewTicker(projectionWorkerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("entity-events-projection-worker: stopping")
			return
		case <-ticker.C:
			runProjectionCycle(ctx, repo)
		}
	}
}

// runProjectionCycle processes one batch of new entity events and folds them
// into the projection table. It processes up to projectionBatchSize events per
// call; subsequent ticks will catch up on any remaining backlog.
func runProjectionCycle(ctx context.Context, repo *repository.EntityEventsRepository) {
	// Find the global watermark: the highest event ID already folded into
	// any projection row. We start just past this point.
	watermark, err := repo.MaxProjectedEventID(ctx)
	if err != nil {
		log.Error().Err(err).Msg("entity-events-projection-worker: watermark query failed")
		return
	}

	events, err := repo.ListNewEventsBatch(ctx, watermark, projectionBatchSize)
	if err != nil {
		log.Error().Err(err).Msg("entity-events-projection-worker: list events failed")
		return
	}

	if len(events) == 0 {
		return
	}

	// Group events by (org_id, entity_type, entity_id) so we can fold
	// each entity's events in a single pass.
	type entityKey struct {
		orgID      string
		entityType string
		entityID   string
	}

	// Build a per-entity ordered event list from the batch.
	// Events arrive in id ASC order, so appending preserves chronology.
	grouped := make(map[entityKey][]*repository.EntityEvent)
	keyOrder := make([]entityKey, 0)
	seen := make(map[entityKey]bool)

	for _, e := range events {
		k := entityKey{e.OrgID.String(), e.EntityType, e.EntityID}
		if !seen[k] {
			keyOrder = append(keyOrder, k)
			seen[k] = true
		}
		grouped[k] = append(grouped[k], e)
	}

	now := time.Now().UTC()
	flushed := 0
	var lastErr error

	// For each entity, load its existing projection, apply the new events,
	// and upsert the result.
	for _, k := range keyOrder {
		entityEvents := grouped[k]
		if len(entityEvents) == 0 {
			continue
		}

		// Load existing projection (may be nil if this is the first event).
		proj, err := repo.GetProjection(ctx, entityEvents[0].OrgID, k.entityType, k.entityID)
		if err != nil {
			log.Warn().Err(err).
				Str("entity_type", k.entityType).
				Str("entity_id", k.entityID).
				Msg("entity-events-projection-worker: load projection failed, skipping entity")
			lastErr = err
			continue
		}

		// Bootstrap an empty projection for new entities.
		if proj == nil {
			proj = &repository.EntityProjection{
				OrgID:      entityEvents[0].OrgID,
				EntityType: k.entityType,
				EntityID:   k.entityID,
				State:      make(map[string]any),
			}
		}

		// Apply each event as a JSON merge-patch onto the current state.
		var maxEventID int64
		for _, e := range entityEvents {
			for key, val := range e.Payload {
				proj.State[key] = val
			}
			if e.ID > maxEventID {
				maxEventID = e.ID
			}
		}

		proj.LastEventID = maxEventID
		proj.ProjectedAt = now

		if err := repo.UpsertProjection(ctx, proj); err != nil {
			log.Warn().Err(err).
				Str("entity_type", k.entityType).
				Str("entity_id", k.entityID).
				Msg("entity-events-projection-worker: upsert projection failed")
			lastErr = err
			continue
		}
		flushed++
	}

	level := log.Info()
	if lastErr != nil {
		level = log.Warn().Err(lastErr)
	}
	level.
		Int("events_processed", len(events)).
		Int("entities_updated", flushed).
		Int64("watermark_before", watermark).
		Int64("watermark_after", events[len(events)-1].ID).
		Msg("entity-events-projection-worker: cycle complete")
}
