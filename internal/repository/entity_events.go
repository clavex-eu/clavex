package repository

// EntityEventsRepository provides write and read access to the entity_events
// table — Clavex's lightweight event store.
//
// # Design
//
// The key correctness property is that entity_events rows are written INSIDE
// the same database transaction as the mutation they record. If the mutation
// rolls back, the event disappears with it. If the mutation commits, the event
// is guaranteed to exist. This closes the audit gap in the existing audit_logs
// approach, where the mutation and the log write are two separate round-trips.
//
// # Usage pattern (in a repository method)
//
//	func (r *UserRepository) ChangePassword(ctx context.Context, userID uuid.UUID, newHash string) error {
//	    tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
//	    if err != nil { return err }
//	    defer tx.Rollback(ctx)
//
//	    if _, err = tx.Exec(ctx,
//	        "UPDATE users SET password_hash=$1 WHERE id=$2", newHash, userID); err != nil {
//	        return err
//	    }
//
//	    if err = EntityEvents.AppendTx(ctx, tx, AppendParams{
//	        OrgID:      orgID,
//	        EntityType: "user",
//	        EntityID:   userID.String(),
//	        EventType:  "user.password_changed",
//	        ActorID:    actorID,
//	        Payload:    map[string]any{"password_hash_updated": true},
//	    }); err != nil {
//	        return err
//	    }
//
//	    return tx.Commit(ctx)
//	}
//
// # Critical event types
//
// Not every mutation needs an entity_event — only those relevant to compliance
// and security forensics. Recommended minimum set:
//
//	user.password_changed
//	user.role_assigned / user.role_removed
//	user.suspended / user.restored / user.deleted
//	user.mfa_enabled / user.mfa_disabled
//	org.policy_changed
//	client.secret_rotated / client.scope_changed
//	pam.break_glass_used / pam.credential_rotated
//	admin.role_assigned / admin.role_removed

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EntityEventsRepository provides append and query access to entity_events.
type EntityEventsRepository struct {
	pool *pgxpool.Pool
}

// NewEntityEventsRepository constructs a repository backed by pool.
func NewEntityEventsRepository(pool *pgxpool.Pool) *EntityEventsRepository {
	return &EntityEventsRepository{pool: pool}
}

// ── AppendParams ──────────────────────────────────────────────────────────────

// AppendParams carries the data for a single entity event.
type AppendParams struct {
	OrgID      uuid.UUID
	EntityType string    // e.g. "user", "client", "org", "policy"
	EntityID   string    // UUID or other stable identifier of the affected entity
	EventType  string    // e.g. "user.password_changed"
	ActorID    *uuid.UUID
	ActorEmail *string
	// Payload is the "after" state delta — only the fields that changed.
	// For creates: full initial state. For deletes: {"deleted": true}.
	Payload  map[string]any
	Metadata map[string]any // optional: {request_id, session_id, ip, user_agent}
	// OccurredAt defaults to time.Now() if zero.
	OccurredAt time.Time
}

// ── Write API ─────────────────────────────────────────────────────────────────

// AppendTx writes a single entity event inside an existing transaction.
// This is the preferred method: it guarantees ACID — the event is written
// atomically with the mutation that triggered it.
func (r *EntityEventsRepository) AppendTx(ctx context.Context, tx pgx.Tx, p AppendParams) error {
	return appendEvent(ctx, tx, p)
}

// Append writes a single entity event outside a transaction.
// Use this only when no transaction is available (e.g. in background workers).
// Prefer AppendTx when the event accompanies a mutation.
func (r *EntityEventsRepository) Append(ctx context.Context, p AppendParams) error {
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	return appendEvent(ctx, conn, p)
}

// pgxExecutor matches the Exec method shared by pgx.Tx, *pgx.Conn, and *pgxpool.Conn.
type pgxExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// appendEvent is the shared implementation used by both AppendTx and Append.
func appendEvent(ctx context.Context, q pgxExecutor, p AppendParams) error {
	if p.OccurredAt.IsZero() {
		p.OccurredAt = time.Now().UTC()
	}

	payloadJSON, err := json.Marshal(p.Payload)
	if err != nil {
		payloadJSON = []byte("{}")
	}
	metaJSON, err := json.Marshal(p.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	_, err = q.Exec(ctx, `
		INSERT INTO entity_events
		    (org_id, entity_type, entity_id, event_type,
		     actor_id, actor_email, payload, metadata, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`,
		p.OrgID, p.EntityType, p.EntityID, p.EventType,
		p.ActorID, p.ActorEmail, payloadJSON, metaJSON, p.OccurredAt,
	)
	return err
}

// ── EntityEvent (read model) ──────────────────────────────────────────────────

// EntityEvent is a single row from entity_events, decoded.
type EntityEvent struct {
	ID         int64
	OrgID      uuid.UUID
	EntityType string
	EntityID   string
	EventType  string
	ActorID    *uuid.UUID
	ActorEmail *string
	Payload    map[string]any
	Metadata   map[string]any
	OccurredAt time.Time
}

// ── Read API ──────────────────────────────────────────────────────────────────

// ListEntityEvents returns all events for a specific entity in chronological
// order, optionally capped at the given point in time.
//
//   - upTo: if zero, all events are returned.
func (r *EntityEventsRepository) ListEntityEvents(
	ctx context.Context,
	orgID uuid.UUID,
	entityType, entityID string,
	upTo time.Time,
) ([]*EntityEvent, error) {
	var rows pgx.Rows
	var err error

	if upTo.IsZero() {
		rows, err = r.pool.Query(ctx, `
			SELECT id, org_id, entity_type, entity_id, event_type,
			       actor_id, actor_email, payload, metadata, occurred_at
			FROM entity_events
			WHERE org_id=$1 AND entity_type=$2 AND entity_id=$3
			ORDER BY id ASC
		`, orgID, entityType, entityID)
	} else {
		rows, err = r.pool.Query(ctx, `
			SELECT id, org_id, entity_type, entity_id, event_type,
			       actor_id, actor_email, payload, metadata, occurred_at
			FROM entity_events
			WHERE org_id=$1 AND entity_type=$2 AND entity_id=$3
			  AND occurred_at <= $4
			ORDER BY id ASC
		`, orgID, entityType, entityID, upTo)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEntityEvents(rows)
}

// ListNewEventsBatch returns up to limit events with id > afterID across all
// entity types. Used by the projection worker to process events incrementally.
func (r *EntityEventsRepository) ListNewEventsBatch(
	ctx context.Context,
	afterID int64,
	limit int,
) ([]*EntityEvent, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, entity_type, entity_id, event_type,
		       actor_id, actor_email, payload, metadata, occurred_at
		FROM entity_events
		WHERE id > $1
		ORDER BY id ASC
		LIMIT $2
	`, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEntityEvents(rows)
}

// scanEntityEvents is the shared row scanner for all query results.
func scanEntityEvents(rows pgx.Rows) ([]*EntityEvent, error) {
	var events []*EntityEvent
	for rows.Next() {
		e := &EntityEvent{}
		var payloadRaw, metaRaw []byte
		if err := rows.Scan(
			&e.ID, &e.OrgID, &e.EntityType, &e.EntityID, &e.EventType,
			&e.ActorID, &e.ActorEmail, &payloadRaw, &metaRaw, &e.OccurredAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(payloadRaw, &e.Payload)
		_ = json.Unmarshal(metaRaw, &e.Metadata)
		events = append(events, e)
	}
	return events, rows.Err()
}

// ── Projection read/write ─────────────────────────────────────────────────────

// EntityProjection is the folded current state of one entity.
type EntityProjection struct {
	OrgID        uuid.UUID
	EntityType   string
	EntityID     string
	State        map[string]any
	LastEventID  int64
	ProjectedAt  time.Time
}

// UpsertProjection persists a folded projection row (upsert on primary key).
// Called by the projection worker after folding a batch of events.
func (r *EntityEventsRepository) UpsertProjection(ctx context.Context, p *EntityProjection) error {
	stateJSON, err := json.Marshal(p.State)
	if err != nil {
		stateJSON = []byte("{}")
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO entity_events_projection
		    (org_id, entity_type, entity_id, state, last_event_id, projected_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (org_id, entity_type, entity_id) DO UPDATE
		    SET state         = EXCLUDED.state,
		        last_event_id = EXCLUDED.last_event_id,
		        projected_at  = EXCLUDED.projected_at
	`, p.OrgID, p.EntityType, p.EntityID, stateJSON, p.LastEventID, p.ProjectedAt)
	return err
}

// GetProjection reads the latest folded state for a single entity.
// Returns nil, nil if no projection exists yet (entity has no events).
func (r *EntityEventsRepository) GetProjection(
	ctx context.Context,
	orgID uuid.UUID,
	entityType, entityID string,
) (*EntityProjection, error) {
	p := &EntityProjection{
		OrgID:      orgID,
		EntityType: entityType,
		EntityID:   entityID,
	}
	var stateRaw []byte
	err := r.pool.QueryRow(ctx, `
		SELECT state, last_event_id, projected_at
		FROM entity_events_projection
		WHERE org_id=$1 AND entity_type=$2 AND entity_id=$3
	`, orgID, entityType, entityID).Scan(&stateRaw, &p.LastEventID, &p.ProjectedAt)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal(stateRaw, &p.State)
	return p, nil
}

// MaxProjectedEventID returns the global watermark — the highest entity_events.id
// that has been folded into any projection row. The projection worker starts
// from this value on each run.
func (r *EntityEventsRepository) MaxProjectedEventID(ctx context.Context) (int64, error) {
	var maxID int64
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(last_event_id), 0) FROM entity_events_projection
	`).Scan(&maxID)
	return maxID, err
}

// ── Time-travel snapshot ──────────────────────────────────────────────────────

// SnapshotFromEvents replays entity_events for the given entity up to atTime
// and returns the deterministic reconstructed state.
//
// Unlike AuditRepository.SnapshotEntity (which folds audit_logs metadata),
// this function uses entity_events as the source of truth. Every payload field
// is applied in event order using JSON merge-patch semantics (later fields
// overwrite earlier ones). The result is always consistent with the actual DB
// mutations because events are written inside the same transaction.
//
// Returns nil state (empty map) if no events exist before atTime — the entity
// did not exist at that point in time.
func (r *EntityEventsRepository) SnapshotFromEvents(
	ctx context.Context,
	orgID uuid.UUID,
	entityType, entityID string,
	atTime time.Time,
) (*EntitySnapshot, error) {
	events, err := r.ListEntityEvents(ctx, orgID, entityType, entityID, atTime)
	if err != nil {
		return nil, err
	}

	snap := &EntitySnapshot{
		OrgID:           orgID,
		EntityType:      entityType,
		EntityID:        entityID,
		ReconstructedAt: atTime,
		State:           make(map[string]any),
	}

	if len(events) == 0 {
		return snap, nil
	}

	// Fold all events in chronological order (JSON merge-patch semantics).
	for _, e := range events {
		// Track first/last timestamps.
		if snap.FirstSeenAt == nil {
			t := e.OccurredAt
			snap.FirstSeenAt = &t
		}
		t := e.OccurredAt
		snap.LastModifiedAt = &t

		// Apply payload delta.
		for k, v := range e.Payload {
			snap.State[k] = v
		}

		// Add to change log.
		entry := ChangeEntry{
			At:        e.OccurredAt,
			Action:    e.EventType,
			Status:    "success",
			ActorID:   e.ActorID,
			ActorEmail: e.ActorEmail,
			After:     e.Payload,
		}
		snap.ChangeLog = append(snap.ChangeLog, entry)
	}

	return snap, nil
}
