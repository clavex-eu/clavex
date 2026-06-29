-- 118_entity_events.up.sql
--
-- Implements a lightweight event-store layer for Clavex.
--
-- Architecture note:
--   Clavex's audit_logs table is an append-only CloudEvents log, but it is a
--   *derived* artefact: if the DB crashes between the UPDATE users SET ... and
--   the INSERT INTO audit_logs ..., the mutation is persisted but no event
--   exists for it. This table closes that gap for the mutations that matter
--   most for compliance (password changes, role assignments, policy changes).
--
--   Writers: repository methods write a row here INSIDE the same transaction
--   as the mutation (e.g. UPDATE users SET password_hash = $1). ACID guarantees
--   that either both succeed or both roll back — the event can never be lost.
--
--   Readers: the projection worker (RunEntityEventsProjectionWorker) periodically
--   folds entity_events into entity_events_projection, which provides an
--   O(1) "current state" read-model. The SnapshotEntityFromEvents function
--   replays events for point-in-time state reconstruction.
--
-- Comparison with Zitadel's EventStore:
--   Zitadel uses entity_events as the *sole* source of truth (CQRS strict).
--   Clavex keeps its relational write-model (users, clients, ...) as the
--   authoritative DB state and uses entity_events as an event log running
--   alongside. This avoids a 6-12 month rewrite while closing the audit gap
--   for the subset of mutations that matter for compliance.

-- ── 1. entity_events — the append-only event store ──────────────────────────

CREATE TABLE entity_events (
    -- Monotonically increasing surrogate key. BIGSERIAL gives cheap total
    -- ordering without UUID comparison overhead. Global ordering across all
    -- orgs and entity types in a single sequence.
    id            BIGSERIAL     PRIMARY KEY,

    -- Tenant scoping
    org_id        UUID          NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Entity identity
    entity_type   TEXT          NOT NULL,  -- 'user' | 'client' | 'org' | 'role' | 'policy' | etc.
    entity_id     TEXT          NOT NULL,  -- UUID of the affected entity (stored as text for flexibility)

    -- Event identity
    event_type    TEXT          NOT NULL,  -- e.g. 'user.password_changed', 'user.role_assigned'
    event_version INT           NOT NULL DEFAULT 1,  -- schema version of the payload

    -- Actor context
    actor_id      UUID,                   -- null for system/automated events
    actor_email   TEXT,

    -- Payload: the "after" state delta — only the changed fields.
    -- For creates, this is the full initial state.
    -- For deletes, this is {"deleted": true} plus any tombstone data.
    -- Kept minimal (deltas, not full snapshots) to control storage growth.
    payload       JSONB         NOT NULL DEFAULT '{}',

    -- Request context for tracing
    metadata      JSONB         NOT NULL DEFAULT '{}',  -- {ip, user_agent, request_id, session_id}

    -- occurred_at is set explicitly by the writer (not defaulted) so that
    -- events written in the same transaction have a consistent timestamp.
    occurred_at   TIMESTAMPTZ   NOT NULL
);

-- Primary access pattern: replay all events for a given entity up to a point.
-- Covers: SnapshotEntityFromEvents, time-travel queries.
CREATE INDEX idx_entity_events_entity
    ON entity_events(org_id, entity_type, entity_id, id);

-- Cross-entity scan: projection worker iterates over new events by id watermark.
CREATE INDEX idx_entity_events_watermark
    ON entity_events(id);

-- Per-org timeline (list recent changes across all entities for an org).
CREATE INDEX idx_entity_events_org_time
    ON entity_events(org_id, occurred_at DESC);


-- ── 2. entity_events_projection — read-model (eventual consistency) ──────────
--
-- The projection worker folds entity_events into this table every N minutes.
-- Each row holds the best-known current state of one entity, reconstructed
-- by replaying all events in order. Querying current state is O(1) — no replay.

CREATE TABLE entity_events_projection (
    org_id          UUID    NOT NULL,
    entity_type     TEXT    NOT NULL,
    entity_id       TEXT    NOT NULL,

    -- Folded state: JSON merge-patch of all payload deltas in event order.
    -- For a user: {"is_active": false, "mfa_required": true, "roles": [...]}
    state           JSONB   NOT NULL DEFAULT '{}',

    -- Watermark: the highest entity_events.id that has been folded into state.
    -- The worker uses this to process only new events incrementally.
    last_event_id   BIGINT  NOT NULL DEFAULT 0,

    -- Timestamp of the last projection run for this entity.
    projected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (org_id, entity_type, entity_id)
);

-- Allow the worker to find entities with unflushed events efficiently.
CREATE INDEX idx_entity_events_projection_watermark
    ON entity_events_projection(last_event_id);
