-- fleet_ingest_secret is a random secret that fleet agents use to authenticate
-- their heartbeat webhooks via the X-Fleet-Token header.
-- NULL means fleet ingestion is disabled for that organization.
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS fleet_ingest_secret TEXT;

-- device_facts stores the last-known posture facts emitted by fleet agents.
-- The webhook endpoint upserts rows on each heartbeat, keyed by (org_id, device_id).
CREATE TABLE IF NOT EXISTS device_facts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id       TEXT        NOT NULL,
    user_id         UUID        REFERENCES users(id) ON DELETE SET NULL,
    platform        TEXT,
    facts           JSONB       NOT NULL DEFAULT '{}',
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_device_facts_org_user ON device_facts (org_id, user_id);
