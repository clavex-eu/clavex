-- Entity Review Campaigns — Object Lifecycle Management
-- Extends access-review certification to the entities themselves:
-- OIDC clients, groups, and roles. Admins confirm periodically that an entity
-- is still needed; if no response by the deadline the entity is auto-disabled.

CREATE TABLE IF NOT EXISTS entity_review_campaigns (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    description     TEXT,
    -- entity_type: 'client' | 'group' | 'role'
    entity_type     TEXT        NOT NULL CHECK (entity_type IN ('client', 'group', 'role')),
    -- How many days between recurrences (0 = one-shot).
    frequency_days  INT         NOT NULL DEFAULT 90,
    -- status: 'pending' | 'active' | 'completed' | 'cancelled'
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'completed', 'cancelled')),
    starts_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ends_at         TIMESTAMPTZ NOT NULL,
    -- Days before ends_at to send reminders (e.g. ARRAY[7,1]).
    reminder_days   INTEGER[]   NOT NULL DEFAULT '{7,1}',
    -- If TRUE, entities not confirmed before ends_at are automatically disabled.
    auto_disable    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_by      UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS entity_review_campaigns_org_status
    ON entity_review_campaigns(org_id, status);

CREATE TABLE IF NOT EXISTS entity_review_items (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id      UUID        NOT NULL REFERENCES entity_review_campaigns(id) ON DELETE CASCADE,
    org_id           UUID        NOT NULL,
    -- entity_type mirrors the campaign's entity_type.
    entity_type      TEXT        NOT NULL CHECK (entity_type IN ('client', 'group', 'role')),
    -- entity_id: client_id TEXT for clients; UUID string for groups/roles.
    entity_id        TEXT        NOT NULL,
    entity_name      TEXT        NOT NULL,
    reviewer_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- decision: 'pending' | 'confirmed' | 'deprecated' | 'auto_deprecated'
    decision         TEXT        NOT NULL DEFAULT 'pending'
                     CHECK (decision IN ('pending', 'confirmed', 'deprecated', 'auto_deprecated')),
    -- One-time token embedded in approve / deprecate email links.
    token            TEXT        NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(32), 'hex'),
    decided_at       TIMESTAMPTZ,
    comment          TEXT,
    last_reminded_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS entity_review_items_campaign
    ON entity_review_items(campaign_id, decision);

CREATE INDEX IF NOT EXISTS entity_review_items_reviewer
    ON entity_review_items(reviewer_id, decision);
