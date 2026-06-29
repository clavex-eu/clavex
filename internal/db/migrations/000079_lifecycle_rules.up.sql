-- Joiner/Mover/Leaver workflow engine
-- lifecycle_rules: configurable rules applied when users are created, updated, or deactivated.

CREATE TABLE IF NOT EXISTS identity.lifecycle_rules (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT,
    -- 'joiner': user created · 'mover': attribute change · 'leaver': user deactivated/deleted
    trigger     TEXT        NOT NULL CHECK (trigger IN ('joiner', 'mover', 'leaver')),
    -- lower number = higher priority; first matching rule wins per trigger type
    priority    INTEGER     NOT NULL DEFAULT 0,
    -- JSON array of condition objects: [{field, op, value}]
    -- Supported fields: email, first_name, last_name, is_active, and any metadata key
    -- Supported ops: eq, neq, contains, starts_with, ends_with, exists, not_exists
    -- Empty array = match all users
    conditions  JSONB       NOT NULL DEFAULT '[]',
    -- JSON array of action objects: [{type, ...params}]
    -- Supported types: assign_role, remove_role, add_to_group, remove_from_group,
    --                  revoke_sessions, send_notification
    actions     JSONB       NOT NULL DEFAULT '[]',
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS lifecycle_rules_org_trigger_idx
    ON identity.lifecycle_rules (org_id, trigger, priority);
