-- Actions V2 — generic HTTP hooks on API events.
-- Operators configure named targets (external HTTP endpoints) and bind them to
-- event types via executions. When an event fires, Clavex POSTs to the target
-- and (for synchronous events) uses the response to modify behaviour.
--
-- Supported event types:
--   user.pre_login   (sync)  — can deny login or inject extra claims
--   user.pre_token   (sync)  — can inject/override token claims
--   user.created     (async) — external provisioning on new user
--   user.updated     (async) — sync attributes to external systems
--   user.deleted     (async) — deprovisioning

CREATE TABLE IF NOT EXISTS action_targets (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    url             TEXT        NOT NULL,
    -- Timeout in milliseconds for synchronous calls (100–30 000).
    timeout_ms      INT         NOT NULL DEFAULT 3000 CHECK (timeout_ms BETWEEN 100 AND 30000),
    -- HMAC-SHA256 signing secret; if set, Clavex sends X-Clavex-Signature header.
    signing_secret  TEXT,
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS action_targets_org ON action_targets(org_id) WHERE is_active = TRUE;

CREATE TABLE IF NOT EXISTS action_executions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id       UUID        NOT NULL REFERENCES action_targets(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    -- event_type determines when this execution fires.
    event_type      TEXT        NOT NULL
                    CHECK (event_type IN (
                        'user.pre_login', 'user.pre_token',
                        'user.created', 'user.updated', 'user.deleted'
                    )),
    -- Optional condition filter as JSONB (e.g. {"client_id":"my-app"}).
    -- Empty object {} means "always run".
    condition       JSONB       NOT NULL DEFAULT '{}',
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS action_executions_org_event
    ON action_executions(org_id, event_type) WHERE is_active = TRUE;
