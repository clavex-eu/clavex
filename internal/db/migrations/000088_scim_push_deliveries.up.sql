-- 000088_scim_push_deliveries.up.sql
-- Delivery log for Clavex SCIM outbound push.
-- Every push attempt (success or failure) is recorded here so operators can
-- audit the hub-and-spoke bidirectional sync and retry failed deliveries from
-- the admin console.

CREATE TABLE scim_push_deliveries (
    id              BIGSERIAL       PRIMARY KEY,
    -- The outbound push config that was used.
    config_id       UUID            NOT NULL REFERENCES scim_push_configs(id) ON DELETE CASCADE,
    -- Trigger event (user.created, user.updated, user.deactivated, group.created, …)
    event           TEXT            NOT NULL,
    -- Subject: user or group UUID (NULL when the entity was deleted before delivery)
    subject_id      UUID,
    subject_type    TEXT            NOT NULL DEFAULT 'user', -- 'user' | 'group'
    -- Outcome
    http_status     INT,            -- NULL = network error (no response received)
    error_msg       TEXT,           -- NULL on success
    duration_ms     INT,            -- request round-trip in milliseconds
    success         BOOLEAN         NOT NULL GENERATED ALWAYS AS (http_status IS NOT NULL AND http_status < 400) STORED,
    -- Timestamps
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Queries: list deliveries for a config (admin delivery log)
CREATE INDEX idx_scim_push_deliveries_config ON scim_push_deliveries(config_id, created_at DESC);
-- Queries: recent failures (for retry UI)
CREATE INDEX idx_scim_push_deliveries_fail   ON scim_push_deliveries(config_id, created_at DESC)
    WHERE success = FALSE;
