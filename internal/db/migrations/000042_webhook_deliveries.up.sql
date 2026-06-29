CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id   UUID        NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Delivery identity
    delivery_id  TEXT        NOT NULL,          -- matches Payload.ID (idempotency key)
    event        TEXT        NOT NULL,
    -- Request
    payload      JSONB       NOT NULL,
    -- Result of the attempt
    attempt      SMALLINT    NOT NULL DEFAULT 1,
    status       TEXT        NOT NULL CHECK (status IN ('pending','success','failed')),
    http_status  SMALLINT,                      -- NULL if network error before response
    error        TEXT,                          -- error message if failed
    duration_ms  INT,                           -- round-trip ms
    -- Timestamps
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id
    ON webhook_deliveries (webhook_id, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_org_id
    ON webhook_deliveries (org_id, attempted_at DESC);
