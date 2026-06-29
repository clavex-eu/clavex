-- Shared Signals Framework (SSF) — RFC 8935/8936 + CAEP
-- ssf_streams holds receiver stream registrations per org.
-- Each stream is a subscription from a Relying Party (receiver) to
-- this OP (transmitter) for a set of CAEP/RISC security event types.

CREATE TABLE IF NOT EXISTS ssf_streams (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_id        TEXT NOT NULL,        -- the OIDC client that owns this stream
    -- Delivery: "push" = RFC 8935, "poll" = RFC 8936
    delivery_method  TEXT NOT NULL DEFAULT 'push'
                         CHECK (delivery_method IN ('push', 'poll')),
    push_endpoint    TEXT,                  -- required when delivery_method = 'push'
    -- HMAC-SHA256 secret for verifying push delivery (webhook-style)
    push_secret_hash TEXT,
    -- RFC 8936 poll streams: SETs queued in ssf_pending_sets
    -- Enabled event types (subset of all supported types)
    events_requested TEXT[] NOT NULL DEFAULT '{
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        "https://schemas.openid.net/secevent/caep/event-type/credential-change",
        "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
        "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
        "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
    }',
    status           TEXT NOT NULL DEFAULT 'enabled'
                         CHECK (status IN ('enabled', 'paused', 'disabled')),
    -- Receiver-provided description (optional)
    description      TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, client_id)
);

CREATE INDEX idx_ssf_streams_org ON ssf_streams(org_id);
CREATE INDEX idx_ssf_streams_client ON ssf_streams(client_id);

-- ssf_pending_sets holds SETs queued for poll-based delivery (RFC 8936).
-- Push streams do not use this table — SETs are delivered immediately by the worker.
-- The jti column is the JWT ID of the SET (unique across all streams).
CREATE TABLE IF NOT EXISTS ssf_pending_sets (
    jti         TEXT PRIMARY KEY,          -- JWT ID of the SET
    stream_id   UUID NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
    payload     JSONB NOT NULL,            -- full SET JWT (compact serialization stored as text in json key)
    event_type  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Receivers acknowledge sets by JTI; acknowledged sets are deleted.
    -- Sets older than 7 days are purged by a background job.
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '7 days'
);

CREATE INDEX idx_ssf_pending_sets_stream ON ssf_pending_sets(stream_id, created_at);
CREATE INDEX idx_ssf_pending_sets_expires ON ssf_pending_sets(expires_at);
