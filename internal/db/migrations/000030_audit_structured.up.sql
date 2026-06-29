-- 030_audit_structured.up.sql
-- Upgrade the audit log to a fully structured, CloudEvents-compatible schema
-- with per-tenant retention settings and pluggable sink configuration.

-- ── 1. Add structured columns to audit_logs ──────────────────────────────────
ALTER TABLE audit_logs
    -- CloudEvents mandatory fields
    ADD COLUMN IF NOT EXISTS event_id      TEXT,                  -- unique per-event ID (ce-id)
    ADD COLUMN IF NOT EXISTS spec_version  TEXT NOT NULL DEFAULT '1.0',
    ADD COLUMN IF NOT EXISTS event_source  TEXT,                  -- e.g. "https://auth.example.com/acme"
    ADD COLUMN IF NOT EXISTS event_type    TEXT,                  -- mirrors "action" but in ce-type form
    ADD COLUMN IF NOT EXISTS subject       TEXT,                  -- affected resource URI
    -- Context enrichment
    ADD COLUMN IF NOT EXISTS session_id    TEXT,
    ADD COLUMN IF NOT EXISTS request_id    TEXT,
    ADD COLUMN IF NOT EXISTS country_code  CHAR(2),
    ADD COLUMN IF NOT EXISTS data_schema   TEXT,                  -- URL to JSON schema
    -- Delivery tracking
    ADD COLUMN IF NOT EXISTS dispatched_at TIMESTAMPTZ;           -- when fan-out completed

-- Back-fill event_id for existing rows (idempotent on re-run)
UPDATE audit_logs SET event_id = gen_random_uuid()::text WHERE event_id IS NULL;
ALTER TABLE audit_logs ALTER COLUMN event_id SET NOT NULL;
ALTER TABLE audit_logs ALTER COLUMN event_id SET DEFAULT gen_random_uuid()::text;
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_event_id ON audit_logs(event_id);

-- Cursor-based pagination support
CREATE INDEX IF NOT EXISTS idx_audit_org_cursor ON audit_logs(org_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(org_id, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(org_id, resource_type, resource_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs(org_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_logs(session_id) WHERE session_id IS NOT NULL;

-- ── 2. Per-tenant audit retention settings ──────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_retention (
    org_id              UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    retention_days      INT  NOT NULL DEFAULT 90   CHECK (retention_days BETWEEN 1 AND 3650),
    export_enabled      BOOL NOT NULL DEFAULT FALSE,
    -- optional S3/GCS/SFTP export target (stored as JSONB for flexibility)
    export_config       JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── 3. Audit sink definitions (fan-out targets per org) ──────────────────────
CREATE TABLE IF NOT EXISTS audit_sinks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    sink_type       TEXT NOT NULL CHECK (sink_type IN ('webhook','http','mqtt','kafka')),
    is_active       BOOL NOT NULL DEFAULT TRUE,
    -- Type-specific configuration stored as JSONB
    -- webhook: {url, secret, headers:{}}
    -- http:    {url, method, headers:{}, timeout_seconds}
    -- mqtt:    {broker, topic, qos, client_id, username, password, tls}
    -- kafka:   {brokers:[], topic, sasl_mechanism, username, password, tls}
    config          JSONB NOT NULL DEFAULT '{}',
    -- Filter: only forward events matching these criteria (null = all)
    filter_actions  TEXT[],                 -- e.g. ARRAY['user.login','user.login.failed']
    filter_statuses TEXT[],                 -- e.g. ARRAY['failure']
    -- Delivery stats
    last_success_at TIMESTAMPTZ,
    last_error_at   TIMESTAMPTZ,
    last_error_msg  TEXT,
    success_count   BIGINT NOT NULL DEFAULT 0,
    failure_count   BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_sinks_org ON audit_sinks(org_id) WHERE is_active = TRUE;
