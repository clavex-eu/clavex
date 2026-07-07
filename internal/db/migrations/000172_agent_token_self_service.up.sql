-- Self-service agent grants + UEBA step-up support.
--
-- 1. last_used_at lets the end-user (and admin) see when an agent token was last
--    presented to a resource server (updated best-effort on introspection).
-- 2. agent_token_usage records one row per introspection of an active agent
--    token. It is the behavioural history the UEBA agent scorer consumes to
--    detect anomalous call frequency and scope drift for a specific agent_id.
ALTER TABLE agent_tokens
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS agent_token_usage (
    id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id    UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id  TEXT        NOT NULL,            -- stable AI-agent identity ("claude-mcp-v1")
    jti       TEXT        NOT NULL,            -- JWT ID of the presented token
    scope     TEXT        NOT NULL DEFAULT '', -- space-separated scopes on the token
    used_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Baseline queries scan by (org_id, agent_id) ordered/filtered on used_at.
CREATE INDEX IF NOT EXISTS agent_token_usage_agent_idx
    ON agent_token_usage (org_id, agent_id, used_at DESC);
