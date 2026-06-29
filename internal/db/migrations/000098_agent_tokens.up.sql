-- Agent Tokens: machine identities for AI agents acting on behalf of users.
-- An agent token is an OAuth 2.0 access token with additional claims:
--   agent_id (free-form identifier for the AI agent, e.g. "claude-mcp-v1")
--   delegated_by (user_id — the human principal who granted the delegation)
--   scope (subset of the user's permissions, space-separated)
-- Tokens are revocable independently from the user's browser session.
CREATE TABLE agent_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id    TEXT        NOT NULL,              -- e.g. "claude-mcp-v1", "gpt-plugin"
    agent_name  TEXT        NOT NULL,              -- human-readable label
    scope       TEXT        NOT NULL DEFAULT '',   -- space-separated OAuth 2.0 scopes
    jti         TEXT        NOT NULL UNIQUE,       -- JWT ID; used for revocation check
    is_revoked  BOOLEAN     NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    revoked_by  UUID        REFERENCES users(id),  -- admin who issued the revocation
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  UUID        REFERENCES users(id)   -- admin who issued the token
);

CREATE INDEX agent_tokens_org_user_idx   ON agent_tokens(org_id, user_id);
CREATE INDEX agent_tokens_jti_idx        ON agent_tokens(jti);
CREATE INDEX agent_tokens_org_active_idx ON agent_tokens(org_id, is_revoked, expires_at);
