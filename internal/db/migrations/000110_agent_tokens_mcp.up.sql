-- Add MCP (Model Context Protocol) fields to agent_tokens.
-- mcp_server_id identifies the specific MCP server the token is scoped to,
-- enabling per-server token binding and audit filtering.
-- mcp_resource_url is the canonical resource URL of the MCP server
-- (RFC 8707 Resource Indicators, used to scope the token to one server).
ALTER TABLE agent_tokens
    ADD COLUMN IF NOT EXISTS mcp_server_id   TEXT,
    ADD COLUMN IF NOT EXISTS mcp_resource_url TEXT;

CREATE INDEX IF NOT EXISTS agent_tokens_mcp_server_idx
    ON agent_tokens(org_id, mcp_server_id)
    WHERE mcp_server_id IS NOT NULL;
