ALTER TABLE agent_tokens
    DROP COLUMN IF EXISTS mcp_server_id,
    DROP COLUMN IF EXISTS mcp_resource_url;
