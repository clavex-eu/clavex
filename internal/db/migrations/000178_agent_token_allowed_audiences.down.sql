ALTER TABLE agent_tokens
    DROP COLUMN IF EXISTS audience;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS agent_token_allowed_audiences;
