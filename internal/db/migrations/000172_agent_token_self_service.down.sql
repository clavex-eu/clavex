DROP TABLE IF EXISTS agent_token_usage;
ALTER TABLE agent_tokens DROP COLUMN IF EXISTS last_used_at;
