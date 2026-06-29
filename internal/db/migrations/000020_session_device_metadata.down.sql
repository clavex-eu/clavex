ALTER TABLE sessions.refresh_tokens
    DROP COLUMN IF EXISTS user_agent,
    DROP COLUMN IF EXISTS ip_address,
    DROP COLUMN IF EXISTS device_name,
    DROP COLUMN IF EXISTS last_seen_at;
