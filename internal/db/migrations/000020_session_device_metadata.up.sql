-- Add device/session metadata columns to refresh_tokens so sessions can be
-- listed and revoked per-device in the admin console and user self-service UI.
ALTER TABLE sessions.refresh_tokens
    ADD COLUMN IF NOT EXISTS user_agent   TEXT,
    ADD COLUMN IF NOT EXISTS ip_address   TEXT,
    ADD COLUMN IF NOT EXISTS device_name  TEXT,
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
