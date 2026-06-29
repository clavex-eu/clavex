ALTER TABLE trusted_devices
    DROP COLUMN IF EXISTS user_agent,
    DROP COLUMN IF EXISTS last_ip;
