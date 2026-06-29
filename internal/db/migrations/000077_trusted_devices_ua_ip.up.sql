-- Add user_agent and last_ip to trusted_devices for the account portal device audit UI.
-- These columns let users see "Chrome 124 on macOS" and the IP that enrolled the device.

ALTER TABLE trusted_devices
    ADD COLUMN IF NOT EXISTS user_agent TEXT,
    ADD COLUMN IF NOT EXISTS last_ip    INET;
