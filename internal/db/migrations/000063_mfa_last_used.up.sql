-- Add last_used_at to mfa_credentials so we can show "last used" on the
-- self-service passkey device management page.
ALTER TABLE mfa_credentials
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
