-- 000010_required_actions.up.sql

-- Required actions are stored per-user as a text array.
-- Supported values: 'VERIFY_EMAIL' | 'UPDATE_PASSWORD' | 'CONFIGURE_TOTP'
-- They are consumed during the OIDC authorize flow and cleared upon completion.
ALTER TABLE users ADD COLUMN IF NOT EXISTS required_actions TEXT[] NOT NULL DEFAULT '{}';
