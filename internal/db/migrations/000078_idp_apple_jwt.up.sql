-- Add Apple Sign In With Apple credentials for server-side JWT client_secret generation.
-- Apple requires the client_secret to be a short-lived ES256 JWT signed with the
-- developer's .p8 private key rather than a static secret string.
-- We store the three required components (team_id, key_id, private_key_pem) so
-- Clavex can generate a fresh JWT client_secret on every token exchange.

ALTER TABLE identity_providers
    ADD COLUMN IF NOT EXISTS apple_team_id       TEXT,
    ADD COLUMN IF NOT EXISTS apple_key_id        TEXT,
    ADD COLUMN IF NOT EXISTS apple_private_key   TEXT; -- raw PEM / p8 content
