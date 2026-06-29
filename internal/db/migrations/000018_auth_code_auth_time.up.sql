-- Add auth_time to track when the user authenticated during the authorization flow.
-- Used to populate the auth_time claim in OIDC ID tokens (OIDC Core §2).
ALTER TABLE sessions.authorization_codes ADD COLUMN auth_time BIGINT NOT NULL DEFAULT 0;
