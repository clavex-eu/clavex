-- Track when each OIDC client last successfully obtained a token.
-- Used by the Object Lifecycle Management dashboard to identify
-- stale / unused clients that are candidates for deprecation.
ALTER TABLE oidc_clients ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
