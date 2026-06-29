-- 000131_client_org_token_ttl.up.sql
--
-- Adds per-client and per-org token TTL overrides.
--
-- Hierarchy at issuance: global default → org override → client override (client wins).
-- NULL means "inherit from the next level up".
-- 0 is treated as "reset to NULL / server default" by the admin API.

ALTER TABLE oidc_clients
    ADD COLUMN access_token_ttl  INTEGER DEFAULT NULL,
    ADD COLUMN refresh_token_ttl INTEGER DEFAULT NULL;

ALTER TABLE organizations
    ADD COLUMN access_token_ttl  INTEGER DEFAULT NULL,
    ADD COLUMN refresh_token_ttl INTEGER DEFAULT NULL;

COMMENT ON COLUMN oidc_clients.access_token_ttl  IS 'Per-client access token lifetime (seconds). NULL = inherit from org or server default.';
COMMENT ON COLUMN oidc_clients.refresh_token_ttl IS 'Per-client refresh token lifetime (seconds). NULL = inherit from org or server default.';
COMMENT ON COLUMN organizations.access_token_ttl  IS 'Per-org access token lifetime (seconds). NULL = use server default.';
COMMENT ON COLUMN organizations.refresh_token_ttl IS 'Per-org refresh token lifetime (seconds). NULL = use server default.';
