-- 000131_client_org_token_ttl.down.sql

ALTER TABLE oidc_clients
    DROP COLUMN IF EXISTS access_token_ttl,
    DROP COLUMN IF EXISTS refresh_token_ttl;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS access_token_ttl,
    DROP COLUMN IF EXISTS refresh_token_ttl;
