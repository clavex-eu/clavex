-- 000120_require_pkce.down.sql
ALTER TABLE oidc_clients DROP COLUMN IF EXISTS require_pkce;
