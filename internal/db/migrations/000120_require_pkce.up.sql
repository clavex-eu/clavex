-- 000120_require_pkce.up.sql
--
-- Adds require_pkce to oidc_clients.
--
-- When TRUE the PAR endpoint (and authorize endpoint) MUST reject authorization
-- requests that do not include a code_challenge with method S256.
-- Required for FAPI 2.0 Security Profile compliance (§5.2.2-18 / RFC 7636).
-- Defaults to FALSE so existing clients are unaffected.

ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS require_pkce BOOLEAN NOT NULL DEFAULT FALSE;
