-- 000122_session_isolation.up.sql
--
-- Adds session_isolation to oidc_clients.
--
-- When TRUE, the client's SSO session is stored under a per-client cookie name
-- (clavex_iso_<hash>) and is never shared with other clients in the same org.
-- Login on App A does not grant silent SSO access to App B.

ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS session_isolation BOOLEAN NOT NULL DEFAULT FALSE;
