ALTER TABLE oidc_clients
    ADD COLUMN spid_enabled boolean NOT NULL DEFAULT false;

UPDATE oidc_clients
SET spid_enabled = true
WHERE 'spid' = ANY(enabled_login_providers);

ALTER TABLE oidc_clients DROP COLUMN enabled_login_providers;
