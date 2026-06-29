ALTER TABLE oidc_clients
    ADD COLUMN enabled_login_providers text[] NOT NULL DEFAULT '{}';

UPDATE oidc_clients
SET enabled_login_providers = ARRAY['spid']
WHERE spid_enabled = true;

ALTER TABLE oidc_clients DROP COLUMN spid_enabled;
