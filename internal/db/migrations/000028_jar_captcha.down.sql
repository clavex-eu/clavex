ALTER TABLE oidc_clients
    DROP COLUMN IF EXISTS jwks_uri,
    DROP COLUMN IF EXISTS request_object_signing_alg;

DROP TABLE IF EXISTS identity.org_captcha_settings;
