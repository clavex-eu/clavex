ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS userinfo_signed_response_alg TEXT NOT NULL DEFAULT '';
