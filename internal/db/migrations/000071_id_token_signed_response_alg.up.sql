ALTER TABLE identity.oidc_clients
    ADD COLUMN IF NOT EXISTS id_token_signed_response_alg TEXT NOT NULL DEFAULT '';
