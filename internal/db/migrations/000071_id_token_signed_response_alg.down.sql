ALTER TABLE identity.oidc_clients
    DROP COLUMN IF EXISTS id_token_signed_response_alg;
