ALTER TABLE oidc_clients
    DROP COLUMN IF EXISTS tls_client_certificate_bound_access_tokens;
