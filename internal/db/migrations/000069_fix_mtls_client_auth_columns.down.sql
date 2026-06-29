ALTER TABLE oidc_clients
    DROP COLUMN IF EXISTS tls_client_auth_subject_dn,
    DROP COLUMN IF EXISTS tls_client_auth_san_dns;
