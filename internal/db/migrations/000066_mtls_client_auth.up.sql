-- 000066_mtls_client_auth: adds mTLS client authentication fields to OIDC clients.
--
-- RFC 8705 §2.3 defines that when token_endpoint_auth_method is "tls_client_auth"
-- the authorization server identifies the client by matching the Subject
-- Distinguished Name (or SAN) of the presented certificate.
--
-- tls_client_auth_subject_dn: the full RFC 4514 Subject DN string that the
--   client's TLS certificate must match, e.g.
--   "CN=my-service,O=Acme Corp,C=US"
--
-- tls_client_auth_san_dns: alternative to subject_dn — the client cert's
--   Subject Alternative Name DNS entry to match, e.g. "myservice.example.com"
--   (RFC 8705 §2.3 allows SAN-based matching as well as DN matching).
--
-- Exactly one of subject_dn or san_dns should be set for tls_client_auth clients.
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS tls_client_auth_subject_dn TEXT,
    ADD COLUMN IF NOT EXISTS tls_client_auth_san_dns    TEXT;
