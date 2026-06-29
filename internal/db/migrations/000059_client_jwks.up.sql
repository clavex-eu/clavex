-- 000059: Add inline JWKS column to oidc_clients for private_key_jwt client auth.
-- Clients that authenticate via private_key_jwt (RFC 7523) can register their
-- public key set either as an inline JSON object (jwks) or as a remote URI
-- (jwks_uri, already present). The server tries inline JWKS first; if nil it
-- falls back to fetching jwks_uri.
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS jwks JSONB;
