-- Migration 000130: store mTLS cert thumbprint in refresh_tokens
--
-- RFC 8705 §3.2: the authorization server SHOULD store the thumbprint of the
-- TLS client certificate used at the time of the initial authorization and bind
-- any subsequently issued access tokens to the same thumbprint.
--
-- When a refresh token request arrives without a client certificate (e.g. because
-- the reverse proxy does not forward the cert header on subsequent requests), the
-- server can still produce a certificate-bound access token by reading the
-- thumbprint that was stored here during the initial authorization code exchange.

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS mtls_x5t_s256 TEXT;
