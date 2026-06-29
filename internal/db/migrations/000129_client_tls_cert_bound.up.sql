-- Migration 000129: add tls_client_certificate_bound_access_tokens to oidc_clients
--
-- RFC 8705 §3 (Certificate-Bound Access Tokens) requires the authorization
-- server to bind issued access tokens to the TLS client certificate presented
-- at the token endpoint.  When this flag is set to true the token endpoint
-- MUST reject any request that does not carry a valid TLS client certificate.
--
-- Conformance: FAPI 2.0 test fapi2-security-profile-id2-ensure-holder-of-key-required
-- with sender_constrain=mtls registers clients with this field set to true and
-- then verifies that the token endpoint refuses requests sent without a cert.

ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS tls_client_certificate_bound_access_tokens BOOLEAN NOT NULL DEFAULT FALSE;
