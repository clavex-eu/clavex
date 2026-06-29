-- 000121_require_par.up.sql
--
-- Adds require_par to oidc_clients.
--
-- When TRUE the authorization endpoint MUST reject any request that did not
-- arrive via PAR (Pushed Authorization Request, RFC 9126).  This enforces
-- FAPI 2.0 Security Profile ID2 §5.2.2-1 for clients that use unsigned PAR
-- (fapi_request_method=unsigned in the basic DPoP plan) and therefore do not
-- set request_object_signing_alg.

ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS require_par BOOLEAN NOT NULL DEFAULT FALSE;
