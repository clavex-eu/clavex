-- Migration 000144: add format column to credential_configs
--
-- OID4VCI Final §8 credential requests carry a "format" field that selects the
-- credential encoding.  Current values used by Clavex:
--   'vc+sd-jwt'  (default) — W3C SD-JWT-VC per IETF draft-ietf-oauth-sd-jwt-vc
--   'mso_mdoc'             — ISO 18013-5 mobile document (mdoc), signed by a DS key
--
-- Existing rows default to 'vc+sd-jwt' (no behaviour change).

ALTER TABLE credential_configs
    ADD COLUMN IF NOT EXISTS credential_format TEXT NOT NULL DEFAULT 'vc+sd-jwt';

CREATE INDEX IF NOT EXISTS idx_credential_configs_format
    ON credential_configs (org_id, credential_format);
