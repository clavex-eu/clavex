-- 000136_oid4vci_vpr.down.sql
DROP INDEX IF EXISTS credential_offers_vp_session;
ALTER TABLE credential_offers DROP COLUMN IF EXISTS vp_session_id;
ALTER TABLE credential_configs DROP COLUMN IF EXISTS presentation_definition_vpr;
ALTER TABLE credential_configs DROP COLUMN IF EXISTS require_vp;
