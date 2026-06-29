-- Migration 000142: add source_idp_type to credential_configs
--
-- Links a credential configuration to the identity provider type whose verified
-- claims should be embedded in the issued SD-JWT VC.  When set, Clavex:
--   1. Automatically creates a pre-authorized credential offer after a successful
--      login via the referenced IdP.
--   2. Uses the IdP-specific claim mapping instead of the generic user profile.
--
-- Known values: 'franceconnect' | 'spid' | 'cie' | 'itsme' | 'bundid' | 'digid' | 'clave'

ALTER TABLE credential_configs
    ADD COLUMN IF NOT EXISTS source_idp_type TEXT;

CREATE INDEX IF NOT EXISTS idx_credential_configs_source_idp_type
    ON credential_configs (org_id, source_idp_type)
    WHERE source_idp_type IS NOT NULL;
