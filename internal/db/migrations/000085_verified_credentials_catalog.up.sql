-- 000085: Clavex Verified — structured credential catalog for training,
-- qualification, and competency-badge VCs (eIDAS 2.0 / OID4VCI).
--
-- credential_configs.category  — 'identity' (existing) | 'training' | 'qualification' | 'badge'
-- credential_configs.schema_fields — ordered list of claim field descriptors (for admin UI)
-- credential_offers.payload      — arbitrary JSON claims provided at offer creation time
--                                   (used instead of user-profile attributes when non-NULL)

ALTER TABLE credential_configs
    ADD COLUMN IF NOT EXISTS category      TEXT  NOT NULL DEFAULT 'identity',
    ADD COLUMN IF NOT EXISTS schema_fields JSONB NOT NULL DEFAULT '[]';

ALTER TABLE credential_offers
    ADD COLUMN IF NOT EXISTS payload JSONB;

COMMENT ON COLUMN credential_configs.category IS
    'Credential category: identity | training | qualification | badge';
COMMENT ON COLUMN credential_configs.schema_fields IS
    'JSON array of {name, label, type, mandatory} field descriptors shown in the admin issue UI';
COMMENT ON COLUMN credential_offers.payload IS
    'Arbitrary claim payload provided at offer time; when non-NULL overrides user-profile attribute mapping';
