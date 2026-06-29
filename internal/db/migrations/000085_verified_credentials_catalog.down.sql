ALTER TABLE credential_offers
    DROP COLUMN IF EXISTS payload;

ALTER TABLE credential_configs
    DROP COLUMN IF EXISTS schema_fields,
    DROP COLUMN IF EXISTS category;
