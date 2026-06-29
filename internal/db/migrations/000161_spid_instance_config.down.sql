DROP TABLE IF EXISTS spid_instance_config;

ALTER TABLE spid_configs
    ADD COLUMN IF NOT EXISTS entity_id        TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS org_name         TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS org_display_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS org_locality     TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS org_url          TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS contact_email    TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS contact_phone    TEXT,
    ADD COLUMN IF NOT EXISTS vat_number       TEXT,
    ADD COLUMN IF NOT EXISTS ipa_code         TEXT,
    ADD COLUMN IF NOT EXISTS entity_type      TEXT NOT NULL DEFAULT 'private',
    ADD COLUMN IF NOT EXISTS sp_cert_pem      TEXT,
    ADD COLUMN IF NOT EXISTS sp_key_pem       TEXT;
