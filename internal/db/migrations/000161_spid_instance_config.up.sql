-- ── SPID instance-level SP config (singleton) ───────────────────────────────
-- Replaces the per-org SP identity fields in spid_configs.
-- One row for the whole Clavex instance: EntityID, signing keypair, legal info.
CREATE TABLE spid_instance_config (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id        TEXT        NOT NULL,
    org_name         TEXT        NOT NULL DEFAULT '',
    org_display_name TEXT        NOT NULL DEFAULT '',
    org_locality     TEXT        NOT NULL DEFAULT '',
    org_url          TEXT        NOT NULL DEFAULT '',
    contact_email    TEXT        NOT NULL DEFAULT '',
    contact_phone    TEXT,
    vat_number       TEXT,
    ipa_code         TEXT,
    entity_type      TEXT        NOT NULL DEFAULT 'private'
                         CHECK (entity_type IN ('private', 'public')),
    sp_cert_pem      TEXT,
    sp_key_pem       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enforce singleton: at most one row.
CREATE UNIQUE INDEX spid_instance_config_singleton ON spid_instance_config ((true));

-- Remove SP identity columns from spid_configs; keep only per-org auth preferences.
ALTER TABLE spid_configs
    DROP COLUMN IF EXISTS entity_id,
    DROP COLUMN IF EXISTS org_name,
    DROP COLUMN IF EXISTS org_display_name,
    DROP COLUMN IF EXISTS org_locality,
    DROP COLUMN IF EXISTS org_url,
    DROP COLUMN IF EXISTS contact_email,
    DROP COLUMN IF EXISTS contact_phone,
    DROP COLUMN IF EXISTS vat_number,
    DROP COLUMN IF EXISTS ipa_code,
    DROP COLUMN IF EXISTS entity_type,
    DROP COLUMN IF EXISTS sp_cert_pem,
    DROP COLUMN IF EXISTS sp_key_pem;
