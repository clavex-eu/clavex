CREATE TABLE IF NOT EXISTS eidas_configs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    entity_id       TEXT        NOT NULL,
    eidas_node_url  TEXT        NOT NULL,
    acs_url         TEXT        NOT NULL,
    idp_cert_pem    TEXT        NOT NULL,
    sp_cert_pem     TEXT        NOT NULL,
    sp_key_pem      TEXT        NOT NULL,
    requested_loa   TEXT        NOT NULL DEFAULT 'http://eidas.europa.eu/LoA/substantial',
    org_name        TEXT        NOT NULL DEFAULT '',
    org_display_name TEXT       NOT NULL DEFAULT '',
    org_url         TEXT        NOT NULL DEFAULT '',
    contact_email   TEXT        NOT NULL DEFAULT '',
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id)
);

CREATE INDEX IF NOT EXISTS eidas_configs_org_id_idx ON eidas_configs (org_id);
