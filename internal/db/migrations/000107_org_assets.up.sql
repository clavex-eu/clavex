-- 000107: Centralized org asset storage (S3-backed).
-- Tracks uploaded binary assets (logos, favicons, backgrounds) per org.
CREATE TABLE org_assets (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_type      TEXT        NOT NULL CHECK (asset_type IN ('logo','favicon','background','icon')),
    s3_key          TEXT        NOT NULL,
    content_type    TEXT        NOT NULL DEFAULT 'image/png',
    size_bytes      BIGINT      NOT NULL DEFAULT 0,
    url             TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, asset_type)
);
CREATE INDEX idx_org_assets_org ON org_assets(org_id);
