CREATE TABLE org_branding (
    org_id          UUID        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    company_name    TEXT,
    logo_url        TEXT,
    favicon_url     TEXT,
    primary_color   TEXT        NOT NULL DEFAULT '#4f46e5',
    bg_color        TEXT        NOT NULL DEFAULT '#f9fafb',
    text_color      TEXT        NOT NULL DEFAULT '#111827',
    welcome_title   TEXT        NOT NULL DEFAULT 'Sign in',
    welcome_subtitle TEXT,
    custom_css      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
