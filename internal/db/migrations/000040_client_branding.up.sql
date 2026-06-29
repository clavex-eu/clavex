CREATE TABLE IF NOT EXISTS client_branding (
    client_id    TEXT PRIMARY KEY REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    company_name TEXT,
    logo_url     TEXT,
    primary_color TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
