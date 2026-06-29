-- 000065_fga_stores: maps each Clavex organization to an OpenFGA store.
-- One store per org, allowing complete isolation of authorization models
-- and relationship tuples across tenants.
CREATE TABLE IF NOT EXISTS fga_stores (
    org_id     UUID        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    store_id   TEXT        NOT NULL,
    model_id   TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
