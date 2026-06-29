-- 000012_password_policy.up.sql
-- Per-org password complexity and rotation policy
CREATE TABLE org_password_policy (
    org_id              UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    min_length          INT  NOT NULL DEFAULT 8,
    require_uppercase   BOOL NOT NULL DEFAULT FALSE,
    require_number      BOOL NOT NULL DEFAULT FALSE,
    require_symbol      BOOL NOT NULL DEFAULT FALSE,
    max_age_days        INT,          -- NULL = never expires
    prevent_reuse_count INT  NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
