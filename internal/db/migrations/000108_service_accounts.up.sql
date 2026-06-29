-- 000108: Org-scoped service accounts for M2M (machine-to-machine) access.
-- Service accounts are first-class entities visible to org admins, distinct
-- from OIDC clients. They use client_credentials grant with their own
-- client_id/secret pair and appear in audit logs with their own identity.
CREATE TABLE service_accounts (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                TEXT        NOT NULL,
    description         TEXT,
    client_id           TEXT        NOT NULL UNIQUE,
    client_secret_hash  TEXT        NOT NULL,
    scopes              TEXT[]      NOT NULL DEFAULT '{}',
    is_active           BOOL        NOT NULL DEFAULT TRUE,
    last_used_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_service_accounts_org ON service_accounts(org_id);
CREATE INDEX idx_service_accounts_client_id ON service_accounts(client_id);
