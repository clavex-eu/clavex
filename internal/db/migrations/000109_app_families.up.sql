-- 000109: Application Families — groups of OIDC clients for seamless cross-app SSO.
-- When a user logs out from any member client, all other members receive a
-- backchannel logout notification.  When a user is already authenticated in one
-- member app, other family apps can accept the SSO session without re-login.
CREATE TABLE app_families (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX idx_app_families_org ON app_families(org_id);

CREATE TABLE app_family_members (
    family_id               UUID        NOT NULL REFERENCES app_families(id) ON DELETE CASCADE,
    client_id               TEXT        NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    backchannel_logout_uri  TEXT,      -- optional: POST logout_token here on family-wide logout
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (family_id, client_id)
);
CREATE INDEX idx_app_family_members_client ON app_family_members(client_id);
