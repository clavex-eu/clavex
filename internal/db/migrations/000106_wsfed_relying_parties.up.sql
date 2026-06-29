-- 000106: WS-Federation relying party registry.
-- Each row is a registered SP (e.g. SharePoint site) that can federate with Clavex
-- using the WS-Federation Passive Requestor Profile.
CREATE TABLE wsfed_relying_parties (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                    TEXT        NOT NULL,
    realm                   TEXT        NOT NULL,  -- wtrealm: unique RP identifier (URN or URL)
    wreply_uris             TEXT[]      NOT NULL DEFAULT '{}',  -- allowed wreply URLs
    token_lifetime_seconds  INT         NOT NULL DEFAULT 3600,
    claims_mapping          JSONB       NOT NULL DEFAULT '{}', -- {"givenname":"first_name", ...}
    is_active               BOOL        NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, realm)
);
CREATE INDEX idx_wsfed_rp_org ON wsfed_relying_parties(org_id);
