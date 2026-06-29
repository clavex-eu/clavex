-- 000011_protocol_mappers.up.sql

-- Protocol mappers transform user attributes into token claims.
-- Each mapper is scoped to an OIDC client.
-- mapper_type values:
--   'user_property'    — built-in user field: email, first_name, last_name, sub
--   'user_attribute'   — arbitrary key from users.metadata JSONB
--   'hardcoded'        — always emit a constant claim value
--   'role_list'        — emit the user's roles in a configurable claim
--   'group_membership' — emit the user's groups in a configurable claim
CREATE TABLE protocol_mappers (
    id                  UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_id           TEXT    NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    name                TEXT    NOT NULL,
    mapper_type         TEXT    NOT NULL,
    claim_name          TEXT    NOT NULL,
    claim_value         TEXT,               -- for 'hardcoded'
    attribute_name      TEXT,               -- for user_property / user_attribute
    add_to_access_token BOOLEAN NOT NULL DEFAULT TRUE,
    add_to_id_token     BOOLEAN NOT NULL DEFAULT TRUE,
    add_to_userinfo     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(client_id, name)
);

CREATE INDEX idx_protocol_mappers_client ON protocol_mappers(client_id);
