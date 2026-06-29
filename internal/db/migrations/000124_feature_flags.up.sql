-- 000124_feature_flags.up.sql
--
-- Feature flags integrated with the auth context (Kinde-style).
--
-- feature_flags:          per-org flag definitions with a boolean default value.
-- feature_flag_overrides: per-user or per-role overrides that win over the default.
--
-- At token issuance time the server resolves each flag to a boolean value for the
-- current user and injects { "flags": { "flag_key": true } } into the JWT claims.
-- The client reads flags from the token — no additional API call required.
--
-- Resolution order (highest priority first):
--   1. per-user override  (target_type = 'user',  target_id = user.id)
--   2. per-role override  (target_type = 'role',  target_id = any assigned role)
--   3. flag default value (feature_flags.value)

CREATE TABLE feature_flags (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key         TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    value       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, key)
);

CREATE TABLE feature_flag_overrides (
    id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    flag_id     UUID    NOT NULL REFERENCES feature_flags(id) ON DELETE CASCADE,
    target_type TEXT    NOT NULL CHECK (target_type IN ('user', 'role')),
    target_id   UUID    NOT NULL,
    value       BOOLEAN NOT NULL,
    UNIQUE (flag_id, target_type, target_id)
);

CREATE INDEX ON feature_flag_overrides (flag_id, target_type, target_id);
