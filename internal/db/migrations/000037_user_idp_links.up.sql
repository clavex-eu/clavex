-- user_idp_links stores the mapping between a Clavex user and their pseudonymous
-- subject identifier at an external identity provider.
-- This is required for IdPs like FranceConnect and itsme where `sub` is
-- per-SP pseudonymous and must be used as the primary key for identity resolution.
CREATE TABLE IF NOT EXISTS user_idp_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_type TEXT NOT NULL,   -- 'franceconnect' | 'itsme' | 'oidc' | etc.
    external_sub TEXT NOT NULL,    -- the sub claim from the external IdP
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, provider_type),
    UNIQUE (provider_type, external_sub)
);

CREATE INDEX idx_user_idp_links_lookup ON user_idp_links(provider_type, external_sub);
