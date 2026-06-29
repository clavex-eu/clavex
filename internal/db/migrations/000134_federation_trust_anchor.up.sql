-- 000134: EUDIW / eIDAS 2.0 Trust Anchor support for OpenID Federation 1.0.
--
-- Enables Clavex to act as a private Trust Anchor for banking consortia,
-- university federations, and eIDAS 2.0 wallet ecosystems.
--
-- New tables:
--   federation_subordinates  — registered subordinate entities (RPs, OPs, Wallet Providers)
--   federation_trust_marks   — issued trust marks per OIDF §8
--   federation_trust_mark_types — trust mark definitions managed by the TA operator

-- ── Subordinate entities ─────────────────────────────────────────────────────

CREATE TABLE federation_subordinates (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- OIDF entity identifier (URI), unique per TA org.
    entity_id           TEXT        NOT NULL,

    -- Human-readable name for the subordinate.
    name                TEXT        NOT NULL DEFAULT '',

    -- Entity type(s): "openid_provider", "openid_relying_party", "wallet_provider",
    -- "credential_issuer", "federation_entity" etc.
    entity_types        TEXT[]      NOT NULL DEFAULT '{}',

    -- The subordinate's own federation JWKS (public keys used to verify its Entity Config).
    -- JSON object {"keys":[...]}
    jwks                JSONB,

    -- The subordinate's JWKS URI (alternative to inline jwks).
    jwks_uri            TEXT,

    -- Optional metadata to include verbatim in the subordinate's entity statement.
    -- JSON object keyed by entity type, e.g. {"openid_relying_party": {...}}.
    metadata_override   JSONB,

    -- Metadata policy to enforce for this subordinate (OIDF §5).
    -- JSON object keyed by entity type.
    metadata_policy     JSONB,

    -- Trust mark IDs granted to this subordinate (array of trust_mark_id strings).
    trust_mark_ids      TEXT[]      NOT NULL DEFAULT '{}',

    -- Lifecycle status.
    status              TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'suspended', 'revoked')),

    -- Entity statement JWT lifetime override (seconds). 0 = use TA default (86400).
    statement_lifetime  INT         NOT NULL DEFAULT 0,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (org_id, entity_id)
);

CREATE INDEX federation_subordinates_org_id   ON federation_subordinates (org_id);
CREATE INDEX federation_subordinates_status    ON federation_subordinates (status);
CREATE INDEX federation_subordinates_entity_id ON federation_subordinates (entity_id);

-- ── Trust Mark type definitions ───────────────────────────────────────────────

CREATE TABLE federation_trust_mark_types (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Trust Mark identifier URI, e.g.
    --   https://ta.example.com/trust-mark/wallet-provider
    --   https://eudiw.ec.europa.eu/PID_Provider
    trust_mark_id   TEXT        NOT NULL,

    -- Human-readable name.
    name            TEXT        NOT NULL DEFAULT '',

    -- Description of what this trust mark certifies.
    description     TEXT        NOT NULL DEFAULT '',

    -- Logo URI shown in federation discovery UIs.
    logo_uri        TEXT,

    -- Reference URI to the policy document governing this trust mark.
    ref_uri         TEXT,

    -- Lifetime in seconds for issued trust marks of this type. Default 365 days.
    lifetime_secs   INT         NOT NULL DEFAULT 31536000,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (org_id, trust_mark_id)
);

CREATE INDEX federation_trust_mark_types_org_id ON federation_trust_mark_types (org_id);

-- ── Issued Trust Marks ────────────────────────────────────────────────────────

CREATE TABLE federation_trust_marks (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Trust Mark identifier URI (references a type in federation_trust_mark_types).
    trust_mark_id   TEXT        NOT NULL,

    -- Subject entity ID (the entity receiving the trust mark).
    subject         TEXT        NOT NULL,

    -- The signed trust-mark+jwt compact JWS ready to be served.
    issued_jwt      TEXT        NOT NULL,

    -- When the trust mark expires (from the JWT exp claim).
    expires_at      TIMESTAMPTZ NOT NULL,

    -- Whether the trust mark has been revoked.
    revoked         BOOLEAN     NOT NULL DEFAULT false,
    revoked_at      TIMESTAMPTZ,
    revoked_reason  TEXT,

    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (org_id, trust_mark_id, subject)
);

CREATE INDEX federation_trust_marks_org_id        ON federation_trust_marks (org_id);
CREATE INDEX federation_trust_marks_subject        ON federation_trust_marks (subject);
CREATE INDEX federation_trust_marks_trust_mark_id  ON federation_trust_marks (trust_mark_id);
CREATE INDEX federation_trust_marks_expires_at     ON federation_trust_marks (expires_at) WHERE NOT revoked;
