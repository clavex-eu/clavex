-- 000154_credential_marketplace.up.sql
-- Clavex Credential Marketplace — public catalog of verifiable credential templates.
--
-- PA and private issuers publish templates that anyone can discover and import
-- with one click.  Each listing is tied to an org's credential_config and
-- exposes just the public-facing metadata needed by wallet developers.
--
-- Trust model: only orgs that are either:
--   (a) directly trusted by the Clavex installation's trust anchor, OR
--   (b) manually approved by a Clavex superadmin
-- have their listings shown as "verified".  All others are shown as "pending".

CREATE TABLE IF NOT EXISTS credential_marketplace_listings (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- The credential config that backs this listing (optional: may be
    -- listed without a live config for pre-announcement purposes).
    credential_config_id UUID   REFERENCES credential_configs(id) ON DELETE SET NULL,

    -- ── Display metadata ─────────────────────────────────────────────────────
    -- Short human-readable name, e.g. "Certificato di Residenza".
    display_name    TEXT        NOT NULL,
    -- Long description shown in the detail view.
    description     TEXT,
    -- Issuer display name, e.g. "Comune di Roma".
    issuer_name     TEXT        NOT NULL,
    -- The canonical VCT (Verifiable Credential Type) URI.
    vct             TEXT        NOT NULL,
    -- The SD-JWT/mdoc credential format: "vc+sd-jwt" | "mso_mdoc".
    credential_format TEXT      NOT NULL DEFAULT 'vc+sd-jwt',
    -- BCP 47 language tag of the credential content, e.g. "it", "de", "en".
    lang            TEXT        NOT NULL DEFAULT 'it',

    -- ── Technical integration fields ─────────────────────────────────────────
    -- OID4VCI credential_issuer URL (the /.well-known endpoint base).
    issuer_endpoint TEXT        NOT NULL,
    -- Normative SD-JWT/mdoc claims schema as JSON Schema or compact claims map.
    -- Displayed in the "Schema" tab of the detail view.
    schema_json     JSONB       NOT NULL DEFAULT '{}',
    -- OpenID Credential Offer URI deep-link template.
    -- Use %s as a placeholder for the pre-authorized_code if applicable.
    -- Nil = issuer does not offer a deep-link (wallet must initiate manually).
    offer_template  TEXT,

    -- ── Discovery / search ───────────────────────────────────────────────────
    -- Taxonomy tags, e.g. ["anagrafe","residenza","PA","comune"].
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    -- Full-text search index (updated by a trigger below).
    tsv             TSVECTOR,

    -- ── Trust & moderation ───────────────────────────────────────────────────
    -- "pending" until a superadmin approves, "verified" after approval,
    -- "rejected" if removed.
    status          TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'verified', 'rejected')),
    -- Superadmin-controlled: visible in the public catalog?
    is_public       BOOLEAN     NOT NULL DEFAULT false,
    -- Notes from the superadmin (rejection reason, etc.).
    moderation_note TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────────────────────────

-- Fast lookup by org (for the "manage my listings" admin view).
CREATE INDEX IF NOT EXISTS idx_marketplace_org
    ON credential_marketplace_listings(org_id);

-- Fast public catalog query: is_public=true ordered by created_at.
CREATE INDEX IF NOT EXISTS idx_marketplace_public
    ON credential_marketplace_listings(is_public, created_at DESC)
    WHERE is_public = true;

-- GIN index for full-text search and tag overlap.
CREATE INDEX IF NOT EXISTS idx_marketplace_tsv
    ON credential_marketplace_listings USING GIN (tsv);

CREATE INDEX IF NOT EXISTS idx_marketplace_tags
    ON credential_marketplace_listings USING GIN (tags);

-- VCT uniqueness per issuer.
CREATE UNIQUE INDEX IF NOT EXISTS idx_marketplace_vct_org
    ON credential_marketplace_listings(org_id, vct);

-- ── Full-text search trigger ─────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION credential_marketplace_tsv_trigger()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.tsv :=
        setweight(to_tsvector('simple', coalesce(NEW.display_name, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(NEW.issuer_name,   '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(NEW.vct,           '')), 'B') ||
        setweight(to_tsvector('simple', coalesce(NEW.description,   '')), 'C') ||
        setweight(to_tsvector('simple', array_to_string(NEW.tags, ' ')), 'B');
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_marketplace_tsv
    BEFORE INSERT OR UPDATE ON credential_marketplace_listings
    FOR EACH ROW EXECUTE FUNCTION credential_marketplace_tsv_trigger();
