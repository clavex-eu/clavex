-- 000158_credential_analytics.up.sql
-- Privacy-Preserving Analytics for credential issuers.
--
-- Architecture: RSA blind signature scheme (Chaum 1982).
-- The wallet blinds a random token, the issuer signs without seeing the
-- actual value, the wallet unblinds.  At redemption the issuer can verify
-- the token was signed by itself but CANNOT correlate the redemption with
-- the original issuance: unlinkability is cryptographic, not policy-based.
--
-- analytics_keys   — one RSA-2048 signing key per org (auto-generated on first use)
-- analytics_spent  — spent token registry (prevents double-counting)
-- analytics_events — aggregate counts; contains NO personal data

CREATE TABLE IF NOT EXISTS analytics_keys (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    -- RSA-2048 private key in PKCS#8 PEM format.
    -- The corresponding public key is derived server-side and served at
    -- GET /:org_slug/oid4vci/analytics/public-key (JWKS format).
    private_key_pem TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Spent tokens are stored by SHA-256(token_message_hex) to save space.
-- TTL: tokens expire after 180 days (matching the max credential TTL for analytics participation).
CREATE TABLE IF NOT EXISTS analytics_spent (
    token_hash  TEXT        PRIMARY KEY,
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    spent_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytics_spent_org ON analytics_spent (org_id);

-- Aggregate event buckets.  Day-granularity for k-anonymity.
-- No timestamps finer than one day; no user identifiers of any kind.
-- purpose_hint: open taxonomy — "employment", "education", "age_gate",
--   "access_control", "travel", "healthcare", "financial", "other"
-- country_hint: ISO 3166-1 alpha-2 (optional, submitted by verifier)
CREATE TABLE IF NOT EXISTS analytics_events (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    vct           TEXT        NOT NULL,
    day           DATE        NOT NULL,
    purpose_hint  TEXT        NOT NULL DEFAULT '',
    country_hint  TEXT        NOT NULL DEFAULT '',
    -- count is incremented via ON CONFLICT DO UPDATE SET count = count + excluded.count
    count         BIGINT      NOT NULL DEFAULT 1,
    UNIQUE (org_id, vct, day, purpose_hint, country_hint)
);

CREATE INDEX IF NOT EXISTS idx_analytics_events_org_day
    ON analytics_events (org_id, day DESC);

-- Auto-purge spent tokens older than 180 days (run by the GDPR retention worker or a cron).
-- This is a partitioned-table candidate for high volume; for MVP a simple DELETE will do.
