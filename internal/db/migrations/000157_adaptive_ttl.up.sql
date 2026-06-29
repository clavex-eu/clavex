-- 000157_adaptive_ttl.up.sql
-- Adaptive Credential Freshness: credentials used frequently are silently
-- renewed before expiry; credentials dormant for >inactivity_revoke_days are
-- revoked for security.
--
-- Config lives in credential_configs (per credential type).
-- Tracking lives in issued_credentials (per issuance).
--
-- Config semantics:
--   adaptive_ttl          — enables the adaptive lifecycle for this config.
--   min_ttl_seconds       — floor: renewed credential cannot expire sooner
--                           than min_ttl_seconds from the renewal timestamp.
--   max_ttl_seconds       — ceiling: a credential cannot be renewed beyond
--                           max_ttl_seconds from original issuance.
--   renewal_threshold     — fraction of TTL elapsed that triggers renewal.
--                           0.8 = renew when 80% of the original TTL has passed.
--   inactivity_revoke_days — revoke if credential was never presented AND the
--                           issuing user has not logged in for this many days.

ALTER TABLE credential_configs
    ADD COLUMN IF NOT EXISTS adaptive_ttl            BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS min_ttl_seconds         INT     NOT NULL DEFAULT 604800,
    ADD COLUMN IF NOT EXISTS max_ttl_seconds         INT     NOT NULL DEFAULT 31536000,
    ADD COLUMN IF NOT EXISTS renewal_threshold       FLOAT   NOT NULL DEFAULT 0.8,
    ADD COLUMN IF NOT EXISTS inactivity_revoke_days  INT     NOT NULL DEFAULT 90;

-- last_presented_at: set whenever the credential's status list slot is checked
-- by a verifier (i.e., the credential was actively presented).
-- presentation_count: monotonically increasing; used to distinguish "never used"
-- from "used at least once" when deciding whether to renew vs revoke.
-- adaptive_renewed_at: timestamp of the last adaptive renewal (for audit trail).
ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS last_presented_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS presentation_count  INT         NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS adaptive_renewed_at TIMESTAMPTZ;

-- Partial index used by the adaptive TTL worker's renewal and inactivity queries.
CREATE INDEX IF NOT EXISTS idx_issued_adaptive_worker
    ON issued_credentials (org_id, vct, expires_at, last_presented_at)
    WHERE NOT is_revoked AND expires_at IS NOT NULL;
