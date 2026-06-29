-- breach_events records every HIBP breach detection for per-org reporting.
-- This provides the FusionAuth-style aggregated breach report:
-- total checks, breach categories (exact_match / common_password / sub_address),
-- and a paginable per-user history.
--
-- breach_category:
--   exact_match     — password found in HIBP (any count)
--   common_password — password found in HIBP with count >= 1 000 (extremely common)
--   sub_address     — password equals email local-part (with or without +tag)
--
-- action_taken mirrors the org's breached_password_action at detection time.
-- context records where the check was triggered.

CREATE TABLE IF NOT EXISTS breach_events (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id          UUID        REFERENCES users(id) ON DELETE SET NULL,
    email            TEXT        NOT NULL,
    breach_category  TEXT        NOT NULL
                     CHECK (breach_category IN ('exact_match', 'common_password', 'sub_address')),
    hibp_count       INT         NOT NULL DEFAULT 0,
    action_taken     TEXT        NOT NULL
                     CHECK (action_taken IN ('warn', 'block', 'force_reset')),
    context          TEXT        NOT NULL DEFAULT 'password_change'
                     CHECK (context IN ('registration', 'password_change', 'login')),
    detected_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS breach_events_org_time  ON breach_events(org_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS breach_events_user      ON breach_events(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS breach_events_category  ON breach_events(org_id, breach_category);
