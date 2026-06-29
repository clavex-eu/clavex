-- 000087_adaptive_lockout.up.sql
-- Per-org adaptive lockout configuration for Clavex Guard.
--
-- The lockout duration scales with the real-time risk score computed by
-- Clavex Shield. Low-risk accounts get a brief timeout; high-risk accounts
-- (Tor exit, new country, many consecutive failures) get a long lockout and
-- an optional admin alert.
--
-- Enforcement is entirely Redis-based (clavex:guard:{orgID}:{emailHash}:*)
-- so this table is only the configuration store; it is read at login time
-- with a short in-process cache (30 s).

CREATE TABLE org_lockout_config (
    org_id      UUID        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,

    -- JSON array of scoring bands.
    -- Each band covers a score range and defines the failure threshold +
    -- lockout duration for accounts that fall into that risk bucket.
    -- Default bands:
    --   score   0-29  → 5 failures  → 30 s lockout  (low risk)
    --   score  30-59  → 3 failures  → 5 min lockout  (medium risk)
    --   score  60-79  → 2 failures  → 15 min lockout (high risk)
    --   score  80-100 → 1 failure   → 60 min lockout (critical risk)
    bands       JSONB       NOT NULL DEFAULT '[
        {"score_min":0,  "score_max":29,  "max_attempts":5, "lockout_seconds":30},
        {"score_min":30, "score_max":59,  "max_attempts":3, "lockout_seconds":300},
        {"score_min":60, "score_max":79,  "max_attempts":2, "lockout_seconds":900},
        {"score_min":80, "score_max":100, "max_attempts":1, "lockout_seconds":3600}
    ]',

    -- When true, a lockout at score ≥ 80 fires a login.lockout.critical audit
    -- event which can trigger an admin webhook / SIEM alert.
    alert_admin BOOLEAN     NOT NULL DEFAULT FALSE,

    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
