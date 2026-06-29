-- 000147_conformance_score.up.sql
-- Continuous Assurance: real-time conformance score per org.
--
-- conformance_scores      — latest score per org (upserted every 5 min by the worker)
-- conformance_score_history — append-only log for trend charts and regression detection

CREATE TABLE IF NOT EXISTS conformance_scores (
    org_id          UUID        NOT NULL PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    -- Aggregate score 0-100
    score           INT         NOT NULL CHECK (score BETWEEN 0 AND 100),
    -- Component sub-scores (each 0 to their respective max weight)
    score_mfa       INT         NOT NULL DEFAULT 0,   -- max 30: % users with MFA enrolled
    score_pkce      INT         NOT NULL DEFAULT 0,   -- max 25: % clients with require_pkce
    score_dpop      INT         NOT NULL DEFAULT 0,   -- max 25: % clients with DPoP bound tokens
    score_nis2      INT         NOT NULL DEFAULT 0,   -- max 20: NIS2 policy checklist
    -- Raw component detail for dashboard display
    components      JSONB       NOT NULL DEFAULT '{}',
    -- Alert threshold (default 70/100); configurable per org via PATCH
    threshold       INT         NOT NULL DEFAULT 70 CHECK (threshold BETWEEN 0 AND 100),
    -- Track whether we have already fired a below-threshold alert to avoid spam.
    -- Reset to NULL when score recovers above threshold.
    alerted_at      TIMESTAMPTZ,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS conformance_score_history (
    id          BIGSERIAL   PRIMARY KEY,
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    score       INT         NOT NULL,
    components  JSONB       NOT NULL DEFAULT '{}',
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS conformance_score_history_org_at
    ON conformance_score_history (org_id, computed_at DESC);
