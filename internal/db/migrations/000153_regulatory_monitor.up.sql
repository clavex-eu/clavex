-- 000153_regulatory_monitor.up.sql
-- AI Regulatory Change Monitor state table.
--
-- The monitor is a weekly worker that polls upstream specification sources
-- (EUDIW ARF GitHub, OID4VCI, OID4VP, eIDAS 2.0 EUR-Lex, AgID SPID/CIE) and
-- uses Claude to analyse diffs and produce actionable "update Clavex here"
-- reports.  This table persists the last-seen version / ETag / commit SHA per
-- source so the worker only re-analyses when something has actually changed.

CREATE TABLE IF NOT EXISTS regulatory_monitor_sources (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Short human-readable key, e.g. "eudiw-arf", "oid4vci", "agid-spid".
    source_key  TEXT        NOT NULL UNIQUE,
    -- Display name shown in reports and emails.
    display_name TEXT       NOT NULL,
    -- Last content fingerprint: SHA-1/ETag/latest release tag seen by the worker.
    last_seen_ref TEXT,
    -- ISO-8601 timestamp of the last successful check (even when no change found).
    last_checked_at TIMESTAMPTZ,
    -- ISO-8601 timestamp of the last change that triggered an analysis.
    last_changed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS regulatory_monitor_reports (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_key  TEXT        NOT NULL REFERENCES regulatory_monitor_sources(source_key) ON DELETE CASCADE,
    -- The diff / changelog text that was passed to Claude for analysis.
    diff_text   TEXT        NOT NULL,
    -- The structured JSON report produced by Claude.
    -- Schema: { "summary": "...", "impact": "none|low|medium|high|critical",
    --           "findings": [ { "section": "§X.Y", "change": "...",
    --                           "affected_files": ["..."], "action": "..." } ] }
    report_json JSONB,
    -- Markdown-formatted report for email / MCP response.
    report_md   TEXT,
    -- ref that was new when this report was generated.
    new_ref     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_regulatory_reports_source
    ON regulatory_monitor_reports(source_key, created_at DESC);
