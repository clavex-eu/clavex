-- 000115: PAM Break-Glass emergency access policy
--
-- PCI DSS 8.2.6 requires documented emergency access procedures with:
--   - Limited usage (max N per week)
--   - Immediate notification to all administrators
--   - Full audit trail with emergency access flag
--
-- Break-glass bypasses the normal JIT approval workflow. The access is
-- immediately active (no approver step). Every use fires a webhook event
-- and is marked with is_break_glass=TRUE in the audit trail.

-- Add break-glass flag to existing access requests table.
-- Added as the last column so SELECT * scanners append it cleanly.
ALTER TABLE pam_access_requests
  ADD COLUMN IF NOT EXISTS is_break_glass BOOLEAN NOT NULL DEFAULT FALSE;

-- Fast lookup of recent break-glass events (compliance queries, audit reports).
CREATE INDEX IF NOT EXISTS idx_pam_requests_break_glass
  ON pam_access_requests(org_id, is_break_glass, created_at DESC)
  WHERE is_break_glass = TRUE;

-- Per-org break-glass policy configuration.
-- If no row exists the handler uses safe defaults (enabled, max 3/week).
CREATE TABLE IF NOT EXISTS pam_break_glass_configs (
  org_id                UUID        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  enabled               BOOLEAN     NOT NULL DEFAULT TRUE,
  max_uses_per_week     INT         NOT NULL DEFAULT 3,   -- 0 = unlimited
  require_justification BOOLEAN     NOT NULL DEFAULT TRUE,
  notify_on_use         BOOLEAN     NOT NULL DEFAULT TRUE, -- fires pam.break_glass.used webhook
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
