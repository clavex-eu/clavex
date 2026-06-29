-- 000123_email_policy.down.sql

ALTER TABLE organizations
    DROP COLUMN IF EXISTS email_blocklist,
    DROP COLUMN IF EXISTS email_allowlist;
