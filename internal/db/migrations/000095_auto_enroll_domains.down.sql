-- 000095_auto_enroll_domains.down.sql
ALTER TABLE organizations
    DROP COLUMN IF EXISTS auto_enroll_domains,
    DROP COLUMN IF EXISTS auto_enroll_role_id;
