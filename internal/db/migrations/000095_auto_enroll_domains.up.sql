-- 000095_auto_enroll_domains.up.sql
-- Domain-based organization enrollment: users whose email domain matches
-- auto_enroll_domains are automatically added to the org with auto_enroll_role_id
-- (no invite required). Useful for B2B SaaS deployments.
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS auto_enroll_domains  TEXT[]    NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS auto_enroll_role_id  UUID      REFERENCES roles(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_orgs_auto_enroll
    ON organizations USING GIN (auto_enroll_domains);
