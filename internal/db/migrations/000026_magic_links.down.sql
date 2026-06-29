ALTER TABLE identity.organizations DROP COLUMN IF EXISTS magic_link_enabled;
ALTER TABLE identity.organizations DROP COLUMN IF EXISTS magic_link_as_mfa;
DROP TABLE IF EXISTS magic_links;
