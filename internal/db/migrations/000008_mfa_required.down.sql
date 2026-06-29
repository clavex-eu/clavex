ALTER TABLE organizations DROP COLUMN IF EXISTS mfa_required;
ALTER TABLE users        DROP COLUMN IF EXISTS mfa_required;
