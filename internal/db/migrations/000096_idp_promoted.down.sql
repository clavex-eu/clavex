-- 000096_idp_promoted.down.sql
ALTER TABLE identity_providers DROP COLUMN IF EXISTS is_promoted;
