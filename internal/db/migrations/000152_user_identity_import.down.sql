-- 000152_user_identity_import.down.sql
ALTER TABLE users
    DROP COLUMN IF EXISTS identity_source_issuer,
    DROP COLUMN IF EXISTS identity_imported_at;
