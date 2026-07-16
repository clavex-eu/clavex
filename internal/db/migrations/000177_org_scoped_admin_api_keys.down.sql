DROP INDEX IF EXISTS idx_admin_api_keys_org_id;
ALTER TABLE admin_api_keys DROP COLUMN IF EXISTS permissions;
ALTER TABLE admin_api_keys DROP COLUMN IF EXISTS org_id;
