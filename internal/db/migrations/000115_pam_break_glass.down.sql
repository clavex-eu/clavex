DROP TABLE IF EXISTS pam_break_glass_configs;
ALTER TABLE pam_access_requests DROP COLUMN IF EXISTS is_break_glass;
