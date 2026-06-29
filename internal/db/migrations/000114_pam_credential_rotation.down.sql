DROP TABLE IF EXISTS pam_credential_rotation_log;
ALTER TABLE pam_credentials DROP COLUMN IF EXISTS rotation_interval_days;
