DROP TABLE IF EXISTS pam_ssh_ca_rotations;

ALTER TABLE pam_ssh_ca_configs
    DROP COLUMN IF EXISTS rotation_policy,
    DROP COLUMN IF EXISTS rotation_interval_days;
