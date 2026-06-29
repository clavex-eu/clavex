ALTER TABLE identity_providers
    DROP COLUMN IF EXISTS apple_team_id,
    DROP COLUMN IF EXISTS apple_key_id,
    DROP COLUMN IF EXISTS apple_private_key;
