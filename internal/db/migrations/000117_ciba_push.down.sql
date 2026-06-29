DROP TRIGGER IF EXISTS trg_ciba_device_tokens_updated_at ON ciba_device_tokens;
DROP FUNCTION IF EXISTS update_ciba_device_tokens_updated_at();
DROP TABLE IF EXISTS ciba_device_tokens;

ALTER TABLE org_ciba_notification_config
    DROP COLUMN IF EXISTS push_enabled,
    DROP COLUMN IF EXISTS apns_key_p8,
    DROP COLUMN IF EXISTS apns_key_id,
    DROP COLUMN IF EXISTS apns_team_id,
    DROP COLUMN IF EXISTS apns_bundle_id,
    DROP COLUMN IF EXISTS apns_production,
    DROP COLUMN IF EXISTS fcm_service_account_json;
