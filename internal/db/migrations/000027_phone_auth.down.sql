ALTER TABLE identity.organizations DROP COLUMN IF EXISTS phone_mfa_enabled;
ALTER TABLE identity.organizations DROP COLUMN IF EXISTS sms_login_enabled;
DROP TABLE IF EXISTS org_sms_settings;
DROP TABLE IF EXISTS phone_otp_codes;
DROP TABLE IF EXISTS user_phone_numbers;
