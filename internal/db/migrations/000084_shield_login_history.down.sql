ALTER TABLE login_history
    DROP COLUMN IF EXISTS is_malicious,
    DROP COLUMN IF EXISTS confidence_score,
    DROP COLUMN IF EXISTS is_tor_exit;
