-- PAM credential auto-rotation config and audit log.
-- PCI DSS 8.6.3 / NIS2 Art.21 require periodic rotation of privileged credentials.

-- Add rotation schedule to each credential (NULL = no auto-rotation).
ALTER TABLE pam_credentials
  ADD COLUMN IF NOT EXISTS rotation_interval_days INTEGER;

-- Audit log for every rotation event (automatic or manual).
CREATE TABLE IF NOT EXISTS pam_credential_rotation_log (
  id            BIGSERIAL     PRIMARY KEY,
  credential_id UUID          NOT NULL REFERENCES pam_credentials(id) ON DELETE CASCADE,
  org_id        UUID          NOT NULL,
  rotated_by    TEXT          NOT NULL DEFAULT 'system',  -- 'system' or admin user UUID
  rotation_type TEXT          NOT NULL DEFAULT 'auto',    -- 'auto' | 'manual'
  note          TEXT,
  rotated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pam_rot_log_cred   ON pam_credential_rotation_log(credential_id, rotated_at DESC);
CREATE INDEX IF NOT EXISTS idx_pam_rot_log_org    ON pam_credential_rotation_log(org_id, rotated_at DESC);
