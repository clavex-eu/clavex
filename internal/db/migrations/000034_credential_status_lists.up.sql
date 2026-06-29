-- 000034: credential status lists and revocation support

-- Stores one status list per org (bitstring, zlib-compressed, base64url).
-- A single list can track 65536 credentials; orgs that issue more will need
-- multiple lists (list_index differentiates them).
CREATE TABLE IF NOT EXISTS credential_status_lists (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    list_index  INT         NOT NULL DEFAULT 0,  -- list sequence number within an org
    encoded     TEXT        NOT NULL,            -- zlib+base64url bitstring
    next_slot   INT         NOT NULL DEFAULT 0,  -- next available index (monotonically increasing)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, list_index)
);

-- Add status tracking columns to issued_credentials.
-- status_list_id + status_index together point to the credential's bit in the list.
ALTER TABLE issued_credentials
    ADD COLUMN IF NOT EXISTS is_revoked       BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS revoked_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revocation_reason TEXT,
    ADD COLUMN IF NOT EXISTS status_list_id   UUID        REFERENCES credential_status_lists(id),
    ADD COLUMN IF NOT EXISTS status_index     INT;

-- Fast lookup: find all active credentials for a status list (for refresh).
CREATE INDEX IF NOT EXISTS idx_issued_credentials_status_list
    ON issued_credentials(status_list_id)
    WHERE status_list_id IS NOT NULL;
