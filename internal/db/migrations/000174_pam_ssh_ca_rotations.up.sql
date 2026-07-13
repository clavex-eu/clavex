-- Staged rotation state machine for the Vault SSH CA.
--
-- A rotation generates a NEW Vault SSH mount with its own CA so the old and new
-- CAs can both sign during propagation (checkpoint). The old mount is retired
-- only after Complete + a grace window, by a background worker.

ALTER TABLE pam_ssh_ca_configs
    ADD COLUMN rotation_policy        TEXT NOT NULL DEFAULT 'manual'
        CHECK (rotation_policy IN ('manual', 'scheduled')),
    ADD COLUMN rotation_interval_days INTEGER;

CREATE TABLE pam_ssh_ca_rotations (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                 UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- idle/rollback are terminal; rotating/cutover_ready are in-flight.
    state                  TEXT NOT NULL DEFAULT 'rotating'
        CHECK (state IN ('idle', 'rotating', 'cutover_ready', 'rollback')),
    old_ca_fingerprint     TEXT,
    new_ca_fingerprint     TEXT,
    old_vault_mount        TEXT,
    new_vault_mount        TEXT,
    -- Records only the policy that TRIGGERED the start (manual|scheduled); the
    -- mark-ready/complete steps are always explicit, never scheduled.
    rotation_policy        TEXT NOT NULL DEFAULT 'manual'
        CHECK (rotation_policy IN ('manual', 'scheduled')),
    rotation_interval_days INTEGER,
    started_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cutover_ready_at       TIMESTAMPTZ,
    completed_at           TIMESTAMPTZ,
    grace_expires_at       TIMESTAMPTZ,
    old_mount_removed      BOOLEAN NOT NULL DEFAULT FALSE,
    started_by             TEXT,
    notes                  TEXT
);

-- At most one in-flight rotation per org.
CREATE UNIQUE INDEX pam_ssh_ca_rotations_one_active
    ON pam_ssh_ca_rotations (org_id)
    WHERE state IN ('rotating', 'cutover_ready');

-- Grace-cleanup worker scans completed rotations whose old mount is still present.
CREATE INDEX pam_ssh_ca_rotations_grace
    ON pam_ssh_ca_rotations (grace_expires_at)
    WHERE state = 'idle' AND old_mount_removed = FALSE;
