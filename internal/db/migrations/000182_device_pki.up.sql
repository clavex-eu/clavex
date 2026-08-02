-- Device CA: mTLS client-certificate identity for IoT device fleets
-- authenticating to an external MQTT broker. Separate CA/Vault mount from the
-- PAM SSH CA (internal/sshca/) — same custody pattern, different key,
-- different domain of trust (machine identity vs human SSH access).
--
-- Bootstrap secrets are per-device (not fleet-wide), so a single leaked secret
-- only lets an attacker mint a certificate for the one device it was issued
-- for — the failure mode this whole scheme replaces.

CREATE TABLE device_ca_configs (
    org_id                       UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    vault_addr                   TEXT NOT NULL,
    encrypted_vault_token        TEXT NOT NULL,
    vault_mount                  TEXT NOT NULL,
    vault_role                   TEXT NOT NULL,
    ca_certificate_pem           TEXT,
    cert_ttl_seconds             INTEGER NOT NULL DEFAULT 604800,  -- 7d
    renewal_window_seconds       INTEGER NOT NULL DEFAULT 172800,  -- 2d
    bootstrap_secret_ttl_seconds INTEGER NOT NULL DEFAULT 259200,  -- 72h
    rotation_policy              TEXT NOT NULL DEFAULT 'manual'
        CHECK (rotation_policy IN ('manual', 'scheduled')),
    rotation_interval_days       INTEGER,
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE devices (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id        TEXT NOT NULL, -- external ID from the physical provisioning process
    fleet_id         TEXT,
    status           TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'revoked', 'disabled')),
    last_enrolled_at TIMESTAMPTZ,
    last_renewed_at  TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, device_id)
);
CREATE INDEX devices_org ON devices (org_id);

-- One row per issued certificate: enables revoking a single device's cert
-- without touching the CA or any other device (the hard requirement that
-- "wait for natural expiry" cannot satisfy for stolen field hardware).
CREATE TABLE device_certificates (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id      UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    serial_number  TEXT NOT NULL,
    cn             TEXT NOT NULL,
    not_before     TIMESTAMPTZ NOT NULL,
    not_after      TIMESTAMPTZ NOT NULL,
    status         TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'superseded', 'revoked')),
    revoked_at     TIMESTAMPTZ,
    revoked_reason TEXT,
    revoked_by     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, serial_number)
);
CREATE INDEX device_certificates_device ON device_certificates (device_id);
CREATE INDEX device_certificates_org_status ON device_certificates (org_id, status);

-- One-time, per-device enrollment secret. Deliberately a separate table/state
-- from device_certificates: "revoke an unused bootstrap secret" (operator
-- fat-fingered provisioning) and "revoke an issued certificate" (device
-- compromised) are distinct operations and must never be conflated.
CREATE TABLE device_enrollment_secrets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    secret_hash TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'used', 'revoked', 'expired')),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX device_enrollment_secrets_device ON device_enrollment_secrets (device_id);
CREATE UNIQUE INDEX device_enrollment_secrets_hash ON device_enrollment_secrets (secret_hash);

-- Staged rotation state machine for the Vault PKI Device CA. Mirrors the SSH
-- CA rotation shape (internal/sshca/, pam_ssh_ca_rotations) but is a wholly
-- separate implementation against a separate Vault PKI mount — the two CAs
-- must never share a blast radius.
CREATE TABLE device_ca_rotations (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                 UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    state                  TEXT NOT NULL DEFAULT 'rotating'
        CHECK (state IN ('idle', 'rotating', 'cutover_ready', 'rollback')),
    old_ca_fingerprint     TEXT,
    new_ca_fingerprint     TEXT,
    old_vault_mount        TEXT,
    new_vault_mount        TEXT,
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

CREATE UNIQUE INDEX device_ca_rotations_one_active
    ON device_ca_rotations (org_id)
    WHERE state IN ('rotating', 'cutover_ready');

CREATE INDEX device_ca_rotations_grace
    ON device_ca_rotations (grace_expires_at)
    WHERE state = 'idle' AND old_mount_removed = FALSE;
