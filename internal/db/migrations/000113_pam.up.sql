-- 000113: Privileged Access Management (PAM)
--
-- Features:
--   1. JIT (just-in-time) access requests with approval workflow
--   2. Privileged session recording
--   3. Encrypted credential vault (AES-256-GCM via crypto.Encryptor)
--   4. Vault SSH CA config — agentless "Platform SSO for Linux"
--      (differentiator vs Authentik's proprietary PAM agent)
--
-- Gap vs Okta PAM: this adds JIT requests + credential vault.
-- Gap vs Authentik: Vault SSH CA approach works on any Linux host
--   with standard authorized_keys config — no agent installation required.

-- ── JIT Access Requests ───────────────────────────────────────────────────────
-- Lifecycle: pending → approved (→ active) | denied
--            active  → expired | revoked
CREATE TABLE pam_access_requests (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    requester_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource_type         TEXT        NOT NULL
                          CHECK (resource_type IN ('server','database','application','credential','admin_role')),
    resource_id           TEXT        NOT NULL,
    resource_name         TEXT        NOT NULL,
    justification         TEXT        NOT NULL,
    requested_duration    INT         NOT NULL DEFAULT 60, -- minutes
    status                TEXT        NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','approved','denied','active','expired','revoked')),
    approved_by           UUID        REFERENCES users(id),
    approve_note          TEXT,
    granted_at            TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    revoke_reason         TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pam_requests_org     ON pam_access_requests(org_id, created_at DESC);
CREATE INDEX idx_pam_requests_user    ON pam_access_requests(org_id, requester_id, created_at DESC);
CREATE INDEX idx_pam_requests_pending ON pam_access_requests(org_id, status)
    WHERE status IN ('pending', 'active');

-- ── Privileged Sessions ───────────────────────────────────────────────────────
CREATE TABLE pam_sessions (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    access_request_id     UUID        REFERENCES pam_access_requests(id) ON DELETE SET NULL,
    user_id               UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_type          TEXT        NOT NULL
                          CHECK (session_type IN ('ssh','rdp','web','db','api')),
    target_host           TEXT,
    target_port           INT,
    target_user           TEXT,
    client_ip             INET,
    event_count           INT         NOT NULL DEFAULT 0,
    started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at              TIMESTAMPTZ
);

CREATE INDEX idx_pam_sessions_org  ON pam_sessions(org_id, started_at DESC);
CREATE INDEX idx_pam_sessions_user ON pam_sessions(org_id, user_id, started_at DESC);

-- ── Session Events ────────────────────────────────────────────────────────────
CREATE TABLE pam_session_events (
    id          BIGSERIAL   PRIMARY KEY,
    session_id  UUID        NOT NULL REFERENCES pam_sessions(id) ON DELETE CASCADE,
    event_type  TEXT        NOT NULL
                CHECK (event_type IN ('command','output','screen','keystroke','transfer','note')),
    payload     JSONB       NOT NULL DEFAULT '{}',
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pam_session_events ON pam_session_events(session_id, ts ASC);

-- ── Encrypted Credential Vault ────────────────────────────────────────────────
-- Secrets are encrypted with AES-256-GCM before storage. Raw plaintext is
-- never written to the DB. The Encryptor key is cfg.Auth.EncryptionKey.
CREATE TABLE pam_credentials (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                  TEXT        NOT NULL,
    description           TEXT,
    credential_type       TEXT        NOT NULL
                          CHECK (credential_type IN ('password','ssh_key','api_token','service_account')),
    username              TEXT,
    encrypted_secret      TEXT        NOT NULL, -- AES-256-GCM ciphertext
    target_host           TEXT,
    checkout_duration     INT         NOT NULL DEFAULT 60, -- minutes
    require_access_request BOOLEAN   NOT NULL DEFAULT TRUE,
    is_active             BOOLEAN     NOT NULL DEFAULT TRUE,
    last_rotated_at       TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX idx_pam_credentials_org ON pam_credentials(org_id, is_active, name);

-- ── Credential Checkouts ──────────────────────────────────────────────────────
CREATE TABLE pam_credential_checkouts (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id         UUID        NOT NULL REFERENCES pam_credentials(id) ON DELETE CASCADE,
    org_id                UUID        NOT NULL,
    user_id               UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_request_id     UUID        REFERENCES pam_access_requests(id),
    reason                TEXT,
    checked_out_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at            TIMESTAMPTZ NOT NULL,
    returned_at           TIMESTAMPTZ
);

CREATE INDEX idx_pam_checkouts_cred ON pam_credential_checkouts(credential_id, checked_out_at DESC);
CREATE INDEX idx_pam_checkouts_user ON pam_credential_checkouts(org_id, user_id, checked_out_at DESC);
-- Only one active checkout per credential at a time.
CREATE UNIQUE INDEX idx_pam_checkouts_active
    ON pam_credential_checkouts(credential_id)
    WHERE returned_at IS NULL;

-- ── Vault SSH CA Config ───────────────────────────────────────────────────────
-- Configures Clavex as a broker for HashiCorp Vault SSH CA.
--
-- Flow: user logs in to Clavex → optionally satisfies a PAM access request →
--   POSTs their SSH public key → Clavex signs it via Vault → returns ephemeral cert
--   → user SSHes to any Linux host without an agent.
--
-- Differentiator: Authentik requires a proprietary Go agent on every Linux host.
--   Clavex uses standard Vault SSH CA + sshd AuthorizedPrincipalsCommand — no
--   agent installation, works with any OpenSSH ≥ 6.5.
CREATE TABLE pam_ssh_ca_configs (
    org_id                UUID        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    vault_addr            TEXT        NOT NULL,
    encrypted_vault_token TEXT        NOT NULL, -- AES-256-GCM via crypto.Encryptor
    vault_mount           TEXT        NOT NULL DEFAULT 'ssh',
    vault_role            TEXT        NOT NULL,
    ca_public_key         TEXT,       -- cached: serve at GET /pam/ssh-ca/public-key
    cert_ttl_seconds      INT         NOT NULL DEFAULT 3600,
    require_access_request BOOLEAN   NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
