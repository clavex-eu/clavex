-- Persistent record of RFC 9396 RAR grants: captures what authorization_details
-- a user consented to, for which client and when. Used by the consent management
-- dashboard (PSD2 compliance: granular view and revocation of grants).
CREATE TABLE rar_grants (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id               UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id             TEXT        NOT NULL,
    scope                 TEXT        NOT NULL DEFAULT '',
    authorization_details JSONB       NOT NULL,   -- RFC 9396 array
    granted_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at          TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    is_active             BOOLEAN     NOT NULL DEFAULT TRUE
);

-- One active grant per (org, user, client) — revoked grants kept for audit trail.
CREATE UNIQUE INDEX idx_rar_grants_active
    ON rar_grants (org_id, user_id, client_id)
    WHERE is_active = TRUE;

CREATE INDEX idx_rar_grants_org_user   ON rar_grants (org_id, user_id);
CREATE INDEX idx_rar_grants_org_client ON rar_grants (org_id, client_id);
