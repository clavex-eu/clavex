-- 000141_oid4vci_notifications.up.sql
-- OID4VCI Final §7: credential notification endpoint.
--
-- Wallets POST to /:org_slug/oid4vci/notification after a credential lifecycle
-- event (credential_accepted, credential_deleted, credential_failure).
-- The issuer can use these events for analytics, audit, and automatic revocation
-- on deletion/failure reports (opt-in via post-issuance webhook).

CREATE TABLE IF NOT EXISTS oid4vci_credential_notifications (
    id                UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id            UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- The notification_id from the wallet (OID4VCI Final §7.1): 128-bit random,
    -- issued by the issuer alongside the credential and echoed back here.
    notification_id   TEXT        NOT NULL,
    -- The event type as sent by the wallet.
    event             TEXT        NOT NULL
                          CHECK (event IN (
                              'credential_accepted',
                              'credential_deleted',
                              'credential_failure'
                          )),
    -- Description of the failure (present only for credential_failure).
    event_description TEXT,
    -- Links back to the issued_credentials row via sd_jwt_hash (best-effort;
    -- NULL when the credential is not (yet) recorded or has been pruned).
    issued_credential_id UUID     REFERENCES issued_credentials(id) ON DELETE SET NULL,
    -- Raw HTTP request body for audit / replay investigation.
    raw_payload       JSONB,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lookup by notification_id (wallet-scoped idempotency).
CREATE INDEX IF NOT EXISTS oid4vci_notif_notification_id
    ON oid4vci_credential_notifications (notification_id);

-- Org-scoped listing used by the admin analytics page.
CREATE INDEX IF NOT EXISTS oid4vci_notif_org_received
    ON oid4vci_credential_notifications (org_id, received_at DESC);
