-- FIDO Alliance Metadata Service 3 (MDS3) local cache.
--
-- Populated by the mds3-worker which downloads https://mds3.fidoalliance.org,
-- verifies the JWS signature using the FIDO root CA, and upserts one row per
-- authenticator entry (identified by AAGUID).
--
-- Used by:
--   1. The WebAuthn attestation policy engine — to enforce certification-level
--      requirements (e.g. "only FIDO2 L2+") without maintaining a manual
--      AAGUID allow-list.
--   2. The admin UI — to browse the certified device catalog and attach
--      human-readable labels to AAGUIDs already in the allow-list.

CREATE TABLE IF NOT EXISTS fido_mds_entries (
    -- Authenticator AAGUID (UUID v4, lowercase with hyphens).
    -- This is the primary lookup key for policy enforcement.
    aaguid               TEXT        PRIMARY KEY,

    -- Human-readable authenticator description (e.g. "YubiKey 5 NFC FIDO2").
    description          TEXT        NOT NULL DEFAULT '',

    -- FIDO certification level: "L1", "L1+", "L1p", "L2", "L2+", "L3", "L3+".
    -- NULL means uncertified / level information not available.
    certification_level  TEXT,

    -- Certificate number assigned by the FIDO Alliance (e.g. "FIDO20020230401001").
    certificate_number   TEXT,

    -- Date from which the authenticator is certified (ISO-8601 date string
    -- as provided in the MDS3 payload).
    certified_at         TEXT,

    -- Known security issues / advisory flags pulled from the metadataStatement.
    -- Stored as a JSON array of status report strings so we can filter on them.
    -- Example: ["REVOKED", "USER_VERIFICATION_BYPASS"].
    status_reports       JSONB       NOT NULL DEFAULT '[]',

    -- Full metadataStatement JSON from the MDS blob — retained for future use
    -- (e.g. attestation root extraction, aaguid extension checks).
    metadata_statement   JSONB,

    -- FIDO Alliance attestation root certificates (PEM, one per element).
    -- Extracted from metadataStatement.attestationRootCertificates.
    root_certificates    TEXT[]      NOT NULL DEFAULT '{}',

    -- Authenticator category inferred from metadataStatement.authenticatorGetInfo
    -- or protocolFamily: "platform", "cross-platform", "unknown".
    authenticator_type   TEXT        NOT NULL DEFAULT 'unknown',

    -- Date after which the device is considered end-of-life (from the
    -- timeOfLastStatusChange field of the last status report, or NULL).
    effective_date       TEXT,

    -- Timestamp when this row was last refreshed from the MDS3 feed.
    refreshed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- MDS3 "no" (entry sequence number) from the JWT payload.
    -- Monotonically increasing; used to detect stale local entries.
    mds_entry_number     BIGINT      NOT NULL DEFAULT 0
);

-- Index for certification-level queries (policy enforcement).
CREATE INDEX IF NOT EXISTS fido_mds_entries_cert_level_idx
    ON fido_mds_entries (certification_level);

-- Index for fast lookup of entries with status issues (e.g. REVOKED).
CREATE INDEX IF NOT EXISTS fido_mds_entries_status_idx
    ON fido_mds_entries USING GIN (status_reports);

-- Metadata table: one row, tracks the last successful MDS3 pull.
CREATE TABLE IF NOT EXISTS fido_mds_sync (
    id                   SMALLINT    PRIMARY KEY DEFAULT 1
                                     CHECK (id = 1),  -- singleton row
    last_synced_at       TIMESTAMPTZ,
    entry_count          INT         NOT NULL DEFAULT 0,
    -- "no" value from the JWT payload (used for next-request optimization).
    last_no              BIGINT      NOT NULL DEFAULT 0,
    -- HTTP ETag / Last-Modified from the MDS3 response for conditional GET.
    http_etag            TEXT,
    http_last_modified   TEXT,
    -- Error from the last sync attempt (NULL = last sync was successful).
    last_error           TEXT,
    -- When the currently cached token expires (from JWT exp claim).
    token_expires_at     TIMESTAMPTZ
);

INSERT INTO fido_mds_sync (id) VALUES (1) ON CONFLICT DO NOTHING;

-- Extend the WebAuthn attestation policy table with MDS3 fields.
-- These allow admins to configure "only FIDO2 L2+" instead of a manual AAGUID list.
ALTER TABLE webauthn_attestation_policies
    ADD COLUMN IF NOT EXISTS require_mds_certification      BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS min_certification_level        TEXT,
    ADD COLUMN IF NOT EXISTS exclude_revoked_authenticators BOOLEAN DEFAULT FALSE;

--
-- Populated by the mds3-worker which downloads https://mds3.fidoalliance.org,
-- verifies the JWS signature using the FIDO root CA, and upserts one row per
-- authenticator entry (identified by AAGUID).
--
-- Used by:
--   1. The WebAuthn attestation policy engine — to enforce certification-level
--      requirements (e.g. "only FIDO2 L2+") without maintaining a manual
--      AAGUID allow-list.
--   2. The admin UI — to browse the certified device catalog and attach
--      human-readable labels to AAGUIDs already in the allow-list.

CREATE TABLE IF NOT EXISTS fido_mds_entries (
    -- Authenticator AAGUID (UUID v4, lowercase with hyphens).
    -- This is the primary lookup key for policy enforcement.
    aaguid               TEXT        PRIMARY KEY,

    -- Human-readable authenticator description (e.g. "YubiKey 5 NFC FIDO2").
    description          TEXT        NOT NULL DEFAULT '',

    -- FIDO certification level: "L1", "L1+", "L1p", "L2", "L2+", "L3", "L3+".
    -- NULL means uncertified / level information not available.
    certification_level  TEXT,

    -- Certificate number assigned by the FIDO Alliance (e.g. "FIDO20020230401001").
    certificate_number   TEXT,

    -- Date from which the authenticator is certified (ISO-8601 date string
    -- as provided in the MDS3 payload).
    certified_at         TEXT,

    -- Known security issues / advisory flags pulled from the metadataStatement.
    -- Stored as a JSON array of status report strings so we can filter on them.
    -- Example: ["REVOKED", "USER_VERIFICATION_BYPASS"].
    status_reports       JSONB       NOT NULL DEFAULT '[]',

    -- Full metadataStatement JSON from the MDS blob — retained for future use
    -- (e.g. attestation root extraction, aaguid extension checks).
    metadata_statement   JSONB,

    -- FIDO Alliance attestation root certificates (PEM, one per element).
    -- Extracted from metadataStatement.attestationRootCertificates.
    root_certificates    TEXT[]      NOT NULL DEFAULT '{}',

    -- Authenticator category inferred from metadataStatement.authenticatorGetInfo
    -- or protocolFamily: "platform", "cross-platform", "unknown".
    authenticator_type   TEXT        NOT NULL DEFAULT 'unknown',

    -- Date after which the device is considered end-of-life (from the
    -- timeOfLastStatusChange field of the last status report, or NULL).
    effective_date       TEXT,

    -- Timestamp when this row was last refreshed from the MDS3 feed.
    refreshed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- MDS3 "no" (entry sequence number) from the JWT payload.
    -- Monotonically increasing; used to detect stale local entries.
    mds_entry_number     BIGINT      NOT NULL DEFAULT 0
);

-- Index for certification-level queries (policy enforcement).
CREATE INDEX IF NOT EXISTS fido_mds_entries_cert_level_idx
    ON fido_mds_entries (certification_level);

-- Index for fast lookup of entries with status issues (e.g. REVOKED).
CREATE INDEX IF NOT EXISTS fido_mds_entries_status_idx
    ON fido_mds_entries USING GIN (status_reports);

-- Metadata table: one row, tracks the last successful MDS3 pull.
CREATE TABLE IF NOT EXISTS fido_mds_sync (
    id                   SMALLINT    PRIMARY KEY DEFAULT 1
                                     CHECK (id = 1),  -- singleton row
    last_synced_at       TIMESTAMPTZ,
    entry_count          INT         NOT NULL DEFAULT 0,
    -- "no" value from the JWT payload (used for next-request optimization).
    last_no              BIGINT      NOT NULL DEFAULT 0,
    -- HTTP ETag / Last-Modified from the MDS3 response for conditional GET.
    http_etag            TEXT,
    http_last_modified   TEXT,
    -- Error from the last sync attempt (NULL = last sync was successful).
    last_error           TEXT,
    -- When the currently cached token expires (from JWT exp claim).
    token_expires_at     TIMESTAMPTZ
);

INSERT INTO fido_mds_sync (id) VALUES (1) ON CONFLICT DO NOTHING;
