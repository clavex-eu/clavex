-- ── mdoc proximity sessions (ISO 18013-5 / OID4VP proximity flow) ─────────────
--
-- Tracks in-flight proximity verification sessions initiated by a verifier.
-- Each session maps to one QR code shown at a physical service counter.
--
-- Lifecycle:
--   pending   → QR displayed, wallet not yet scanned
--   scanned   → wallet fetched the authorization request
--   completed → wallet submitted a valid DeviceResponse; vp_claims populated
--   failed    → verification failed; error_message populated
--   expired   → TTL exceeded before completion
CREATE TABLE mdoc_proximity_sessions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Unique request identifier embedded in the QR engagement URI.
    request_id          TEXT        NOT NULL UNIQUE,

    -- OID4VP nonce included in the authorization request; verified by the wallet.
    nonce               TEXT        NOT NULL,

    -- The client_id used in the OID4VP authorization request
    -- (typically the verifier's base URL / org slug endpoint).
    client_id           TEXT        NOT NULL,

    -- The response_uri where the wallet POSTs the DeviceResponse.
    response_uri        TEXT        NOT NULL,

    -- Expected docType(s) in the DeviceResponse (e.g. "eu.europa.ec.eudi.pid.1").
    -- Stored as a JSONB array to support multi-document requests.
    requested_doc_types JSONB       NOT NULL DEFAULT '[]',

    -- Presentation definition (PEX v2 InputDescriptors) for the OID4VP request.
    -- May be empty for simple proximity flows that accept any mdoc.
    presentation_definition JSONB  NOT NULL DEFAULT '{}',

    -- Session status.
    status              TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','scanned','completed','failed','expired')),

    -- Populated on successful DeviceResponse verification.
    vp_claims           JSONB,

    -- ISO 3166-1 alpha-2 country code of the issuing authority (from MSO).
    issuer_country      TEXT,

    -- Human-readable error message if status = 'failed'.
    error_message       TEXT,

    -- Redirect URI to send the operator browser to after successful verification.
    redirect_uri        TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ
);

CREATE INDEX idx_mdoc_proximity_sessions_org_id ON mdoc_proximity_sessions (org_id);
CREATE INDEX idx_mdoc_proximity_sessions_request_id ON mdoc_proximity_sessions (request_id);
CREATE INDEX idx_mdoc_proximity_sessions_status ON mdoc_proximity_sessions (org_id, status, created_at DESC);

COMMENT ON TABLE mdoc_proximity_sessions IS
    'ISO 18013-5 / eIDAS 2.0 mdoc proximity verification sessions. '
    'Each row corresponds to one QR code shown at a physical verifier terminal.';
