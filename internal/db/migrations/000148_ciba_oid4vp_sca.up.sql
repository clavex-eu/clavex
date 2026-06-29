-- 000148_ciba_oid4vp_sca: CIBA + OID4VP combined Strong Customer Authentication
-- (PSD2 SCA) flow.
--
-- A merchant initiates a CIBA backchannel auth request.  Instead of a simple
-- tap-to-approve, the end-user's wallet presents a verifiable credential
-- (e.g. CIE as ISO 18013-5 mdoc or SD-JWT VC) via OID4VP.  Clavex verifies
-- the presentation, auto-approves the CIBA request, and stores the credential
-- claims so the bank can inspect them in the resulting ID token.
--
-- Relationship: one CIBA request ← (optional) one presentation_session.
-- The link is stored on presentation_sessions to avoid a circular FK.

-- presentation_sessions: back-link to the CIBA request that initiated this VP
-- flow.  NULL for standalone VP sessions.
ALTER TABLE presentation_sessions
    ADD COLUMN IF NOT EXISTS ciba_auth_req_id TEXT
        REFERENCES ciba_requests(auth_req_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_presentation_sessions_ciba_auth_req_id
    ON presentation_sessions(ciba_auth_req_id)
    WHERE ciba_auth_req_id IS NOT NULL;

-- ciba_requests: store the VP claims returned by the wallet presentation and
-- the ACR value achieved (e.g. "urn:clavex:acr:oid4vp-credential").
-- Both are NULL for classic CIBA flows that do not use VP-based SCA.
ALTER TABLE ciba_requests
    ADD COLUMN IF NOT EXISTS vp_claims JSONB,
    ADD COLUMN IF NOT EXISTS acr       TEXT;
