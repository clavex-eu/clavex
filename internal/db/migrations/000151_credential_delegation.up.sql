-- 000151_credential_delegation.up.sql
-- Delegated Credential Issuance (ARF EUDIW §6.3.4).
--
-- Enables one Clavex installation (sub-issuer) to issue credentials under a VCT
-- that is nominally owned by a different issuer (delegating issuer).  The classic
-- use-case: a university (Trust Anchor) delegates to 10 faculties (sub-issuers)
-- the right to issue diplomas under the university VCT.  The diploma is signed by
-- the faculty's key but carries a delegation proof signed by the university, so a
-- wallet can verify the full chain: university → faculty → document.
--
-- Trust chain: wallet verifies
--   1. issuer SD-JWT signature  → faculty sub-issuer key (cnf / x5c in SD-JWT header)
--   2. del.proof JWS signature  → university delegating_issuer key (jwks_uri)
--   3. del.vct matches cfg.vct  → university explicitly authorised THIS credential type
--
-- Pattern: ARF EUDIW §6.3.4 "Issuer delegation" – referenced but not yet widely
-- implemented by any IAM vendor as of 2025.

ALTER TABLE credential_configs
    -- Entity ID URL of the issuer that delegated the right to issue this VCT.
    -- When non-null this credential config operates in "delegated issuance" mode:
    -- credentials are signed by THIS org's key but carry a delegation proof that
    -- traces up to the delegating issuer, allowing wallet trust-chain verification.
    ADD COLUMN IF NOT EXISTS delegated_by TEXT,
    -- Compact JWS (signed by the delegating issuer) that grants this sub-issuer
    -- permission to issue credentials of this VCT.  The JWS is embedded verbatim
    -- as the "del.proof" claim in issued SD-JWT-VCs so wallets can verify the grant
    -- offline without contacting the delegating issuer at presentation time.
    ADD COLUMN IF NOT EXISTS delegation_jwt TEXT;

CREATE INDEX IF NOT EXISTS idx_credential_configs_delegated
    ON credential_configs(org_id, delegated_by)
    WHERE delegated_by IS NOT NULL AND is_active = TRUE;
