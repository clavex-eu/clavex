-- 000155_credential_config_key_attestation.up.sql
-- Add require_key_attestation flag to credential_configs.
--
-- When false (default) the OID4VCI issuer metadata does NOT include
-- key_attestations_required in proof_types_supported.  Standard wallets
-- (e.g. EUDI reference wallet) can then complete the pre-authorized code
-- flow without needing a wallet attestation signed by the issuer.
--
-- When true the field is included for conformance testing (HAIP §4.4 /
-- VCICheckKeyAttestationJwksIfKeyAttestationIsRequired) or for high-security
-- credential types that genuinely require wallet key attestation.

ALTER TABLE credential_configs
    ADD COLUMN IF NOT EXISTS require_key_attestation BOOLEAN NOT NULL DEFAULT FALSE;
