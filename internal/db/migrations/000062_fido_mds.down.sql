ALTER TABLE webauthn_attestation_policies
    DROP COLUMN IF EXISTS exclude_revoked_authenticators,
    DROP COLUMN IF EXISTS min_certification_level,
    DROP COLUMN IF EXISTS require_mds_certification;

DROP TABLE IF EXISTS fido_mds_sync;
DROP TABLE IF EXISTS fido_mds_entries;
