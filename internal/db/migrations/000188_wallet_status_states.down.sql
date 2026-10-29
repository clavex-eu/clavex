-- Narrowing published lists would change the meaning of existing references.
-- Refuse rollback if a list has used the new state/encoding capability.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM identity.credential_status_lists WHERE bits<>1)
 OR EXISTS(SELECT 1 FROM identity.issued_credentials WHERE is_suspended OR issuer_cose_hash IS NOT NULL)
 THEN RAISE EXCEPTION 'wallet status state migration requires a reviewed data rollback'; END IF;
END $$;
DROP INDEX identity.issued_credential_issuer_cose_idx;
ALTER TABLE identity.issued_credentials DROP CONSTRAINT issued_credential_state_check;
ALTER TABLE identity.issued_credentials DROP COLUMN issuer_cose_hash, DROP COLUMN is_suspended;
ALTER TABLE identity.credential_status_lists DROP COLUMN bits;
