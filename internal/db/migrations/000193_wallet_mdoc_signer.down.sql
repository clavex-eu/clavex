-- Refuse to discard external signing configuration during rollback.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM org_mdoc_issuers WHERE vault_signer_ref <> '' OR ds_private_key_pem LIKE 'wallet-key:v1:%') THEN
  RAISE EXCEPTION 'Review external references and encrypted DS keys before rollback to an older binary';
 END IF;
END $$;
ALTER TABLE org_mdoc_issuers DROP CONSTRAINT mdoc_signer_exclusive;
ALTER TABLE org_mdoc_issuers DROP COLUMN vault_signer_ref;
