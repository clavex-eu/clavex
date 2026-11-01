-- No existing keys or issuer records are rewritten. New API writes encrypt local
-- keys; Vault references contain no token and are authorised by operator config.
ALTER TABLE org_mdoc_issuers ADD COLUMN vault_signer_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE org_mdoc_issuers ADD CONSTRAINT mdoc_signer_exclusive CHECK
 (vault_signer_ref = '' OR ds_private_key_pem IS NULL);
