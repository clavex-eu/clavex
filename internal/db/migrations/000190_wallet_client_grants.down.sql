DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM identity.wallet_issuance_grants WHERE client_auth_method<>'none' OR attestation_jkt<>'' OR status_parents<>'[]'::jsonb OR authorization_code_id IS NOT NULL)
 THEN RAISE EXCEPTION 'cannot discard wallet client/grant bindings without reviewed lifecycle rollback'; END IF;
END $$;
DROP INDEX identity.wallet_grant_authorization_code_idx;
ALTER TABLE identity.wallet_issuance_grants DROP COLUMN client_auth_method,DROP COLUMN attestation_jkt,DROP COLUMN status_parents,DROP COLUMN authorization_code_id;
