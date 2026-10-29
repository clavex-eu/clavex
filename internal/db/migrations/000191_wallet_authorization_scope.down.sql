DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM identity.wallet_issuance_grants WHERE authorization_scope<>'' OR authorization_details<>'[]'::jsonb) THEN RAISE EXCEPTION 'cannot discard active wallet authorization scope bindings'; END IF;
END $$;
ALTER TABLE identity.wallet_issuance_grants DROP COLUMN authorization_scope,DROP COLUMN authorization_details;
