DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM identity.issued_credentials WHERE status_parents<>'[]'::jsonb OR parent_status_hold)
 OR EXISTS(SELECT 1 FROM identity.deferred_credentials WHERE status_parents<>'[]'::jsonb)
 THEN RAISE EXCEPTION 'cannot discard authenticated parent lifecycle links without reviewed data rollback'; END IF;
END $$;
DROP INDEX identity.issued_credential_parent_poll_idx;
ALTER TABLE identity.issued_credentials DROP COLUMN status_parents,DROP COLUMN parents_checked_at,DROP COLUMN parent_status_hold;
ALTER TABLE identity.deferred_credentials DROP COLUMN status_parents;
