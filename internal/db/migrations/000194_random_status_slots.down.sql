-- An old binary could reuse random slots or reject genuine credentials. Refuse
-- rollback once any list has reservations outside the old contiguous prefix.
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM identity.credential_status_lists WHERE allocated_slots <> decode(
        repeat('ff',next_slot/8)
        || CASE WHEN next_slot%8=0 THEN '' ELSE lpad(to_hex((1<<(next_slot%8))-1),2,'0') END
        || repeat('00',8192-next_slot/8-CASE WHEN next_slot%8=0 THEN 0 ELSE 1 END),'hex')) THEN
        RAISE EXCEPTION 'Random status slots are in use; legacy rollback requires operator review';
    END IF;
END $$;
ALTER TABLE identity.credential_status_lists
    DROP CONSTRAINT credential_status_allocated_size,
    DROP CONSTRAINT credential_status_allocated_count,
    DROP COLUMN allocated_slots;
COMMENT ON COLUMN identity.credential_status_lists.next_slot IS 'Next sequential available index';
