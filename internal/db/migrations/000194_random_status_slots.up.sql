-- Preserve every legacy sequential reservation, including slots whose issued
-- records were later deleted. Zero status bits do not mean a slot is unused.
ALTER TABLE identity.credential_status_lists
    ADD COLUMN allocated_slots bytea NOT NULL DEFAULT decode(repeat('00',8192),'hex');

UPDATE identity.credential_status_lists SET allocated_slots = decode(
    repeat('ff',next_slot/8)
    || CASE WHEN next_slot%8=0 THEN '' ELSE lpad(to_hex((1<<(next_slot%8))-1),2,'0') END
    || repeat('00',8192-next_slot/8-CASE WHEN next_slot%8=0 THEN 0 ELSE 1 END),'hex');

ALTER TABLE identity.credential_status_lists
    ADD CONSTRAINT credential_status_allocated_size CHECK(octet_length(allocated_slots)=8192),
    ADD CONSTRAINT credential_status_allocated_count CHECK(next_slot BETWEEN 0 AND 65536);
COMMENT ON COLUMN identity.credential_status_lists.next_slot IS
    'Number of reserved slots; random allocations need not form a contiguous prefix';
