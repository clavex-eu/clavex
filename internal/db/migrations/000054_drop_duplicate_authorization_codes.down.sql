-- No rollback: recreating the ghost table would reintroduce the bug.
-- If needed, restore from sessions.authorization_codes schema.
SELECT 1;
