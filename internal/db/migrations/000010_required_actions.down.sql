-- 000010_required_actions.down.sql
ALTER TABLE users DROP COLUMN IF EXISTS required_actions;
