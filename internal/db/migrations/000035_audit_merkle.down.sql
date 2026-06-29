-- Rollback 000035
DROP INDEX IF EXISTS idx_merkle_checkpoints_range;
DROP INDEX IF EXISTS idx_merkle_checkpoints_org;
DROP TABLE IF EXISTS audit_merkle_checkpoints;
