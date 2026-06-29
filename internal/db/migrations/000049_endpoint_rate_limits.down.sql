-- 000049_endpoint_rate_limits.down.sql
ALTER TABLE org_rate_limits DROP COLUMN IF EXISTS endpoint_limits;
