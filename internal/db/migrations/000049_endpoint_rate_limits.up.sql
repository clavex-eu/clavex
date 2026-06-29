-- 000049_endpoint_rate_limits.up.sql
-- Adds per-endpoint rate limit configuration to org_rate_limits.
--
-- endpoint_limits is a JSONB map of path-pattern → req/min, e.g.:
--   { "/elevate": 3, "/oid4vci/offers": 10 }
--
-- The middleware reads this map and applies it per path key.
-- A missing key means the endpoint is not separately rate-limited (only the
-- global org limit applies).

ALTER TABLE org_rate_limits
    ADD COLUMN endpoint_limits JSONB NOT NULL DEFAULT '{}'::jsonb;
