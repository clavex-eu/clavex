-- Migration 000169: make the per-scope active-key indexes key_use-aware
--
-- Migration 000168 added key_use ('sig' | 'enc') and rebuilt the (now redundant)
-- signing_keys_one_active index to include it. But the invariants actually
-- enforced are the per-scope indexes created in migration 000132:
--   • signing_keys_one_active_global   ON (status)          WHERE active AND org_id IS NULL
--   • signing_keys_one_active_per_org  ON (org_id, status)  WHERE active AND org_id IS NOT NULL
-- Both key only on (status[, org_id]) and ignore key_use, so bootstrapping an
-- active 'enc' key collides with the active 'sig' key:
--   ERROR: duplicate key value violates unique constraint
--          "signing_keys_one_active_global" (SQLSTATE 23505)
--
-- Rebuild both per-scope indexes to include key_use (and pqc_algorithm, matching
-- migration 000162) so one active sig key AND one active enc key may coexist in
-- each scope — globally and per org, classical and PQC.

DROP INDEX IF EXISTS signing_keys_one_active_global;
DROP INDEX IF EXISTS signing_keys_one_active_per_org;

CREATE UNIQUE INDEX signing_keys_one_active_global
    ON signing_keys (key_use, COALESCE(pqc_algorithm, ''), status)
    WHERE status = 'active' AND org_id IS NULL;

CREATE UNIQUE INDEX signing_keys_one_active_per_org
    ON signing_keys (org_id, key_use, COALESCE(pqc_algorithm, ''), status)
    WHERE status = 'active' AND org_id IS NOT NULL;
