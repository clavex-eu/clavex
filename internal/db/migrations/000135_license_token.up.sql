-- 000135: runtime license upload support.
--
-- Adds a license_token column to the installation singleton so that a license
-- JWT uploaded via the admin frontend survives server restarts without requiring
-- a file mount or config change.
--
-- On startup the server tries: 1) config.license.key_file  2) this column.
-- PUT /api/v1/superadmin/license writes here AND hot-reloads the checker.

ALTER TABLE installation
    ADD COLUMN IF NOT EXISTS license_token TEXT;
