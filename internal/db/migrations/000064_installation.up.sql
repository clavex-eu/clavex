-- Singleton row that persists a stable UUID for the installation.
-- The UUID is combined with the hostname to derive a privacy-preserving
-- installation_id for anonymous usage telemetry and offline license binding.
CREATE TABLE IF NOT EXISTS installation (
    id                  SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    installation_uuid   UUID        NOT NULL DEFAULT gen_random_uuid(),
    -- Set when org count first exceeds the license limit; cleared on compliance.
    first_violation_at  TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure the singleton row always exists after the migration runs.
INSERT INTO installation (id) VALUES (1) ON CONFLICT DO NOTHING;
