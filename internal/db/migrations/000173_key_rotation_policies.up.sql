-- Scheduled rotation policy for the GLOBAL OIDC/PQC signing keys.
--
-- Only the installation-wide signing keys are auto-rotatable: the classical
-- RSA key (DBSigner) and the ML-DSA-65 key (PQCSigner). Per-organisation BYOK
-- keys (signing_keys.org_id IS NOT NULL, managed by OrgSignerCache) are
-- deliberately excluded — they must be rotated through the org's own key
-- management process. The key_kind CHECK below enforces that: a 'byok' row
-- cannot exist, so the scheduler can never act on a BYOK key.
CREATE TABLE key_rotation_policies (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_kind               TEXT NOT NULL CHECK (key_kind IN ('oidc', 'pqc')),
    rotation_policy        TEXT NOT NULL DEFAULT 'manual' CHECK (rotation_policy IN ('manual', 'scheduled')),
    rotation_interval_days INTEGER NOT NULL DEFAULT 90 CHECK (rotation_interval_days > 0),
    last_rotated_at        TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One policy row per global key kind.
CREATE UNIQUE INDEX key_rotation_policies_kind ON key_rotation_policies (key_kind);
