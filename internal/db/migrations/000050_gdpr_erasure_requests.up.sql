-- 000050_gdpr_erasure_requests.up.sql
-- Self-service GDPR Art.17 erasure requests with 30-day grace period.
--
-- Flow:
--   1. User clicks "Delete my account" → record inserted (status=pending_confirmation)
--   2. Email sent with one-time confirmation token (token_hash, expires 24 h)
--   3. User clicks link → status=scheduled, scheduled_for = NOW() + 30 days
--   4. Background worker finds rows WHERE status='scheduled' AND scheduled_for <= NOW()
--      → runs the erasure transaction, sets status=completed
--
-- Cancellation: user may cancel any pending/scheduled request via a second
-- one-time token (cancel_token_hash) before scheduled_for elapses.

CREATE TABLE gdpr_erasure_requests (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- 'pending_confirmation' | 'scheduled' | 'completed' | 'cancelled'
    status              TEXT        NOT NULL DEFAULT 'pending_confirmation'
                            CHECK (status IN ('pending_confirmation', 'scheduled', 'completed', 'cancelled')),
    -- One-time token to confirm the erasure request (hashed, expires 24h)
    confirm_token_hash  TEXT        UNIQUE,
    confirm_expires_at  TIMESTAMPTZ,
    -- One-time token to cancel a scheduled erasure (hashed, no expiry while status=scheduled)
    cancel_token_hash   TEXT        UNIQUE,
    -- When the actual erasure will execute (NOW() + 30 days after confirmation)
    scheduled_for       TIMESTAMPTZ,
    -- When the erasure was actually completed by the background worker
    completed_at        TIMESTAMPTZ,
    -- When the user cancelled (revoked the request)
    cancelled_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Allow at most one active (non-cancelled, non-completed) request per user
    CONSTRAINT uq_active_erasure_request UNIQUE (user_id, org_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_gdpr_erasure_scheduled
    ON gdpr_erasure_requests (scheduled_for)
    WHERE status = 'scheduled';

CREATE INDEX idx_gdpr_erasure_user
    ON gdpr_erasure_requests (user_id, org_id);
