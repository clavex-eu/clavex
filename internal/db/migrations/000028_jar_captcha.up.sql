-- 000028: JAR support fields on oidc_clients + org captcha settings

-- JAR (RFC 9101): clients may optionally register a JWKS URI so the server
-- can verify signed request objects, and declare which signing alg they use.
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS jwks_uri                    TEXT,
    ADD COLUMN IF NOT EXISTS request_object_signing_alg  TEXT NOT NULL DEFAULT 'none';

-- Per-org CAPTCHA settings (Cloudflare Turnstile, hCaptcha, reCAPTCHA v2)
CREATE TABLE IF NOT EXISTS identity.org_captcha_settings (
    org_id      UUID PRIMARY KEY REFERENCES identity.organizations(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL DEFAULT 'turnstile',   -- 'turnstile' | 'hcaptcha' | 'recaptcha'
    site_key    TEXT NOT NULL,
    secret_key  TEXT NOT NULL,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
