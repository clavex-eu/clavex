-- Migration 000128: per-org custom domains
-- Allows SaaS Enterprise customers to point their own CNAME to Clavex so that
-- their OIDC endpoints appear under e.g. auth.acme.com instead of the Clavex
-- base URL.
--
-- Flow:
--   1. Org admin POSTs their domain → status='pending'
--   2. Clavex validates the CNAME points at the Clavex edge (or Traefik).
--   3. Let's Encrypt / Traefik issues a TLS certificate automatically.
--   4. Status is set to 'active'; cert_expiry is recorded for monitoring.
--
-- Middleware reads the Host header, strips the port, and looks up the domain
-- here (with a Redis cache) to resolve the org_id used as the tenant context.

CREATE TABLE org_custom_domains (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain      TEXT        NOT NULL UNIQUE,
    -- 'pending'  — CNAME not yet verified
    -- 'active'   — verified and TLS certificate provisioned
    -- 'failed'   — CNAME check or certificate provisioning failed
    status      TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'active', 'failed')),
    verified_at TIMESTAMPTZ,
    -- cert_expiry is updated by the Traefik ACME integration or cron job
    cert_expiry TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX org_custom_domains_org_id ON org_custom_domains (org_id);
-- Fast lookup by domain (e.g. from the middleware Host header check).
-- The UNIQUE constraint already creates an index; this is just documentation.
