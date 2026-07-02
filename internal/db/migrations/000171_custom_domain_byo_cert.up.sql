-- Migration 000171: bring-your-own TLS certificate for per-org custom domains
-- (Clavex Cloud shared cluster).
--
-- The default cert model is ACME (Traefik / Let's Encrypt auto-issues). An org
-- may instead upload its own certificate, which the ingress reconciler stores as
-- a k8s TLS Secret. The private key is encrypted at rest with AES-256-GCM (same
-- KEK as signing_keys) — the ciphertext lives in cert_key_enc.

ALTER TABLE org_custom_domains
    -- 'acme' — Traefik/Let's Encrypt issues + renews automatically (default).
    -- 'byo'  — customer-supplied certificate in cert_pem + cert_key_enc.
    ADD COLUMN IF NOT EXISTS cert_source  TEXT NOT NULL DEFAULT 'acme'
        CHECK (cert_source IN ('acme', 'byo')),
    -- Full PEM chain (leaf + intermediates) for BYO certs; NULL for ACME.
    ADD COLUMN IF NOT EXISTS cert_pem     TEXT,
    -- AES-256-GCM encrypted PKCS#8/PKCS#1 DER private key: nonce||ciphertext+tag.
    ADD COLUMN IF NOT EXISTS cert_key_enc BYTEA;
