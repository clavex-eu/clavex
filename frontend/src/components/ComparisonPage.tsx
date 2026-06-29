import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'

// ─── Data ────────────────────────────────────────────────────────────────────

type Status = 'yes' | 'no' | 'partial' | 'enterprise' | 'plugin'

interface Feature {
  label: string
  tooltip?: string
  clavex: Status
  authentik: Status
  clerk: Status
  fusionauth: Status
  okta: Status
  keycloak: Status
  auth0: Status
  descope: Status
  kratos: Status
}

interface Category {
  name: string
  icon: string
  features: Feature[]
}

const CATEGORIES: Category[] = [
  {
    name: 'Core protocols',
    icon: '⬡',
    features: [
      { label: 'OIDC 1.0 / OAuth 2.0',         clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',     kratos: 'partial' },
      { label: 'PKCE (RFC 7636)',                clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',     kratos: 'partial' },
      { label: 'Token introspection (RFC 7662)', clavex: 'yes',        authentik: 'yes',        clerk: 'partial',    fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',     kratos: 'partial' },
      { label: 'Token revocation (RFC 7009)',    clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',     kratos: 'partial' },
      { label: 'Token exchange (RFC 8693)',       clavex: 'yes',        authentik: 'partial',    clerk: 'no',         fusionauth: 'partial',    okta: 'yes',        keycloak: 'yes',        auth0: 'partial',    descope: 'partial',  kratos: 'no' },
      { label: 'PAR (RFC 9126)',                  clavex: 'yes',        authentik: 'partial',    clerk: 'no',         fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'no',       kratos: 'no' },
      { label: 'JAR (RFC 9101)',                  clavex: 'yes',        authentik: 'no',         clerk: 'no',         fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'no',       kratos: 'no' },
      { label: 'Device flow (RFC 8628)',          clavex: 'yes',        authentik: 'yes',        clerk: 'no',         fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'no',       kratos: 'no' },
      { label: 'CIBA (OpenID backchannel)',       clavex: 'no',         authentik: 'no',         clerk: 'no',         fusionauth: 'no',         okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'no',       kratos: 'no' },
      { label: 'Dynamic registration (RFC 7591)',clavex: 'yes',        authentik: 'no',         clerk: 'no',         fusionauth: 'no',         okta: 'partial',    keycloak: 'yes',        auth0: 'partial',    descope: 'no',       kratos: 'no' },
      { label: 'SAML 2.0 IdP',                  clavex: 'yes',        authentik: 'yes',        clerk: 'enterprise', fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'enterprise', kratos: 'no' },
      { label: 'SAML 2.0 SP (external IdP)',     clavex: 'yes',        authentik: 'yes',        clerk: 'enterprise', fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'JWKS endpoint',                  clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'OIDC Discovery',                 clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
    ],
  },
  {
    name: 'Multi-tenancy',
    icon: '◈',
    features: [
      { label: 'Multiple tenants / orgs',        clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'partial',    descope: 'yes',      kratos: 'partial' },
      { label: 'Per-tenant OIDC endpoints',      clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'no',         descope: 'partial',  kratos: 'no' },
      { label: 'Per-tenant branding',            clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'enterprise', keycloak: 'yes',        auth0: 'enterprise', descope: 'yes',      kratos: 'partial' },
      { label: 'Per-tenant SMTP',                clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'enterprise', keycloak: 'plugin',     auth0: 'yes',        descope: 'yes',      kratos: 'no' },
      { label: 'Email domain verification',      clavex: 'yes',        authentik: 'partial',    clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'partial',    auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
    ],
  },
  {
    name: 'Security & MFA',
    icon: '⬖',
    features: [
      { label: 'TOTP (RFC 6238)',                clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'WebAuthn / passkeys',            clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'SMS / phone MFA',               clavex: 'partial',    authentik: 'partial',    clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'plugin',     auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Magic link login',               clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'plugin',     auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'MFA step-up enforcement',        clavex: 'yes',        authentik: 'yes',        clerk: 'partial',    fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Adaptive / risk-based auth',     clavex: 'no',         authentik: 'partial',    clerk: 'no',         fusionauth: 'partial',    okta: 'yes',        keycloak: 'partial',    auth0: 'yes',        descope: 'yes',      kratos: 'no' },
      { label: 'Bot detection / CAPTCHA',        clavex: 'yes',        authentik: 'partial',    clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'partial',    auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Login anomaly detection',        clavex: 'no',         authentik: 'partial',    clerk: 'no',         fusionauth: 'partial',    okta: 'yes',        keycloak: 'no',         auth0: 'yes',        descope: 'partial',  kratos: 'no' },
      { label: 'Breached password check (HIBP)', clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'enterprise', okta: 'yes',        keycloak: 'plugin',     auth0: 'yes',        descope: 'partial',  kratos: 'no' },
      { label: 'Password policy engine',         clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'max_age / auth_time enforcement',clavex: 'yes',        authentik: 'yes',        clerk: 'partial',    fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'partial',  kratos: 'partial' },
      { label: 'Login rate limiting',            clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
    ],
  },
  {
    name: 'User & group management',
    icon: '⬟',
    features: [
      { label: 'User CRUD + search',             clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'Groups',                         clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Hierarchical roles',             clavex: 'yes',        authentik: 'partial',    clerk: 'partial',    fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'partial',    descope: 'partial',  kratos: 'partial' },
      { label: 'Protocol mappers / claims',      clavex: 'yes',        authentik: 'yes',        clerk: 'partial',    fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'partial',  kratos: 'partial' },
      { label: 'Required actions',               clavex: 'yes',        authentik: 'yes',        clerk: 'partial',    fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'partial',    descope: 'partial',  kratos: 'yes' },
      { label: 'Granular session management',    clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'User impersonation',             clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'enterprise', keycloak: 'yes',        auth0: 'enterprise', descope: 'partial',  kratos: 'no' },
      { label: 'Org invitations',                clavex: 'yes',        authentik: 'partial',    clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'partial',    auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Bulk user import / migration',   clavex: 'yes',        authentik: 'partial',    clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'partial',  kratos: 'partial' },
      { label: 'User self-service portal',       clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'Multi-org user membership',      clavex: 'no',         authentik: 'no',         clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'partial',    auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Fine-grained authorization (FGA)',clavex: 'no',        authentik: 'no',         clerk: 'no',         fusionauth: 'no',         okta: 'yes',        keycloak: 'partial',    auth0: 'yes',        descope: 'no',       kratos: 'yes' },
    ],
  },
  {
    name: 'Provisioning & federation',
    icon: '⬠',
    features: [
      { label: 'SCIM 2.0 (RFC 7643/7644)',       clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'plugin',     auth0: 'enterprise', descope: 'yes',      kratos: 'no' },
      { label: 'LDAP integration',               clavex: 'yes',        authentik: 'yes',        clerk: 'no',         fusionauth: 'partial',    okta: 'enterprise', keycloak: 'yes',        auth0: 'enterprise', descope: 'no',       kratos: 'no' },
      { label: 'Social / external IdP',          clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'Client scopes',                  clavex: 'yes',        authentik: 'yes',        clerk: 'partial',    fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'partial',  kratos: 'partial' },
      { label: 'JIT provisioning from IdP',      clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'HR system connectors',           clavex: 'no',         authentik: 'no',         clerk: 'no',         fusionauth: 'no',         okta: 'yes',        keycloak: 'no',         auth0: 'partial',    descope: 'no',       kratos: 'no' },
    ],
  },
  {
    name: 'Observability & integrations',
    icon: '⬡',
    features: [
      { label: 'Audit log',                      clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Webhooks',                       clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'plugin',     auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'HTTP event connectors',          clavex: 'yes',        authentik: 'partial',    clerk: 'no',         fusionauth: 'yes',        okta: 'yes',        keycloak: 'plugin',     auth0: 'partial',    descope: 'partial',  kratos: 'partial' },
      { label: 'MQTT event connectors',          clavex: 'yes',        authentik: 'no',         clerk: 'no',         fusionauth: 'no',         okta: 'no',         keycloak: 'no',         auth0: 'no',         descope: 'no',       kratos: 'no' },
      { label: 'Kafka event streaming',          clavex: 'no',         authentik: 'no',         clerk: 'no',         fusionauth: 'yes',        okta: 'yes',        keycloak: 'no',         auth0: 'no',         descope: 'no',       kratos: 'no' },
      { label: 'JWT customization (hooks/scripts)',clavex: 'no',        authentik: 'partial',    clerk: 'no',         fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Custom auth flow builder',       clavex: 'no',         authentik: 'yes',        clerk: 'no',         fusionauth: 'partial',    okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
    ],
  },
  {
    name: 'Infrastructure',
    icon: '⬙',
    features: [
      { label: 'Forward Auth proxy',             clavex: 'yes',        authentik: 'yes',        clerk: 'no',         fusionauth: 'no',         okta: 'yes',        keycloak: 'plugin',     auth0: 'no',         descope: 'no',       kratos: 'partial' },
      { label: 'Self-hosted',                    clavex: 'yes',        authentik: 'yes',        clerk: 'no',         fusionauth: 'yes',        okta: 'no',         keycloak: 'yes',        auth0: 'no',         descope: 'no',       kratos: 'yes' },
      { label: 'Open source',                    clavex: 'yes',        authentik: 'yes',        clerk: 'no',         fusionauth: 'no',         okta: 'no',         keycloak: 'yes',        auth0: 'no',         descope: 'no',       kratos: 'yes' },
      { label: 'Written in Go',                  clavex: 'yes',        authentik: 'no',         clerk: 'no',         fusionauth: 'no',         okta: 'no',         keycloak: 'no',         auth0: 'no',         descope: 'no',       kratos: 'yes' },
      { label: 'PostgreSQL native',              clavex: 'yes',        authentik: 'yes',        clerk: 'no',         fusionauth: 'yes',        okta: 'no',         keycloak: 'yes',        auth0: 'no',         descope: 'no',       kratos: 'yes' },
      { label: 'Docker / single binary',         clavex: 'yes',        authentik: 'partial',    clerk: 'no',         fusionauth: 'yes',        okta: 'no',         keycloak: 'yes',        auth0: 'no',         descope: 'no',       kratos: 'partial' },
      { label: 'IP allowlist per org',           clavex: 'yes',        authentik: 'yes',        clerk: 'enterprise', fusionauth: 'yes',        okta: 'yes',        keycloak: 'partial',    auth0: 'enterprise', descope: 'yes',      kratos: 'no' },
    ],
  },
  {
    name: 'Developer experience',
    icon: '⬣',
    features: [
      { label: 'Drop-in UI components (SDK)',     clavex: 'no',         authentik: 'no',         clerk: 'yes',        fusionauth: 'partial',    okta: 'yes',        keycloak: 'partial',    auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Terraform provider',             clavex: 'no',         authentik: 'no',         clerk: 'no',         fusionauth: 'no',         okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'Mobile SDKs (iOS / Android)',    clavex: 'no',         authentik: 'partial',    clerk: 'yes',        fusionauth: 'partial',    okta: 'yes',        keycloak: 'partial',    auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Admin REST API',                 clavex: 'yes',        authentik: 'yes',        clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'yes',        auth0: 'yes',        descope: 'yes',      kratos: 'yes' },
      { label: 'Management SDKs (Node/Python…)', clavex: 'partial',    authentik: 'partial',    clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'partial',    auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
      { label: 'Interactive API explorer',       clavex: 'no',         authentik: 'no',         clerk: 'yes',        fusionauth: 'yes',        okta: 'yes',        keycloak: 'no',         auth0: 'yes',        descope: 'yes',      kratos: 'partial' },
    ],
  },
]

const PROVIDERS = ['clavex', 'authentik', 'clerk', 'fusionauth', 'okta', 'keycloak', 'auth0', 'descope', 'kratos'] as const
type Provider = typeof PROVIDERS[number]

const PROVIDER_META: Record<Provider, { label: string; tagline: string; color: string; bg: string; border: string }> = {
  clavex:    { label: 'Clavex',     tagline: 'This project',         color: '#1D9E75', bg: 'bg-brand-500/8',  border: 'border-brand-500/30' },
  authentik:  { label: 'Authentik',  tagline: 'Python / self-hosted', color: '#fd4b2d', bg: 'bg-red-500/5',    border: 'border-red-500/20' },
  clerk:      { label: 'Clerk',      tagline: 'Cloud / SaaS',         color: '#6c47ff', bg: 'bg-violet-500/5', border: 'border-violet-500/20' },
  fusionauth: { label: 'FusionAuth', tagline: 'Java / hybrid',        color: '#d97706', bg: 'bg-amber-500/5',  border: 'border-amber-500/20' },
  okta:       { label: 'Okta',       tagline: 'Enterprise / cloud',   color: '#007dc1', bg: 'bg-sky-500/5',    border: 'border-sky-500/20' },
  keycloak:   { label: 'Keycloak',   tagline: 'Java / self-hosted',   color: '#4a5568', bg: 'bg-slate-500/5',  border: 'border-slate-500/20' },
  auth0:      { label: 'Auth0',      tagline: 'Okta / cloud',         color: '#eb5424', bg: 'bg-orange-500/5', border: 'border-orange-500/20' },
  descope:    { label: 'Descope',    tagline: 'Cloud / no-code',      color: '#7c3aed', bg: 'bg-purple-500/5', border: 'border-purple-500/20' },
  kratos:     { label: 'Ory Kratos', tagline: 'Go / self-hosted',     color: '#0f766e', bg: 'bg-teal-500/5',   border: 'border-teal-500/20' },
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function StatusIcon({ status }: { status: Status }) {
  if (status === 'yes')
    return (
      <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-brand-500/15 text-brand-500">
        <svg viewBox="0 0 14 14" fill="none" className="w-3.5 h-3.5">
          <path d="M2.5 7L5.5 10L11.5 4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
    )
  if (status === 'no')
    return (
      <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-slate-100 text-slate-300">
        <svg viewBox="0 0 14 14" fill="none" className="w-3 h-3">
          <path d="M3 3L11 11M11 3L3 11" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      </span>
    )
  if (status === 'partial')
    return (
      <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-amber-50 text-amber-400">
        <svg viewBox="0 0 14 14" fill="none" className="w-3.5 h-3.5">
          <circle cx="7" cy="7" r="5" stroke="currentColor" strokeWidth="1.5" />
          <path d="M7 4.5V7.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          <circle cx="7" cy="9.5" r="0.75" fill="currentColor" />
        </svg>
      </span>
    )
  if (status === 'enterprise')
    return (
      <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-sky-50 text-sky-400">
        <svg viewBox="0 0 14 14" fill="none" className="w-3.5 h-3.5">
          <rect x="2" y="6" width="10" height="7" rx="1" stroke="currentColor" strokeWidth="1.5" />
          <path d="M4.5 6V4.5a2.5 2.5 0 0 1 5 0V6" stroke="currentColor" strokeWidth="1.5" />
        </svg>
      </span>
    )
  // plugin
  return (
    <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-slate-50 text-slate-400">
      <svg viewBox="0 0 14 14" fill="none" className="w-3.5 h-3.5">
        <rect x="1.5" y="5" width="5" height="4" rx="1" stroke="currentColor" strokeWidth="1.5" />
        <path d="M6.5 7H10.5M10.5 5.5V8.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    </span>
  )
}

function scoreFor(provider: Provider): number {
  const all = CATEGORIES.flatMap((c) => c.features)
  return all.reduce((n, f) => {
    const v = f[provider]
    return n + (v === 'yes' ? 2 : v === 'partial' || v === 'plugin' ? 1 : 0)
  }, 0)
}

type Winner = 'clavex' | 'competitor' | 'tie'

function rowWinner(es: Status, cs: Status): Winner {
  const score = (s: Status) => (s === 'yes' ? 2 : s === 'partial' || s === 'plugin' ? 1 : 0)
  const d = score(es) - score(cs)
  return d > 0 ? 'clavex' : d < 0 ? 'competitor' : 'tie'
}

// ─── Head-to-head card ───────────────────────────────────────────────────────

function HeadToHeadCard({ competitor }: { competitor: Exclude<Provider, 'clavex'> }) {
  const meta = PROVIDER_META[competitor]
  const allFeatures = CATEGORIES.flatMap((c) =>
    c.features.map((f) => ({ ...f, category: c.name, icon: c.icon }))
  )

  const eScore = scoreFor('clavex')
  const cScore = scoreFor(competitor)
  const total = allFeatures.length * 2

  const eurWins   = allFeatures.filter((f) => rowWinner(f.clavex, f[competitor]) === 'clavex').length
  const compWins  = allFeatures.filter((f) => rowWinner(f.clavex, f[competitor]) === 'competitor').length
  const ties      = allFeatures.filter((f) => rowWinner(f.clavex, f[competitor]) === 'tie').length

  // Only rows where there's a difference — hide ties to keep the table focused
  const diff = allFeatures.filter((f) => rowWinner(f.clavex, f[competitor]) !== 'tie')

  return (
    <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
      {/* Card header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100" style={{ borderTopColor: meta.color, borderTopWidth: 3 }}>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-brand-700 text-base">Clavex</span>
            <span className="text-slate-300 text-sm font-light">vs.</span>
            <span className="font-bold text-base" style={{ color: meta.color }}>{meta.label}</span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">{meta.tagline}</p>
        </div>

        {/* Mini scoreboard */}
        <div className="flex items-center gap-3">
          <div className="text-center">
            <div className="text-xl font-black text-brand-600">{eScore}</div>
            <div className="text-[9px] uppercase tracking-widest text-slate-400">Clavex</div>
          </div>
          <div className="text-slate-200 text-xl font-thin">|</div>
          <div className="text-center">
            <div className="text-xl font-black" style={{ color: meta.color }}>{cScore}</div>
            <div className="text-[9px] uppercase tracking-widest text-slate-400">{meta.label}</div>
          </div>
          <div className="text-slate-200 text-xl font-thin">|</div>
          <div className="text-center">
            <div className="text-xs font-semibold text-brand-500">+{eurWins}</div>
            <div className="text-[9px] text-slate-400">Clavex wins</div>
          </div>
          <div className="text-center">
            <div className="text-xs font-semibold" style={{ color: meta.color }}>+{compWins}</div>
            <div className="text-[9px] text-slate-400">{meta.label.split(' ')[0]} wins</div>
          </div>
          <div className="text-center">
            <div className="text-xs font-semibold text-slate-400">{ties}</div>
            <div className="text-[9px] text-slate-400">ties</div>
          </div>
        </div>
      </div>

      {/* Progress bar */}
      <div className="h-1.5 bg-slate-100 flex">
        <div className="h-full bg-brand-500 transition-all" style={{ width: `${Math.round((eScore / total) * 100)}%` }} />
        <div className="h-full transition-all" style={{ width: `${Math.round((cScore / total) * 100)}%`, backgroundColor: meta.color }} />
      </div>

      {/* Diff table — only rows where they differ */}
      {diff.length === 0 ? (
        <p className="px-5 py-6 text-sm text-slate-400 italic text-center">
          Identical feature support across all {total / 2} features.
        </p>
      ) : (
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50/70">
              <th className="text-left px-4 py-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider w-8">#</th>
              <th className="text-left px-4 py-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Feature</th>
              <th className="text-center px-3 py-2 text-[11px] font-semibold text-brand-600 uppercase tracking-wider">Clavex</th>
              <th className="text-center px-3 py-2 text-[11px] font-semibold uppercase tracking-wider" style={{ color: meta.color }}>{meta.label}</th>
              <th className="text-center px-3 py-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider w-16">Edge</th>
            </tr>
          </thead>
          <tbody>
            {diff.map((feat, idx) => {
              const w = rowWinner(feat.clavex, feat[competitor])
              return (
                <tr key={feat.label} className={`border-b border-slate-50 ${idx % 2 === 1 ? 'bg-slate-50/30' : ''}`}>
                  <td className="px-4 py-2.5 text-[11px] text-slate-300 tabular-nums">{idx + 1}</td>
                  <td className="px-4 py-2.5">
                    <div className="text-slate-700 font-medium text-[13px] leading-tight">{feat.label}</div>
                    <div className="text-[11px] text-slate-400">{feat.icon} {feat.category}</div>
                  </td>
                  <td className="text-center px-3 py-2.5">
                    <div className="flex justify-center">
                      <StatusIcon status={feat.clavex} />
                    </div>
                  </td>
                  <td className="text-center px-3 py-2.5">
                    <div className="flex justify-center">
                      <StatusIcon status={feat[competitor]} />
                    </div>
                  </td>
                  <td className="text-center px-3 py-2.5">
                    {w === 'clavex' && (
                      <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-brand-500/10 text-brand-600">↑</span>
                    )}
                    {w === 'competitor' && (
                      <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold text-white" style={{ backgroundColor: meta.color }}>{meta.label.split(' ')[0]} ↑</span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}

      {/* Footer note */}
      <div className="px-5 py-3 border-t border-slate-100 flex justify-between items-center">
        <span className="text-[11px] text-slate-400">
          Showing {diff.length} of {allFeatures.length} features where they differ
        </span>
        <span className="text-[11px] font-semibold" style={{ color: w_overall(eScore, cScore) === 'clavex' ? '#1D9E75' : w_overall(eScore, cScore) === 'competitor' ? meta.color : '#94a3b8' }}>
          {w_overall(eScore, cScore) === 'clavex' ? '✦ Clavex leads' : w_overall(eScore, cScore) === 'competitor' ? `${meta.label} leads` : 'Tied'}
        </span>
      </div>
    </div>
  )
}

function w_overall(a: number, b: number): 'clavex' | 'competitor' | 'tie' {
  return a > b ? 'clavex' : a < b ? 'competitor' : 'tie'
}

// ─── View toggle ─────────────────────────────────────────────────────────────

type ViewMode = 'matrix' | 'h2h'

// ─── Component ───────────────────────────────────────────────────────────────

export default function ComparisonPage() {
  const [activeCategory, setActiveCategory] = useState<string | null>(null)
  const [view, setView] = useState<ViewMode>('matrix')

  const visible = activeCategory
    ? CATEGORIES.filter((c) => c.name === activeCategory)
    : CATEGORIES

  const totalMax = CATEGORIES.flatMap((c) => c.features).length * 2

  const competitors = PROVIDERS.filter((p) => p !== 'clavex') as Exclude<Provider, 'clavex'>[]

  // Precompute overall scores for the scoreboard (used in both views)
  const scores = useMemo(() => Object.fromEntries(PROVIDERS.map((p) => [p, scoreFor(p)])) as Record<Provider, number>, [])

  return (
    <div className="min-h-screen bg-slate-50">
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="bg-white border-b border-slate-100 px-6 py-8">
        <div className="max-w-7xl mx-auto">
          {/* Top nav */}
          <div className="flex items-center justify-end gap-4 mb-6 text-sm">
            <Link to="/pricing" className="font-medium text-brand-600 hover:text-brand-700">Pricing</Link>
            <Link to="/login" className="px-3 py-1.5 rounded-lg bg-brand-600 text-white hover:bg-brand-700 font-medium">Get started →</Link>
          </div>
          <div className="flex items-start justify-between gap-6 flex-wrap">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="inline-block w-2 h-2 rounded-full bg-brand-500" />
                <span className="text-xs font-semibold tracking-widest text-brand-600 uppercase">Feature comparison</span>
              </div>
              <h1 className="text-3xl font-bold text-slate-900 tracking-tight">
                Clavex <span className="text-slate-400 font-light">vs.</span> the field
              </h1>
              <p className="mt-1 text-slate-500 text-sm max-w-xl">
                Authentik · Clerk · FusionAuth · Okta · Keycloak · Auth0 · Descope · Ory Kratos — scored across{' '}
                {CATEGORIES.reduce((n, c) => n + c.features.length, 0)} features in{' '}
                {CATEGORIES.length} categories.
              </p>
            </div>
            {/* Score bar */}
            <div className="flex gap-4 flex-wrap">
              {PROVIDERS.map((p) => {
                const score = scores[p]
                const pct = Math.round((score / totalMax) * 100)
                const meta = PROVIDER_META[p]
                return (
                  <div key={p} className="flex flex-col items-center gap-1.5 min-w-[56px]">
                    <div className="relative w-10 h-10 flex items-center justify-center">
                      <svg viewBox="0 0 36 36" className="w-10 h-10 -rotate-90">
                        <circle cx="18" cy="18" r="15" fill="none" stroke="#e2e8f0" strokeWidth="3" />
                        <circle
                          cx="18" cy="18" r="15" fill="none"
                          stroke={meta.color} strokeWidth="3"
                          strokeDasharray={`${Math.round((pct / 100) * 94.2)} 94.2`}
                          strokeLinecap="round"
                        />
                      </svg>
                      <span className="absolute text-[9px] font-bold" style={{ color: meta.color }}>{pct}%</span>
                    </div>
                    <span className="text-[10px] font-semibold text-slate-600">{meta.label}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* ── View toggle + filters ─────────────────────────────── */}
          <div className="flex items-center justify-between mt-6 flex-wrap gap-3">
            {/* View toggle */}
            <div className="flex rounded-lg border border-slate-200 overflow-hidden text-xs font-medium">
              <button
                onClick={() => setView('matrix')}
                className={`px-4 py-1.5 transition-colors ${
                  view === 'matrix' ? 'bg-brand-500 text-white' : 'bg-white text-slate-600 hover:bg-slate-50'
                }`}
              >
                ⊞ Full matrix
              </button>
              <button
                onClick={() => setView('h2h')}
                className={`px-4 py-1.5 border-l border-slate-200 transition-colors ${
                  view === 'h2h' ? 'bg-brand-500 text-white' : 'bg-white text-slate-600 hover:bg-slate-50'
                }`}
              >
                ⊟ Head-to-head
              </button>
            </div>

            {/* Category pills — only relevant in matrix view */}
            {view === 'matrix' && (
              <div className="flex gap-2 flex-wrap">
                <button
                  onClick={() => setActiveCategory(null)}
                  className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                    activeCategory === null
                      ? 'bg-brand-500 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  All categories
                </button>
                {CATEGORIES.map((c) => (
                  <button
                    key={c.name}
                    onClick={() => setActiveCategory(c.name === activeCategory ? null : c.name)}
                    className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                      activeCategory === c.name
                        ? 'bg-brand-500 text-white'
                        : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    {c.icon} {c.name}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Matrix view ────────────────────────────────────────────── */}
      {view === 'matrix' && (
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="rounded-2xl border border-slate-200 overflow-hidden shadow-card bg-white">
            <table className="w-full border-collapse text-sm">
              {/* Column headers */}
              <thead>
                <tr className="border-b border-slate-200">
                  <th className="text-left px-5 py-4 font-semibold text-slate-700 bg-slate-50/80 w-56">
                    Feature
                  </th>
                  {PROVIDERS.map((p) => {
                    const meta = PROVIDER_META[p]
                    const isClavex = p === 'clavex'
                    return (
                      <th
                        key={p}
                        className={`text-center px-3 py-4 ${
                          isClavex
                            ? 'bg-brand-500/6 border-x border-brand-500/20'
                            : 'bg-slate-50/80'
                        }`}
                      >
                        <div className="flex flex-col items-center gap-0.5">
                          <span className={`font-bold text-sm ${isClavex ? 'text-brand-700' : 'text-slate-800'}`}>
                            {meta.label}
                          </span>
                          <span className="text-[10px] font-normal text-slate-400 leading-tight">
                            {meta.tagline}
                          </span>
                        </div>
                      </th>
                    )
                  })}
                </tr>
              </thead>

              <tbody>
                {visible.map((cat) => (
                  <>
                    <tr key={`cat-${cat.name}`} className="border-t border-slate-100">
                      <td
                        colSpan={PROVIDERS.length + 1}
                        className="px-5 py-2.5 bg-slate-50 border-b border-slate-100"
                      >
                        <span className="text-xs font-bold tracking-widest uppercase text-slate-500">
                          {cat.icon}&nbsp;&nbsp;{cat.name}
                        </span>
                      </td>
                    </tr>
                    {cat.features.map((feat, idx) => (
                      <tr
                        key={feat.label}
                        className={`border-b border-slate-50 hover:bg-slate-50/60 transition-colors ${
                          idx % 2 === 1 ? 'bg-slate-50/30' : ''
                        }`}
                      >
                        <td className="px-5 py-3 text-slate-700 font-medium text-[13px]">
                          {feat.label}
                        </td>
                        {PROVIDERS.map((p) => (
                          <td
                            key={p}
                            className={`text-center px-3 py-3 ${
                              p === 'clavex' ? 'bg-brand-500/4 border-x border-brand-500/10' : ''
                            }`}
                          >
                            <div className="flex justify-center">
                              <StatusIcon status={feat[p]} />
                            </div>
                          </td>
                        ))}
                      </tr>
                    ))}
                  </>
                ))}
              </tbody>

              <tfoot>
                <tr className="border-t-2 border-slate-200 bg-slate-50">
                  <td className="px-5 py-3 text-xs font-bold text-slate-500 uppercase tracking-widest">
                    Score
                  </td>
                  {PROVIDERS.map((p) => {
                    const isClavex = p === 'clavex'
                    return (
                      <td
                        key={p}
                        className={`text-center px-3 py-3 ${
                          isClavex ? 'bg-brand-500/6 border-x border-brand-500/20' : ''
                        }`}
                      >
                        <span className={`font-bold text-sm ${isClavex ? 'text-brand-600' : 'text-slate-600'}`}>
                          {scores[p]}
                        </span>
                      </td>
                    )
                  })}
                </tr>
              </tfoot>
            </table>
          </div>

          {/* Legend */}
          <div className="mt-4 flex gap-5 flex-wrap px-1">
            {[
              { status: 'yes'        as Status, label: 'Supported' },
              { status: 'partial'    as Status, label: 'Partial / limited' },
              { status: 'enterprise' as Status, label: 'Enterprise / paid tier' },
              { status: 'plugin'     as Status, label: 'Via plugin / extension' },
              { status: 'no'         as Status, label: 'Not available' },
            ].map(({ status, label }) => (
              <div key={status} className="flex items-center gap-2 text-xs text-slate-500">
                <StatusIcon status={status} />
                {label}
              </div>
            ))}
            <div className="ml-auto text-xs text-slate-400 italic">
              Last updated: May 2026 — data is approximate and may change
            </div>
          </div>
        </div>
      )}

      {/* ── Head-to-head view ──────────────────────────────────────── */}
      {view === 'h2h' && (
        <div className="max-w-7xl mx-auto px-4 py-6">
          <p className="text-xs text-slate-400 italic mb-5 px-1">
            Each table shows only features where Clavex and the competitor differ. Tied features are hidden.
          </p>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {competitors.map((c) => (
              <HeadToHeadCard key={c} competitor={c} />
            ))}
          </div>
          <div className="mt-4 flex gap-5 flex-wrap px-1">
            {[
              { status: 'yes'        as Status, label: 'Supported' },
              { status: 'partial'    as Status, label: 'Partial / limited' },
              { status: 'enterprise' as Status, label: 'Enterprise / paid tier' },
              { status: 'plugin'     as Status, label: 'Via plugin / extension' },
              { status: 'no'         as Status, label: 'Not available' },
            ].map(({ status, label }) => (
              <div key={status} className="flex items-center gap-2 text-xs text-slate-500">
                <StatusIcon status={status} />
                {label}
              </div>
            ))}
            <div className="ml-auto text-xs text-slate-400 italic">
              Last updated: May 2026 — data is approximate and may change
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
