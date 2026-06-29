/**
 * Self-Serve IT Admin Portal
 *
 * Simplified console for ISV customers' IT admins to configure:
 *   - SSO (SAML / OIDC identity providers)
 *   - SCIM provisioning token
 *   - Auto-enrollment domains
 *   - MFA policy
 *
 * Uses the same backend API as the full tenant console but presents only
 * the controls relevant to an end-customer IT admin, reducing ISV support load.
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  Globe, Users, Settings, Shield, CheckCircle2, AlertCircle,
  ClipboardCopy, Plus, Trash2, ExternalLink,
} from 'lucide-react'

// ── Styles ────────────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'var(--clavex-surface)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}

const inp: React.CSSProperties = {
  width: '100%', padding: '8px 12px', borderRadius: 8, fontSize: 13,
  border: '0.5px solid var(--clavex-border)',
  background: 'var(--clavex-surface)', color: 'var(--clavex-text)',
  outline: 'none', boxSizing: 'border-box',
}

const lbl: React.CSSProperties = {
  display: 'block', fontSize: 12, fontWeight: 600,
  color: 'var(--clavex-neutral)', marginBottom: 4,
}

const btn = (variant: 'primary' | 'danger' | 'ghost' = 'primary'): React.CSSProperties => ({
  display: 'inline-flex', alignItems: 'center', gap: 6,
  padding: '7px 14px', borderRadius: 8, fontSize: 13, fontWeight: 600,
  border: variant === 'ghost' ? '0.5px solid var(--clavex-border)' : 'none',
  cursor: 'pointer',
  background: variant === 'primary' ? 'var(--clavex-primary)'
    : variant === 'danger' ? 'var(--clavex-danger)'
    : 'var(--clavex-surface)',
  color: variant === 'ghost' ? 'var(--clavex-text)' : '#fff',
})

// ── Section header ────────────────────────────────────────────────────────────

function SectionHeader({ Icon, title, description }: {
  Icon: React.FC<{ size?: number; color?: string }>
  title: string
  description: string
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 20 }}>
      <div style={{ padding: 8, borderRadius: 10, background: 'var(--clavex-primary)12', flexShrink: 0 }}>
        <Icon size={20} color="var(--clavex-primary)" />
      </div>
      <div>
        <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>{title}</h2>
        <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', margin: '4px 0 0' }}>{description}</p>
      </div>
    </div>
  )
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface IdentityProvider {
  id: string
  name: string
  type: string
  enabled: boolean
  created_at: string
}

interface OrgSettings {
  auto_enroll_domains: string[]
  mfa_required: boolean
}

// ── SSO tab ───────────────────────────────────────────────────────────────────

export function SSOTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', type: 'saml', entity_id: '', sso_url: '', x509_certificate: '' })

  const { data, isLoading } = useQuery({
    queryKey: ['portal-idps', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/identity-providers`).then(r => r.data),
  })

  const createMut = useMutation({
    mutationFn: (body: typeof form) => api.post(`/organizations/${orgId}/identity-providers`, body).then(r => r.data),
    onSuccess: () => { toast.success('Identity provider added'); qc.invalidateQueries({ queryKey: ['portal-idps', orgId] }); setShowForm(false) },
    onError: () => toast.error('Failed to add identity provider'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/identity-providers/${id}`),
    onSuccess: () => { toast.success('Identity provider removed'); qc.invalidateQueries({ queryKey: ['portal-idps', orgId] }) },
    onError: () => toast.error('Failed to remove identity provider'),
  })

  const idps: IdentityProvider[] = Array.isArray(data) ? data : (data?.data ?? [])

  return (
    <div>
      <SectionHeader
        Icon={Globe}
        title="SSO / Identity Providers"
        description="Connect your corporate directory via SAML 2.0 or OIDC. Users will be able to log in with their existing credentials."
      />

      {/* Info callout */}
      <div style={{ background: '#0369a112', border: '1px solid #0369a130', borderRadius: 10, padding: '12px 16px', marginBottom: 20 }}>
        <p style={{ fontSize: 13, margin: 0, color: '#0369a1' }}>
          After adding an IdP, your users can sign in at the organization login URL.
          SAML metadata is available at <code style={{ fontSize: 12 }}>/saml/metadata</code>.
        </p>
      </div>

      <button style={{ ...btn('primary'), marginBottom: 16 }} onClick={() => setShowForm(v => !v)}>
        <Plus size={14} /> Add Identity Provider
      </button>

      {showForm && (
        <div style={{ ...card, marginBottom: 16 }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>New Identity Provider</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <span style={lbl}>Display Name</span>
              <input style={inp} placeholder="Acme Corp SSO" value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div>
              <span style={lbl}>Protocol</span>
              <select style={inp} value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}>
                <option value="saml">SAML 2.0</option>
                <option value="oidc">OIDC</option>
              </select>
            </div>
            {form.type === 'saml' ? (
              <>
                <div>
                  <span style={lbl}>Entity ID (IdP)</span>
                  <input style={inp} placeholder="https://idp.example.com/metadata"
                    value={form.entity_id} onChange={e => setForm(f => ({ ...f, entity_id: e.target.value }))} />
                </div>
                <div>
                  <span style={lbl}>SSO URL</span>
                  <input style={inp} placeholder="https://idp.example.com/sso"
                    value={form.sso_url} onChange={e => setForm(f => ({ ...f, sso_url: e.target.value }))} />
                </div>
                <div style={{ gridColumn: '1/-1' }}>
                  <span style={lbl}>X.509 Certificate</span>
                  <textarea style={{ ...inp, height: 100, fontFamily: 'monospace', fontSize: 11, resize: 'vertical' }}
                    placeholder="Paste the IdP signing certificate (PEM or raw base64)..."
                    value={form.x509_certificate}
                    onChange={e => setForm(f => ({ ...f, x509_certificate: e.target.value }))} />
                </div>
              </>
            ) : (
              <>
                <div>
                  <span style={lbl}>Client ID</span>
                  <input style={inp} placeholder="client_id from your OIDC provider"
                    value={form.entity_id} onChange={e => setForm(f => ({ ...f, entity_id: e.target.value }))} />
                </div>
                <div>
                  <span style={lbl}>Discovery URL</span>
                  <input style={inp} placeholder="https://accounts.google.com/.well-known/openid-configuration"
                    value={form.sso_url} onChange={e => setForm(f => ({ ...f, sso_url: e.target.value }))} />
                </div>
              </>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button style={btn('primary')} onClick={() => createMut.mutate(form)} disabled={createMut.isPending}>
              {createMut.isPending ? 'Saving…' : 'Save'}
            </button>
            <button style={btn('ghost')} onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      {isLoading ? <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>Loading…</p> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {idps.length === 0 && (
            <div style={{ ...card, textAlign: 'center', padding: 40, color: 'var(--clavex-neutral)' }}>
              <Globe size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
              <p style={{ fontSize: 13 }}>No identity providers configured. Add one to enable SSO.</p>
            </div>
          )}
          {idps.map((idp: IdentityProvider) => (
            <div key={idp.id} style={{ ...card, display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 36, height: 36, borderRadius: 8, background: 'var(--clavex-primary)12',
                display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <Globe size={18} color="var(--clavex-primary)" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 13, fontWeight: 700 }}>{idp.name}</span>
                  <span style={{ fontSize: 11, padding: '1px 6px', borderRadius: 4,
                    background: 'var(--clavex-border)', color: 'var(--clavex-neutral)' }}>
                    {idp.type?.toUpperCase()}
                  </span>
                  {idp.enabled
                    ? <CheckCircle2 size={13} color="#16a34a" />
                    : <AlertCircle size={13} color="#d97706" />
                  }
                </div>
                <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', margin: '2px 0 0' }}>
                  Added {new Date(idp.created_at).toLocaleDateString()}
                </p>
              </div>
              <button style={{ ...btn('ghost'), fontSize: 12, padding: '4px 10px', color: 'var(--clavex-danger)' }}
                onClick={() => { if (confirm(`Remove "${idp.name}"?`)) deleteMut.mutate(idp.id) }}>
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── SCIM tab ──────────────────────────────────────────────────────────────────

export function SCIMTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [revealed, setRevealed] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['portal-scim', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/scim/tokens`).then(r => r.data),
  })

  const createMut = useMutation({
    mutationFn: () => api.post(`/organizations/${orgId}/scim/tokens`, { name: 'IT Admin token' }).then(r => r.data),
    onSuccess: (d) => { setRevealed(d.token ?? d.raw_token ?? null); qc.invalidateQueries({ queryKey: ['portal-scim', orgId] }) },
    onError: () => toast.error('Failed to create SCIM token'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/scim/tokens/${id}`),
    onSuccess: () => { toast.success('Token revoked'); qc.invalidateQueries({ queryKey: ['portal-scim', orgId] }) },
    onError: () => toast.error('Failed to revoke token'),
  })

  const tokens: Array<{ id: string; name: string; created_at: string }> = Array.isArray(data) ? data : (data?.data ?? [])
  const scimEndpoint = `${window.location.origin}/scim/v2/${orgId}`

  return (
    <div>
      <SectionHeader
        Icon={Users}
        title="SCIM Provisioning"
        description="Automatically sync users and groups from your directory (Okta, Azure AD, Google Workspace, etc.) using SCIM 2.0."
      />

      {/* Endpoint info */}
      <div style={{ ...card, marginBottom: 16, background: '#f8fafc' }}>
        <p style={{ fontSize: 12, fontWeight: 700, margin: '0 0 6px', color: 'var(--clavex-neutral)' }}>SCIM Endpoint</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <code style={{ fontSize: 12, flex: 1, wordBreak: 'break-all' }}>{scimEndpoint}</code>
          <button style={btn('ghost')} onClick={() => { navigator.clipboard.writeText(scimEndpoint); toast.success('Copied') }}>
            <ClipboardCopy size={13} />
          </button>
        </div>
        <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', margin: '6px 0 0' }}>
          Paste this URL into your identity provider's SCIM configuration. Add a bearer token from below.
        </p>
      </div>

      {/* Token reveal banner */}
      {revealed && (
        <div style={{ background: '#16a34a12', border: '1px solid #16a34a30', borderRadius: 10, padding: '14px 18px', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: '#16a34a' }}>SCIM Bearer Token — copy now, won't be shown again</span>
            <button style={btn('ghost')} onClick={() => setRevealed(null)}>Dismiss</button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--clavex-surface)',
            borderRadius: 8, padding: '8px 12px', fontFamily: 'monospace', fontSize: 12 }}>
            <span style={{ flex: 1, wordBreak: 'break-all' }}>{revealed}</span>
            <button style={btn('ghost')} onClick={() => { navigator.clipboard.writeText(revealed); toast.success('Copied') }}>
              <ClipboardCopy size={13} /> Copy
            </button>
          </div>
        </div>
      )}

      <button style={{ ...btn('primary'), marginBottom: 16 }} onClick={() => createMut.mutate()} disabled={createMut.isPending}>
        <Plus size={14} /> {createMut.isPending ? 'Generating…' : 'Generate New Token'}
      </button>

      {isLoading ? <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>Loading…</p> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {tokens.length === 0 && (
            <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>No active SCIM tokens. Generate one to start syncing.</p>
          )}
          {tokens.map(t => (
            <div key={t.id} style={{ ...card, display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ flex: 1 }}>
                <span style={{ fontSize: 13, fontWeight: 700 }}>{t.name}</span>
                <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', margin: '2px 0 0' }}>
                  Created {new Date(t.created_at).toLocaleDateString()}
                </p>
              </div>
              <button style={{ ...btn('ghost'), fontSize: 12, padding: '4px 10px', color: 'var(--clavex-danger)' }}
                onClick={() => { if (confirm('Revoke this token? SCIM sync will stop.')) deleteMut.mutate(t.id) }}>
                <Trash2 size={13} /> Revoke
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── DOMAINS tab ───────────────────────────────────────────────────────────────

export function DomainsTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [newDomain, setNewDomain] = useState('')

  const { data: org, isLoading } = useQuery({
    queryKey: ['portal-org', orgId],
    queryFn: () => api.get(`/organizations/${orgId}`).then(r => r.data),
  })

  const settings: OrgSettings = {
    auto_enroll_domains: org?.auto_enroll_domains ?? [],
    mfa_required: org?.mfa_required ?? false,
  }

  const updateMut = useMutation({
    mutationFn: (domains: string[]) =>
      api.patch(`/organizations/${orgId}`, { auto_enroll_domains: domains }).then(r => r.data),
    onSuccess: () => { toast.success('Domains updated'); qc.invalidateQueries({ queryKey: ['portal-org', orgId] }) },
    onError: () => toast.error('Failed to update domains'),
  })

  function addDomain() {
    const d = newDomain.trim().toLowerCase().replace(/^@/, '')
    if (!d) return
    if (settings.auto_enroll_domains.includes(d)) { toast.error('Domain already added'); return }
    updateMut.mutate([...settings.auto_enroll_domains, d])
    setNewDomain('')
  }

  function removeDomain(d: string) {
    updateMut.mutate(settings.auto_enroll_domains.filter(x => x !== d))
  }

  return (
    <div>
      <SectionHeader
        Icon={Settings}
        title="Domain Auto-Enrollment"
        description="Users signing up with email addresses matching these domains are automatically added to your organization — no invitation required."
      />

      {isLoading ? <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>Loading…</p> : (
        <>
          {/* Add domain */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <input style={{ ...inp, flex: 1 }}
              placeholder="acme.com"
              value={newDomain}
              onChange={e => setNewDomain(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') addDomain() }} />
            <button style={btn('primary')} onClick={addDomain} disabled={updateMut.isPending}>
              <Plus size={14} /> Add Domain
            </button>
          </div>

          {/* Domain list */}
          {settings.auto_enroll_domains.length === 0 ? (
            <div style={{ ...card, textAlign: 'center', padding: 32, color: 'var(--clavex-neutral)' }}>
              <Globe size={28} style={{ opacity: 0.3, marginBottom: 8 }} />
              <p style={{ fontSize: 13 }}>No domains configured. Add a domain to enable auto-enrollment.</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {settings.auto_enroll_domains.map(d => (
                <div key={d} style={{ ...card, display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ flex: 1, fontSize: 14, fontWeight: 600, fontFamily: 'monospace' }}>@{d}</span>
                  <CheckCircle2 size={14} color="#16a34a" />
                  <span style={{ fontSize: 11, color: '#16a34a' }}>Auto-enroll</span>
                  <button style={{ ...btn('ghost'), fontSize: 12, padding: '4px 10px', color: 'var(--clavex-danger)' }}
                    onClick={() => removeDomain(d)}>
                    <Trash2 size={13} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ── MFA tab ───────────────────────────────────────────────────────────────────

export function MFATab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()

  const { data: org, isLoading } = useQuery({
    queryKey: ['portal-org', orgId],
    queryFn: () => api.get(`/organizations/${orgId}`).then(r => r.data),
  })

  const mfaRequired: boolean = org?.mfa_required ?? false

  const toggleMut = useMutation({
    mutationFn: (required: boolean) =>
      api.patch(`/organizations/${orgId}`, { mfa_required: required }).then(r => r.data),
    onSuccess: (_, required) => {
      toast.success(`MFA ${required ? 'enforced' : 'optional'}`)
      qc.invalidateQueries({ queryKey: ['portal-org', orgId] })
    },
    onError: () => toast.error('Failed to update MFA policy'),
  })

  return (
    <div>
      <SectionHeader
        Icon={Shield}
        title="MFA Policy"
        description="Control whether multi-factor authentication is required for all users in your organization."
      />

      {isLoading ? <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>Loading…</p> : (
        <div style={card}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
            <div>
              <p style={{ fontSize: 14, fontWeight: 700, margin: '0 0 4px' }}>Require MFA for all users</p>
              <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', margin: 0 }}>
                When enabled, every user must enrol a second factor (TOTP, passkey, or SMS) before accessing the application.
                Meets PCI DSS 8.4, ISO 27001 A.9.4, and NIS2 Art.21 authentication requirements.
              </p>
            </div>
            <button
              style={{
                padding: '7px 18px', borderRadius: 8, fontSize: 13, fontWeight: 700,
                border: 'none', cursor: 'pointer',
                background: mfaRequired ? '#16a34a' : 'var(--clavex-border)',
                color: mfaRequired ? '#fff' : 'var(--clavex-neutral)',
                minWidth: 80,
              }}
              onClick={() => toggleMut.mutate(!mfaRequired)}
              disabled={toggleMut.isPending}
            >
              {mfaRequired ? 'Required ✓' : 'Optional'}
            </button>
          </div>

          {mfaRequired && (
            <div style={{ marginTop: 16, padding: '12px 16px', borderRadius: 8, background: '#16a34a12',
              border: '0.5px solid #16a34a30' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <CheckCircle2 size={14} color="#16a34a" />
                <span style={{ fontSize: 13, color: '#16a34a', fontWeight: 600 }}>
                  MFA is enforced — all users must complete second-factor enrolment.
                </span>
              </div>
            </div>
          )}

          {/* Docs link */}
          <div style={{ marginTop: 16, borderTop: '0.5px solid var(--clavex-border)', paddingTop: 12 }}>
            <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: 0 }}>
              Supported methods: TOTP authenticator apps, passkeys (FIDO2), and SMS OTP.
              Users can enrol from their profile settings page.{' '}
              <a href="/docs/mfa" target="_blank" rel="noopener noreferrer"
                style={{ color: 'var(--clavex-primary)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                Learn more <ExternalLink size={11} />
              </a>
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Route component exports ───────────────────────────────────────────────────
// Each tab is a routed child of /portal/:orgSlug — see App.tsx.

export function SSOPortalPage()     { const { orgId } = useAuthStore(); return <SSOTab orgId={orgId!} /> }
export function SCIMPortalPage()    { const { orgId } = useAuthStore(); return <SCIMTab orgId={orgId!} /> }
export function DomainsPortalPage() { const { orgId } = useAuthStore(); return <DomainsTab orgId={orgId!} /> }
export function MFAPortalPage()     { const { orgId } = useAuthStore(); return <MFATab orgId={orgId!} /> }
