import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { toArr } from '@/lib/api'
import { useAuthStore } from '@/stores/auth'
import toast from 'react-hot-toast'
import { Plus, Trash2, ArrowRightLeft, Shield } from 'lucide-react'

const card = {
  background: 'var(--clavex-surface-card)',
  border: '0.5px solid rgba(93,202,165,0.2)',
  boxShadow: '0 1px 4px rgba(0,0,0,0.06)',
  borderRadius: 12,
  padding: '24px',
}
const inp = {
  width: '100%',
  background: 'var(--clavex-surface)',
  border: '0.5px solid rgba(93,202,165,0.2)',
  borderRadius: 8,
  padding: '8px 12px',
  color: 'var(--clavex-text)',
  fontSize: 14,
  outline: 'none',
}
const lbl = { fontSize: 12, fontWeight: 600, color: 'var(--clavex-400)', marginBottom: 4 }
const btn = (variant: 'primary' | 'danger' | 'ghost' = 'primary') => ({
  display: 'inline-flex', alignItems: 'center', gap: 6,
  padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600,
  cursor: 'pointer', border: 'none', transition: 'opacity 0.15s',
  ...(variant === 'primary' ? {
    background: 'var(--clavex-primary)', color: '#0f1923',
  } : variant === 'danger' ? {
    background: 'rgba(239,68,68,0.12)', color: '#f87171',
    border: '0.5px solid rgba(239,68,68,0.3)',
  } : {
    background: 'transparent', color: 'var(--clavex-400)',
    border: '0.5px solid rgba(93,202,165,0.2)',
  }),
})

interface Trust {
  id: string
  org_id: string
  trusted_org_slug?: string
  trusted_org_id?: string
  source_org_slug?: string
  source_org_id?: string
  allowed_scopes?: string[]
  allowed_client_ids?: string[]
  max_token_ttl?: number
  require_mfa?: boolean
  created_by?: string
  created_at: string
}

function TagInput({ value, onChange, placeholder }: {
  value: string[]; onChange: (v: string[]) => void; placeholder?: string
}) {
  const [draft, setDraft] = useState('')

  const add = () => {
    const t = draft.trim()
    if (t && !value.includes(t)) onChange([...value, t])
    setDraft('')
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
        {value.map(v => (
          <span key={v} style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            padding: '2px 8px', borderRadius: 20,
            background: 'rgba(93,202,165,0.12)', color: 'var(--clavex-primary)',
            fontSize: 12,
          }}>
            {v}
            <button onClick={() => onChange(value.filter(x => x !== v))}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: 0 }}>×</button>
          </span>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 6 }}>
        <input
          style={{ ...inp, flex: 1 }}
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), add())}
          placeholder={placeholder}
        />
        <button onClick={add} style={btn('ghost')}>Add</button>
      </div>
    </div>
  )
}

export default function CrossOrgTrustPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [tab, setTab] = useState<'outbound' | 'inbound'>('outbound')
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({
    target_org_slug: '',
    allowed_scopes: [] as string[],
    allowed_client_ids: [] as string[],
    max_token_ttl: '' as string,
    require_mfa: false,
  })

  const base = `/organizations/${orgId}/cross-org-trusts`

  const outboundQ = useQuery<Trust[]>({
    queryKey: ['cross-org-trusts', orgId],
    queryFn: () => api.get(base).then(r => toArr<Trust>(r.data)),
    enabled: !!orgId,
  })

  const inboundQ = useQuery<Trust[]>({
    queryKey: ['cross-org-trusts-inbound', orgId],
    queryFn: () => api.get(`${base}/inbound`).then(r => toArr<Trust>(r.data)),
    enabled: !!orgId,
  })

  const createM = useMutation({
    mutationFn: (body: typeof form) => api.post(base, {
      ...body,
      max_token_ttl: body.max_token_ttl ? parseInt(body.max_token_ttl, 10) : undefined,
    }),
    onSuccess: () => {
      toast.success('Trust created')
      qc.invalidateQueries({ queryKey: ['cross-org-trusts', orgId] })
      setShowCreate(false)
      setForm({ target_org_slug: '', allowed_scopes: [], allowed_client_ids: [], max_token_ttl: '', require_mfa: false })
    },
    onError: () => toast.error('Failed to create trust'),
  })

  const revokeM = useMutation({
    mutationFn: (id: string) => api.delete(`${base}/${id}`),
    onSuccess: () => {
      toast.success('Trust revoked')
      qc.invalidateQueries({ queryKey: ['cross-org-trusts', orgId] })
    },
    onError: () => toast.error('Failed to revoke trust'),
  })

  const outboundTrusts = outboundQ.data ?? []
  const inboundTrusts = inboundQ.data ?? []

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <ArrowRightLeft style={{ color: 'var(--clavex-primary)' }} className="h-5 w-5" />
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--clavex-text)' }}>Cross-Org Trust</h1>
        </div>
        <p style={{ fontSize: 14, color: 'var(--clavex-400)' }}>
          Allow users from other organizations to authenticate in this org (outbound trusts), or see which orgs trust yours (inbound).
        </p>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, borderBottom: '0.5px solid rgba(93,202,165,0.1)' }}>
        {(['outbound', 'inbound'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: '8px 18px', fontSize: 13, fontWeight: 600,
            background: 'none', border: 'none', cursor: 'pointer',
            color: tab === t ? 'var(--clavex-primary)' : 'var(--clavex-400)',
            borderBottom: tab === t ? '2px solid var(--clavex-primary)' : '2px solid transparent',
            marginBottom: -1,
          }}>
            {t === 'outbound' ? 'Outbound Trusts' : 'Inbound Trusts'}
          </button>
        ))}
      </div>

      {tab === 'outbound' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
            <button onClick={() => setShowCreate(v => !v)} style={btn()}>
              <Plus className="h-4 w-4" />
              New Trust
            </button>
          </div>

          {/* Create form */}
          {showCreate && (
            <div style={{ ...card, marginBottom: 20 }}>
              <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--clavex-text)', marginBottom: 16 }}>Create Outbound Trust</h3>
              <div style={{ display: 'grid', gap: 14 }}>
                <div>
                  <p style={lbl}>Target Organization Slug *</p>
                  <input style={inp} placeholder="e.g. acme-corp"
                    value={form.target_org_slug}
                    onChange={e => setForm(f => ({ ...f, target_org_slug: e.target.value }))} />
                </div>
                <div>
                  <p style={lbl}>Allowed Scopes (optional — leave empty to allow all)</p>
                  <TagInput value={form.allowed_scopes} onChange={v => setForm(f => ({ ...f, allowed_scopes: v }))} placeholder="openid, profile, email…" />
                </div>
                <div>
                  <p style={lbl}>Allowed Client IDs (optional — leave empty to allow all)</p>
                  <TagInput value={form.allowed_client_ids} onChange={v => setForm(f => ({ ...f, allowed_client_ids: v }))} placeholder="client UUID…" />
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div>
                    <p style={lbl}>Max Token TTL (seconds, optional)</p>
                    <input style={inp} type="number" min="60" max="86400" placeholder="e.g. 3600"
                      value={form.max_token_ttl}
                      onChange={e => setForm(f => ({ ...f, max_token_ttl: e.target.value }))} />
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 22 }}>
                    <input type="checkbox" id="require_mfa" checked={form.require_mfa}
                      onChange={e => setForm(f => ({ ...f, require_mfa: e.target.checked }))}
                      style={{ accentColor: 'var(--clavex-primary)', width: 16, height: 16 }} />
                    <label htmlFor="require_mfa" style={{ fontSize: 13, color: 'var(--clavex-text)', cursor: 'pointer' }}>
                      Require MFA on subject token
                    </label>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                  <button onClick={() => createM.mutate(form)} disabled={!form.target_org_slug || createM.isPending} style={btn()}>
                    {createM.isPending ? 'Creating…' : 'Create Trust'}
                  </button>
                  <button onClick={() => setShowCreate(false)} style={btn('ghost')}>Cancel</button>
                </div>
              </div>
            </div>
          )}

          {/* Outbound list */}
          {outboundQ.isLoading ? (
            <p style={{ color: 'var(--clavex-400)', fontSize: 14 }}>Loading…</p>
          ) : outboundTrusts.length === 0 ? (
            <div style={{ ...card, textAlign: 'center', padding: '40px' }}>
              <Shield className="h-8 w-8 mx-auto mb-3" style={{ color: 'rgba(93,202,165,0.3)' }} />
              <p style={{ color: 'var(--clavex-400)', fontSize: 14 }}>No outbound trusts configured</p>
            </div>
          ) : (
            <div style={{ display: 'grid', gap: 10 }}>
              {outboundTrusts.map(t => (
                <div key={t.id} style={{ ...card, display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                      <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--clavex-text)' }}>
                        {t.trusted_org_slug ?? t.trusted_org_id}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 12, color: 'var(--clavex-400)' }}>
                      {t.allowed_scopes && t.allowed_scopes.length > 0 ? (
                        <span>Scopes: {t.allowed_scopes.join(', ')}</span>
                      ) : <span>All scopes</span>}
                      {t.allowed_client_ids && t.allowed_client_ids.length > 0 ? (
                        <span>Clients: {t.allowed_client_ids.join(', ')}</span>
                      ) : <span>All clients</span>}
                      {t.max_token_ttl != null && <span>Max TTL: {t.max_token_ttl}s</span>}
                      {t.require_mfa && <span style={{ color: 'var(--clavex-primary)' }}>MFA required</span>}
                      {t.created_by && <span>By: {t.created_by}</span>}
                      <span>Created: {new Date(t.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <button
                    onClick={() => { if (confirm('Revoke this trust?')) revokeM.mutate(t.id) }}
                    style={btn('danger')}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Revoke
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {tab === 'inbound' && (
        <div>
          <p style={{ fontSize: 13, color: 'var(--clavex-400)', marginBottom: 16 }}>
            These organizations have granted trust to your org. Inbound trusts are read-only.
          </p>
          {inboundQ.isLoading ? (
            <p style={{ color: 'var(--clavex-400)', fontSize: 14 }}>Loading…</p>
          ) : inboundTrusts.length === 0 ? (
            <div style={{ ...card, textAlign: 'center', padding: '40px' }}>
              <Shield className="h-8 w-8 mx-auto mb-3" style={{ color: 'rgba(93,202,165,0.3)' }} />
              <p style={{ color: 'var(--clavex-400)', fontSize: 14 }}>No inbound trusts from other organizations</p>
            </div>
          ) : (
            <div style={{ display: 'grid', gap: 10 }}>
              {inboundTrusts.map(t => (
                <div key={t.id} style={{ ...card }}>
                  <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--clavex-text)', marginBottom: 6 }}>
                    {t.source_org_slug ?? t.source_org_id ?? t.org_id}
                  </div>
                  <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 12, color: 'var(--clavex-400)' }}>
                    {t.allowed_scopes && t.allowed_scopes.length > 0 ? (
                      <span>Scopes: {t.allowed_scopes.join(', ')}</span>
                    ) : <span>All scopes</span>}
                    {t.allowed_client_ids && t.allowed_client_ids.length > 0 ? (
                      <span>Clients: {t.allowed_client_ids.join(', ')}</span>
                    ) : <span>All clients</span>}
                    <span>Created: {new Date(t.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
