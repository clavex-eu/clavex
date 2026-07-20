import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import { KeyRound, Plus, Trash2, Copy } from 'lucide-react'

interface APIKey {
  id: string
  name: string
  scope: string
  permissions?: string[]
  key_prefix?: string
  created_by?: string
  expires_at?: string
  created_at: string
  last_used_at?: string
  is_active: boolean
}

interface PermissionInfo {
  token: string
  resource: string
  action: string
  description: string
}

interface CreateAPIKeyResponse {
  key: string
  meta: APIKey
}

const SCOPE_OPTIONS = [
  { value: 'read-only', label: 'Read-Only' },
  { value: 'read-write', label: 'Read-Write' },
  { value: 'provision-only', label: 'Provision-Only' },
]

const card: React.CSSProperties = {
  background: 'var(--clavex-surface)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '8px 12px',
  borderRadius: 8,
  border: '0.5px solid var(--clavex-border)',
  fontSize: 13,
  background: 'white',
  color: 'var(--clavex-text)',
  boxSizing: 'border-box',
}

const btnPrimary: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 6,
  padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 500,
  background: 'var(--clavex-primary)', color: 'white', border: 'none', cursor: 'pointer',
}

function formatDate(iso?: string) {
  return iso ? new Date(iso).toLocaleDateString() : '—'
}

export default function APIKeysPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [form, setForm] = useState<{ name: string; scope: string; expires_at: string; permissions: string[] }>({
    name: '', scope: 'read-write', expires_at: '', permissions: [],
  })

  const { data: keys = [], isLoading } = useQuery<APIKey[]>({
    queryKey: ['org-api-keys', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/api-keys`).then(r => toArr<APIKey>(r.data)),
    enabled: !!orgId,
  })

  // Tokens the current admin holds — the only permissions they may grant.
  const { data: heldTokens = [] } = useQuery<string[]>({
    queryKey: ['my-admin-permissions', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/my-admin-permissions`).then(r => toArr<string>(r.data)),
    enabled: !!orgId,
    staleTime: Infinity,
  })

  // Catalogue for human-readable labels/descriptions.
  const { data: catalogue = [] } = useQuery<PermissionInfo[]>({
    queryKey: ['admin-roles-permissions'],
    queryFn: () => api.get('/admin-roles/permissions').then(r => toArr<PermissionInfo>(r.data)),
    staleTime: Infinity,
  })

  // Only offer permissions the admin holds — anything else the server rejects.
  const grantable = useMemo(() => {
    const held = new Set(heldTokens)
    return catalogue.filter(p => held.has(p.token))
  }, [catalogue, heldTokens])

  const createM = useMutation({
    mutationFn: (body: { name: string; scope: string; permissions: string[]; expires_at?: string }) =>
      api.post<CreateAPIKeyResponse>(`/organizations/${orgId}/api-keys`, body),
    onSuccess: (res: { data: CreateAPIKeyResponse }) => {
      setCreatedKey(res.data.key)
      qc.invalidateQueries({ queryKey: ['org-api-keys', orgId] })
      setCreating(false)
      setForm({ name: '', scope: 'read-write', expires_at: '', permissions: [] })
      toast.success("API key created — copy it now, it won't be shown again")
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg || 'Failed to create API key')
    },
  })

  const revokeM = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/api-keys/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['org-api-keys', orgId] })
      toast.success('API key revoked')
    },
    onError: () => toast.error('Failed to revoke API key'),
  })

  function togglePerm(token: string) {
    setForm(f => ({
      ...f,
      permissions: f.permissions.includes(token)
        ? f.permissions.filter(p => p !== token)
        : [...f.permissions, token],
    }))
  }

  function handleCreate() {
    const body: { name: string; scope: string; permissions: string[]; expires_at?: string } = {
      name: form.name.trim(),
      scope: form.scope,
      permissions: form.permissions,
    }
    if (form.expires_at) body.expires_at = new Date(form.expires_at).toISOString()
    createM.mutate(body)
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <KeyRound size={22} color="var(--clavex-primary)" />
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>API Keys</h1>
            <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
              Org-scoped machine keys for the Admin API (e.g. the Kubernetes operator, CI/CD).
              A key can only carry permissions you hold. Shown once at creation.
            </p>
          </div>
        </div>
        <button style={btnPrimary} onClick={() => setCreating(true)}>
          <Plus size={14} /> New API key
        </button>
      </div>

      {/* Newly created key banner */}
      {createdKey && (
        <div style={{
          background: '#E1F5EE', border: '0.5px solid #0F6E56', borderRadius: 12,
          padding: '16px 20px', marginBottom: 20, display: 'flex', alignItems: 'flex-start', gap: 16,
        }}>
          <div style={{ flex: 1 }}>
            <p style={{ fontWeight: 700, fontSize: 13, color: '#0F6E56', marginBottom: 8 }}>
              Copy your new API key — it won't be shown again
            </p>
            <code style={{
              display: 'block', padding: '8px 12px', borderRadius: 6, background: 'white',
              border: '0.5px solid var(--clavex-border)', fontSize: 13, wordBreak: 'break-all',
              fontFamily: 'monospace', color: 'var(--clavex-ink)',
            }}>{createdKey}</code>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button style={{ ...btnPrimary, background: 'white', color: 'var(--clavex-text)', border: '0.5px solid var(--clavex-border)' }}
              onClick={() => { navigator.clipboard.writeText(createdKey); toast.success('Copied!') }}>
              <Copy size={14} /> Copy
            </button>
            <button style={{ padding: '8px 12px', borderRadius: 8, fontSize: 13, border: 'none', background: 'transparent', cursor: 'pointer', color: 'var(--clavex-neutral)' }}
              onClick={() => setCreatedKey(null)}>Dismiss</button>
          </div>
        </div>
      )}

      {/* Create form */}
      {creating && (
        <div style={{ ...card, marginBottom: 20 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 16px' }}>Create API key</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Name *</label>
              <input style={inputStyle} value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="e.g. clavex-operator, CI/CD" />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Scope</label>
              <select style={inputStyle} value={form.scope}
                onChange={e => setForm(f => ({ ...f, scope: e.target.value }))}>
                {SCOPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            <div style={{ gridColumn: 'span 2' }}>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Expires at <span style={{ fontWeight: 400, color: 'var(--clavex-neutral)' }}>(optional)</span></label>
              <input style={inputStyle} type="datetime-local" value={form.expires_at}
                onChange={e => setForm(f => ({ ...f, expires_at: e.target.value }))} />
            </div>
          </div>

          <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 8 }}>
            Permissions * <span style={{ fontWeight: 400, color: 'var(--clavex-neutral)' }}>(only permissions you hold are listed)</span>
          </label>
          {grantable.length === 0 ? (
            <p style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>
              You hold no delegatable permissions, so you cannot mint a key.
            </p>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, maxHeight: 260, overflowY: 'auto', paddingRight: 4 }}>
              {grantable.map(p => (
                <label key={p.token} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12, cursor: 'pointer' }}>
                  <input type="checkbox" checked={form.permissions.includes(p.token)}
                    onChange={() => togglePerm(p.token)} style={{ marginTop: 2 }} />
                  <span>
                    <code style={{ fontSize: 12, color: 'var(--clavex-primary)', fontWeight: 600 }}>{p.token}</code>
                    <span style={{ display: 'block', fontSize: 11, color: 'var(--clavex-neutral)' }}>{p.description}</span>
                  </span>
                </label>
              ))}
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
            <button style={{ padding: '7px 14px', borderRadius: 8, fontSize: 13, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: 'pointer' }}
              onClick={() => setCreating(false)}>Cancel</button>
            <button style={btnPrimary} onClick={handleCreate}
              disabled={!form.name.trim() || form.permissions.length === 0 || createM.isPending}>
              {createM.isPending ? 'Creating…' : 'Create key'}
            </button>
          </div>
        </div>
      )}

      {/* Key list */}
      {isLoading ? (
        <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>
      ) : keys.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', padding: 40, color: 'var(--clavex-neutral)' }}>
          <KeyRound size={36} style={{ opacity: 0.3, marginBottom: 12 }} />
          <p style={{ fontSize: 14 }}>No API keys yet</p>
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 8 }}>
          {keys.map(k => {
            const revoked = !k.is_active
            const expired = k.expires_at ? new Date(k.expires_at) < new Date() : false
            return (
              <div key={k.id} style={{ ...card, display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                    <span style={{ fontWeight: 600, fontSize: 14 }}>{k.name}</span>
                    <span style={{ fontSize: 11, padding: '1px 8px', borderRadius: 12, background: '#e0f2fe', color: '#075985' }}>{k.scope}</span>
                    {k.key_prefix && <code style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>{k.key_prefix}…</code>}
                    {revoked && <span style={{ fontSize: 11, padding: '1px 8px', borderRadius: 12, background: '#fee2e2', color: '#dc2626' }}>revoked</span>}
                    {!revoked && expired && <span style={{ fontSize: 11, padding: '1px 8px', borderRadius: 12, background: '#fef9c3', color: '#854d0e' }}>expired</span>}
                  </div>
                  {k.permissions && k.permissions.length > 0 && (
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
                      {k.permissions.map(p => (
                        <code key={p} style={{ fontSize: 10, padding: '1px 6px', borderRadius: 6, background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)' }}>{p}</code>
                      ))}
                    </div>
                  )}
                  <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 12, color: 'var(--clavex-neutral)' }}>
                    <span>Created: {formatDate(k.created_at)}</span>
                    {k.last_used_at && <span>Last used: {formatDate(k.last_used_at)}</span>}
                    {k.expires_at && <span>Expires: {formatDate(k.expires_at)}</span>}
                  </div>
                </div>
                {!revoked && (
                  <button style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 8, fontSize: 12, border: '0.5px solid #fecaca', background: 'white', color: '#dc2626', cursor: 'pointer' }}
                    onClick={() => { if (confirm(`Revoke API key "${k.name}"?`)) revokeM.mutate(k.id) }}>
                    <Trash2 size={13} /> Revoke
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
