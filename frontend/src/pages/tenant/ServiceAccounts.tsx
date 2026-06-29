import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Bot, Plus, Trash2, Eye, EyeOff, Copy, RefreshCw } from 'lucide-react'

interface ServiceAccount {
  id: string
  name: string
  description?: string
  client_id: string
  scopes: string[]
  is_active: boolean
  created_at: string
  last_used_at?: string
}

interface CreateServiceAccountRequest {
  name: string
  description?: string
  scopes: string[]
}

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

const btnDanger: React.CSSProperties = {
  padding: '6px 12px', borderRadius: 8, fontSize: 12, border: 'none',
  background: '#fee2e2', color: '#dc2626', cursor: 'pointer',
}

export default function ServiceAccountsPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState<CreateServiceAccountRequest>({ name: '', scopes: [] })
  const [newSecret, setNewSecret] = useState<{ client_id: string; client_secret: string } | null>(null)
  const [showSecret, setShowSecret] = useState(false)

  const { data: accounts = [], isLoading } = useQuery<ServiceAccount[]>({
    queryKey: ['service-accounts', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/service-accounts`).then(r =>
      Array.isArray(r.data) ? r.data : (r.data?.items ?? [])),
    enabled: !!orgId,
  })

  const createMutation = useMutation({
    mutationFn: (body: CreateServiceAccountRequest) =>
      api.post(`/organizations/${orgId}/service-accounts`, body),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['service-accounts', orgId] })
      setNewSecret({ client_id: res.data.client_id, client_secret: res.data.client_secret })
      setCreating(false)
      setForm({ name: '', scopes: [] })
    },
    onError: () => toast.error('Failed to create service account'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/service-accounts/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['service-accounts', orgId] })
      toast.success('Service account deleted')
    },
    onError: () => toast.error('Failed to delete'),
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) =>
      api.post(`/organizations/${orgId}/service-accounts/${id}/rotate-secret`),
    onSuccess: (res) => {
      setNewSecret({ client_id: res.data.client_id, client_secret: res.data.client_secret })
      toast.success('Secret rotated — copy it now, it won\'t be shown again')
    },
    onError: () => toast.error('Failed to rotate secret'),
  })

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Bot size={22} color="var(--clavex-primary)" />
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Service Accounts</h1>
            <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
              Machine-to-machine credentials for CI/CD pipelines and backend services
            </p>
          </div>
        </div>
        <button style={btnPrimary} onClick={() => setCreating(true)}>
          <Plus size={14} /> New account
        </button>
      </div>

      {/* New secret banner */}
      {newSecret && (
        <div style={{ ...card, marginBottom: 20, background: '#f0fdf4', borderColor: '#16a34a' }}>
          <p style={{ fontWeight: 600, color: '#15803d', margin: '0 0 8px' }}>
            ✓ Service account ready — copy the secret now
          </p>
          <div style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
            <span style={{ fontSize: 12, color: 'var(--clavex-neutral)', minWidth: 90 }}>Client ID</span>
            <code style={{ fontSize: 12 }}>{newSecret.client_id}</code>
            <button style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer' }}
              onClick={() => { navigator.clipboard.writeText(newSecret.client_id); toast.success('Copied') }}>
              <Copy size={14} />
            </button>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 12, color: 'var(--clavex-neutral)', minWidth: 90 }}>Client Secret</span>
            <code style={{ fontSize: 12, flex: 1, wordBreak: 'break-all' }}>
              {showSecret ? newSecret.client_secret : '••••••••••••••••••••••••••••••'}
            </code>
            <button style={{ background: 'none', border: 'none', cursor: 'pointer' }}
              onClick={() => setShowSecret(s => !s)}>
              {showSecret ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
            <button style={{ background: 'none', border: 'none', cursor: 'pointer' }}
              onClick={() => { navigator.clipboard.writeText(newSecret.client_secret); toast.success('Copied') }}>
              <Copy size={14} />
            </button>
          </div>
          <button style={{ marginTop: 12, fontSize: 12, color: '#6b7280', background: 'none', border: 'none', cursor: 'pointer' }}
            onClick={() => setNewSecret(null)}>
            Dismiss
          </button>
        </div>
      )}

      {/* Create form */}
      {creating && (
        <div style={{ ...card, marginBottom: 20 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 16px' }}>New service account</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Name *</label>
              <input style={inputStyle} value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="e.g. ci-deploy-bot" />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Description</label>
              <input style={inputStyle} value={form.description ?? ''}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                placeholder="Optional description" />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Scopes (space-separated)</label>
              <input style={inputStyle} value={form.scopes.join(' ')}
                onChange={e => setForm(f => ({ ...f, scopes: e.target.value.split(' ').filter(Boolean) }))}
                placeholder="openid profile email" />
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button style={{ padding: '7px 14px', borderRadius: 8, fontSize: 13, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: 'pointer' }}
                onClick={() => setCreating(false)}>Cancel</button>
              <button style={btnPrimary} onClick={() => createMutation.mutate(form)}
                disabled={!form.name || createMutation.isPending}>
                {createMutation.isPending ? 'Creating…' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* List */}
      {isLoading ? (
        <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>
      ) : accounts.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', padding: 40, color: 'var(--clavex-neutral)' }}>
          <Bot size={36} style={{ opacity: 0.3, marginBottom: 12 }} />
          <p style={{ fontSize: 14 }}>No service accounts yet</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {accounts.map(sa => (
            <div key={sa.id} style={{ ...card, display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontWeight: 600, fontSize: 14 }}>{sa.name}</span>
                  <span style={{
                    fontSize: 11, padding: '2px 8px', borderRadius: 12,
                    background: sa.is_active ? '#dcfce7' : '#f1f5f9',
                    color: sa.is_active ? '#15803d' : '#64748b',
                  }}>{sa.is_active ? 'active' : 'disabled'}</span>
                </div>
                {sa.description && <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: '2px 0 0' }}>{sa.description}</p>}
                <code style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>{sa.client_id}</code>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button style={{ ...btnDanger, background: '#f0f9ff', color: '#0369a1', display: 'flex', alignItems: 'center', gap: 4 }}
                  onClick={() => rotateMutation.mutate(sa.id)} title="Rotate secret">
                  <RefreshCw size={12} /> Rotate
                </button>
                <button style={{ ...btnDanger, display: 'flex', alignItems: 'center', gap: 4 }}
                  onClick={() => { if (confirm(`Delete "${sa.name}"?`)) deleteMutation.mutate(sa.id) }}>
                  <Trash2 size={12} /> Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
