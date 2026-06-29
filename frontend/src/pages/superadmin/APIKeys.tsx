import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import { Plus, Trash2, Key, Copy } from 'lucide-react'
import { Badge, Button, Card, EmptyState, Input, Modal, PageHeader, Select, Spinner } from '@/components/ui'

const SCOPE_OPTIONS = [
  { value: 'read-only', label: 'Read-Only' },
  { value: 'read-write', label: 'Read-Write' },
  { value: 'provision-only', label: 'Provision-Only' },
]

interface APIKey {
  id: string
  name: string
  scope: string
  created_by?: string
  expires_at?: string
  created_at: string
  last_used_at?: string
  prefix?: string
}

interface CreateAPIKeyResponse {
  key: string
  meta: APIKey
}

export default function SuperadminAPIKeysPage() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [form, setForm] = useState({ name: '', scope: 'read-write', expires_at: '' })

  const keysQ = useQuery<APIKey[]>({
    queryKey: ['superadmin-api-keys'],
    queryFn: () => api.get('/superadmin/api-keys').then(r => toArr<APIKey>(r.data)),
  })

  const createM = useMutation({
    mutationFn: (body: { name: string; scope: string; expires_at?: string }) =>
      api.post<CreateAPIKeyResponse>('/superadmin/api-keys', body),
    onSuccess: (res: { data: CreateAPIKeyResponse }) => {
      toast.success("API key created — copy it now, it won't be shown again")
      setCreatedKey(res.data.key)
      qc.invalidateQueries({ queryKey: ['superadmin-api-keys'] })
      setShowCreate(false)
      setForm({ name: '', scope: 'read-write', expires_at: '' })
    },
    onError: () => toast.error('Failed to create API key'),
  })

  const revokeM = useMutation({
    mutationFn: (id: string) => api.delete(`/superadmin/api-keys/${id}`),
    onSuccess: () => {
      toast.success('API key revoked')
      qc.invalidateQueries({ queryKey: ['superadmin-api-keys'] })
    },
    onError: () => toast.error('Failed to revoke API key'),
  })

  const handleCreate = () => {
    const payload: { name: string; scope: string; expires_at?: string } = {
      name: form.name,
      scope: form.scope,
    }
    if (form.expires_at) payload.expires_at = new Date(form.expires_at).toISOString()
    createM.mutate(payload)
  }

  const keys = keysQ.data ?? []

  const scopeVariant = (scope: string): 'blue' | 'green' | 'yellow' | 'gray' => {
    const m: Record<string, 'blue' | 'green' | 'yellow'> = {
      'read-only': 'blue',
      'read-write': 'green',
      'provision-only': 'yellow',
    }
    return m[scope] ?? 'gray'
  }

  return (
    <div>
      <PageHeader
        title="API Keys"
        subtitle="Machine-to-machine keys for the Clavex management API. Keys are shown only once upon creation."
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" /> New API Key
          </Button>
        }
      />

      {/* Newly created key banner */}
      {createdKey && (
        <div style={{
          background: '#E1F5EE',
          border: '0.5px solid #0F6E56',
          borderRadius: 'var(--clavex-radius-lg)',
          padding: '16px 20px',
          marginBottom: 20,
          display: 'flex',
          alignItems: 'flex-start',
          gap: 16,
        }}>
          <div style={{ flex: 1 }}>
            <p style={{ fontWeight: 700, fontSize: 13, color: '#0F6E56', marginBottom: 8 }}>
              Copy your new API key — it won't be shown again
            </p>
            <code style={{
              display: 'block', padding: '8px 12px', borderRadius: 6,
              background: 'white', border: '0.5px solid var(--clavex-border)',
              fontSize: 13, wordBreak: 'break-all', fontFamily: 'monospace',
              color: 'var(--clavex-ink)',
            }}>
              {createdKey}
            </code>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <Button variant="secondary" size="sm"
              onClick={() => { navigator.clipboard.writeText(createdKey); toast.success('Copied!') }}>
              <Copy className="h-3.5 w-3.5" /> Copy
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setCreatedKey(null)}>Dismiss</Button>
          </div>
        </div>
      )}

      {/* Keys list */}
      {keysQ.isLoading ? (
        <Spinner />
      ) : keys.length === 0 ? (
        <Card>
          <EmptyState icon={Key} title="No API keys yet" message="Create your first API key to get started." />
        </Card>
      ) : (
        <div style={{ display: 'grid', gap: 8 }}>
          {keys.map(k => (
            <div key={k.id} style={{
              background: 'white',
              border: '0.5px solid var(--clavex-border)',
              borderRadius: 'var(--clavex-radius-lg)',
              padding: '16px 20px',
              display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16,
            }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--clavex-ink)' }}>{k.name}</span>
                  <Badge variant={scopeVariant(k.scope)}>{k.scope}</Badge>
                  {k.prefix && (
                    <code style={{ fontSize: 11, color: 'var(--clavex-neutral)', fontFamily: 'monospace' }}>
                      {k.prefix}…
                    </code>
                  )}
                </div>
                <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 12, color: 'var(--clavex-neutral)' }}>
                  {k.created_by && <span>Created by: {k.created_by}</span>}
                  <span>Created: {new Date(k.created_at).toLocaleDateString()}</span>
                  {k.last_used_at && <span>Last used: {new Date(k.last_used_at).toLocaleDateString()}</span>}
                  {k.expires_at && (
                    <span style={{ color: new Date(k.expires_at) < new Date() ? '#A32D2D' : 'var(--clavex-neutral)' }}>
                      Expires: {new Date(k.expires_at).toLocaleDateString()}
                    </span>
                  )}
                </div>
              </div>
              <Button
                variant="danger"
                size="sm"
                onClick={() => { if (confirm(`Revoke API key "${k.name}"?`)) revokeM.mutate(k.id) }}
              >
                <Trash2 className="h-3.5 w-3.5" /> Revoke
              </Button>
            </div>
          ))}
        </div>
      )}

      {/* Create modal */}
      <Modal
        open={showCreate}
        title="New API Key"
        description="API keys are shown only once upon creation."
        onClose={() => setShowCreate(false)}
      >
        <form onSubmit={e => { e.preventDefault(); handleCreate() }} className="space-y-4">
          <Input
            label="Name"
            placeholder="e.g. CI/CD pipeline, Terraform"
            value={form.name}
            required
            autoFocus
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
          />
          <Select
            label="Scope"
            value={form.scope}
            onChange={e => setForm(f => ({ ...f, scope: e.target.value }))}
          >
            {SCOPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </Select>
          <Input
            label="Expires at (optional)"
            type="datetime-local"
            value={form.expires_at}
            onChange={e => setForm(f => ({ ...f, expires_at: e.target.value }))}
          />
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="secondary" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button type="submit" loading={createM.isPending} disabled={!form.name}>Create</Button>
          </div>
        </form>
      </Modal>
    </div>
  )
}
