import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Tag } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Badge, Button, Modal, Input, PageHeader, EmptyState, Spinner } from '@/components/ui'

interface ClientScope {
  id: string
  org_id: string
  name: string
  description?: string
  protocol: string
  is_default: boolean
  created_at: string
}

interface Props {
  orgId: string
}

export default function ClientScopesPage({ orgId }: Props) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newProtocol, setNewProtocol] = useState('openid-connect')
  const [newIsDefault, setNewIsDefault] = useState(false)

  const { data: scopes = [], isLoading } = useQuery<ClientScope[]>({
    queryKey: ['client-scopes', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/client-scopes`).then(r => r.data),
  })

  const createMut = useMutation({
    mutationFn: (body: object) =>
      api.post(`/organizations/${orgId}/client-scopes`, body).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['client-scopes', orgId] })
      setShowCreate(false)
      setNewName('')
      setNewDesc('')
      setNewIsDefault(false)
      toast.success('Scope created')
    },
    onError: () => toast.error('Failed to create scope'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/organizations/${orgId}/client-scopes/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['client-scopes', orgId] })
      toast.success('Scope deleted')
    },
    onError: () => toast.error('Failed to delete scope'),
  })

  const toggleDefault = useMutation({
    mutationFn: ({ scope }: { scope: ClientScope }) =>
      api.put(`/organizations/${orgId}/client-scopes/${scope.id}`, {
        name: scope.name,
        description: scope.description,
        is_default: !scope.is_default,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['client-scopes', orgId] }),
    onError: () => toast.error('Failed to update scope'),
  })

  return (
    <>
      <PageHeader
        title="Client Scopes"
        subtitle="Reusable OAuth2/OIDC scope definitions assignable to clients"
        action={<Button onClick={() => setShowCreate(true)}><Plus className="h-4 w-4" /> New Scope</Button>}
      />

      {isLoading ? (
        <Spinner />
      ) : scopes.length === 0 ? (
        <EmptyState
          icon={Tag}
          title="No client scopes"
          message="Create reusable scope definitions and assign them to individual OIDC clients."
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {scopes.map(scope => (
            <div
              key={scope.id}
              style={{
                background: 'white',
                border: '1px solid var(--clavex-border)',
                borderRadius: 10,
                padding: '14px 18px',
                display: 'flex',
                alignItems: 'center',
                gap: 12,
              }}
            >
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--clavex-ink)' }}>{scope.name}</span>
                  <Badge variant={scope.is_default ? 'green' : 'gray'}>
                    {scope.is_default ? 'default' : scope.protocol}
                  </Badge>
                </div>
                {scope.description && (
                  <p style={{ fontSize: 12, color: 'var(--clavex-muted)', marginTop: 3 }}>{scope.description}</p>
                )}
              </div>

              <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                <Button
                  size="xs"
                  variant="ghost"
                  onClick={() => toggleDefault.mutate({ scope })}
                  title={scope.is_default ? 'Remove from defaults' : 'Set as default'}
                >
                  {scope.is_default ? 'Unset default' : 'Set default'}
                </Button>
                <Button
                  size="xs"
                  variant="ghost"
                  onClick={() => {
                    if (confirm(`Delete scope "${scope.name}"?`)) deleteMut.mutate(scope.id)
                  }}
                >
                  <Trash2 size={13} />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal
        open={showCreate}
        title="New Client Scope"
        onClose={() => setShowCreate(false)}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Input
            label="Name"
            placeholder="e.g. profile, email, roles"
            value={newName}
            onChange={e => setNewName(e.target.value)}
            autoFocus
          />
          <Input
            label="Description (optional)"
            placeholder="What this scope grants access to"
            value={newDesc}
            onChange={e => setNewDesc(e.target.value)}
          />
          <div>
            <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6 }}>
              Protocol
            </label>
            <select
              value={newProtocol}
              onChange={e => setNewProtocol(e.target.value)}
              style={{
                width: '100%', padding: '8px 12px',
                border: '1.5px solid var(--clavex-border)', borderRadius: 8,
                fontSize: 13, color: 'var(--clavex-ink)', background: 'white',
              }}
            >
              <option value="openid-connect">OpenID Connect</option>
              <option value="saml">SAML</option>
            </select>
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={newIsDefault}
              onChange={e => setNewIsDefault(e.target.checked)}
              style={{ accentColor: 'var(--clavex-primary)', width: 15, height: 15 }}
            />
            <span style={{ fontSize: 13, color: 'var(--clavex-ink)' }}>Add to default scopes for new clients</span>
          </label>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 4 }}>
            <Button variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button
              onClick={() => createMut.mutate({ name: newName, description: newDesc || undefined, protocol: newProtocol, is_default: newIsDefault })}
              disabled={!newName.trim() || createMut.isPending}
            >
              Create
            </Button>
          </div>
        </div>
      </Modal>
    </>
  )
}
