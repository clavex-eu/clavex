import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Layers, Plus, Trash2, UserPlus } from 'lucide-react'

interface AppFamily {
  id: string
  name: string
  description?: string
  members: AppFamilyMember[]
  created_at: string
}

interface AppFamilyMember {
  client_id: string
  client_name: string
  added_at: string
}

const card: React.CSSProperties = {
  background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)',
  borderRadius: 12, padding: '20px 24px',
}

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '8px 12px', borderRadius: 8,
  border: '0.5px solid var(--clavex-border)', fontSize: 13,
  background: 'white', color: 'var(--clavex-text)', boxSizing: 'border-box',
}

const btnPrimary: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 6,
  padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 500,
  background: 'var(--clavex-primary)', color: 'white', border: 'none', cursor: 'pointer',
}

export default function AppFamiliesPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [memberClientId, setMemberClientId] = useState<Record<string, string>>({})

  const { data: families = [], isLoading } = useQuery<AppFamily[]>({
    queryKey: ['app-families', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/app-families`).then(r =>
      Array.isArray(r.data) ? r.data : (r.data?.items ?? [])),
    enabled: !!orgId,
  })

  const createMutation = useMutation({
    mutationFn: (body: { name: string; description?: string }) =>
      api.post(`/organizations/${orgId}/app-families`, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['app-families', orgId] }); toast.success('Family created'); setCreating(false); setForm({ name: '', description: '' }) },
    onError: () => toast.error('Failed to create'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/app-families/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['app-families', orgId] }); toast.success('Family deleted') },
    onError: () => toast.error('Failed to delete'),
  })

  const addMemberMutation = useMutation({
    mutationFn: ({ familyId, clientId }: { familyId: string; clientId: string }) =>
      api.post(`/organizations/${orgId}/app-families/${familyId}/members`, { client_id: clientId }),
    onSuccess: (_, { familyId }) => {
      qc.invalidateQueries({ queryKey: ['app-families', orgId] })
      toast.success('Member added')
      setMemberClientId(m => ({ ...m, [familyId]: '' }))
    },
    onError: () => toast.error('Failed to add member'),
  })

  const removeMemberMutation = useMutation({
    mutationFn: ({ familyId, clientId }: { familyId: string; clientId: string }) =>
      api.delete(`/organizations/${orgId}/app-families/${familyId}/members/${clientId}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['app-families', orgId] }); toast.success('Member removed') },
    onError: () => toast.error('Failed to remove member'),
  })

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Layers size={22} color="var(--clavex-primary)" />
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>App Families</h1>
            <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
              Group applications for shared SSO sessions and cross-app token binding
            </p>
          </div>
        </div>
        <button style={btnPrimary} onClick={() => setCreating(true)}>
          <Plus size={14} /> New family
        </button>
      </div>

      {creating && (
        <div style={{ ...card, marginBottom: 20 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 16px' }}>New app family</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Name *</label>
              <input style={inputStyle} value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="Microsoft 365 Suite" />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Description</label>
              <input style={inputStyle} value={form.description}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                placeholder="Optional description" />
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button style={{ padding: '7px 14px', borderRadius: 8, fontSize: 13, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: 'pointer' }}
                onClick={() => setCreating(false)}>Cancel</button>
              <button style={btnPrimary}
                onClick={() => createMutation.mutate({ name: form.name, description: form.description || undefined })}
                disabled={!form.name || createMutation.isPending}>
                {createMutation.isPending ? 'Creating…' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {isLoading ? (
        <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>
      ) : families.length === 0 && !creating ? (
        <div style={{ ...card, textAlign: 'center', padding: 40, color: 'var(--clavex-neutral)' }}>
          <Layers size={36} style={{ opacity: 0.3, marginBottom: 12 }} />
          <p style={{ fontSize: 14 }}>No app families yet</p>
          <p style={{ fontSize: 12 }}>Group your apps to share SSO sessions automatically.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {families.map(fam => {
            const expanded = expandedId === fam.id
            return (
              <div key={fam.id} style={card}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <Layers size={16} color="var(--clavex-primary)" style={{ flexShrink: 0 }} />
                  <div style={{ flex: 1, cursor: 'pointer' }} onClick={() => setExpandedId(expanded ? null : fam.id)}>
                    <div style={{ fontWeight: 600, fontSize: 15 }}>{fam.name}</div>
                    {fam.description && <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: '2px 0 0' }}>{fam.description}</p>}
                    <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: '2px 0 0' }}>
                      {fam.members.length} member{fam.members.length !== 1 ? 's' : ''}
                    </p>
                  </div>
                  <button style={{ padding: '6px 10px', borderRadius: 8, fontSize: 12, border: 'none', background: '#fee2e2', color: '#dc2626', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}
                    onClick={() => { if (confirm(`Delete "${fam.name}"?`)) deleteMutation.mutate(fam.id) }}>
                    <Trash2 size={12} /> Delete
                  </button>
                </div>

                {expanded && (
                  <div style={{ marginTop: 16, paddingTop: 16, borderTop: '0.5px solid var(--clavex-border)' }}>
                    <h3 style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '0.5px', margin: '0 0 10px' }}>Members</h3>
                    {fam.members.length === 0 ? (
                      <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>No members yet</p>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 12 }}>
                        {fam.members.map(m => (
                          <div key={m.client_id} style={{ display: 'flex', alignItems: 'center', gap: 10, background: '#f8fafc', padding: '8px 12px', borderRadius: 8 }}>
                            <div style={{ flex: 1 }}>
                              <div style={{ fontWeight: 500, fontSize: 13 }}>{m.client_name || m.client_id}</div>
                              <code style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>{m.client_id}</code>
                            </div>
                            <button style={{ padding: '4px 8px', borderRadius: 6, fontSize: 11, border: 'none', background: '#fee2e2', color: '#dc2626', cursor: 'pointer' }}
                              onClick={() => { if (confirm(`Remove "${m.client_id}"?`)) removeMemberMutation.mutate({ familyId: fam.id, clientId: m.client_id }) }}>
                              Remove
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                    <div style={{ display: 'flex', gap: 8 }}>
                      <input style={{ ...inputStyle, flex: 1 }}
                        value={memberClientId[fam.id] ?? ''}
                        onChange={e => setMemberClientId(m => ({ ...m, [fam.id]: e.target.value }))}
                        placeholder="Client ID to add…" />
                      <button style={{ ...btnPrimary, flexShrink: 0 }}
                        disabled={!memberClientId[fam.id]?.trim() || addMemberMutation.isPending}
                        onClick={() => addMemberMutation.mutate({ familyId: fam.id, clientId: memberClientId[fam.id] })}>
                        <UserPlus size={13} /> Add
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
