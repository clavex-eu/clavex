import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Globe2, Plus, Trash2, Pencil } from 'lucide-react'

interface WsFedRP {
  id: string
  name: string
  realm: string
  wreply_uris: string[]
  token_lifetime_seconds: number
  is_active: boolean
  created_at: string
}

type RPForm = {
  name: string
  realm: string
  wreply_uris: string
  token_lifetime_seconds: number
  is_active: boolean
}

const emptyForm = (): RPForm => ({
  name: '', realm: '', wreply_uris: '', token_lifetime_seconds: 3600, is_active: true,
})

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

function RPForm({ initial, onSave, onCancel, saving }: {
  initial: RPForm
  onSave: (f: RPForm) => void
  onCancel: () => void
  saving: boolean
}) {
  const [form, setForm] = useState(initial)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div>
          <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Display name *</label>
          <input style={inputStyle} value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="SharePoint Online" />
        </div>
        <div>
          <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Realm (wtrealm) *</label>
          <input style={inputStyle} value={form.realm}
            onChange={e => setForm(f => ({ ...f, realm: e.target.value }))}
            placeholder="urn:sharepoint:tenant" />
        </div>
        <div style={{ gridColumn: 'span 2' }}>
          <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Reply URLs (one per line) *</label>
          <textarea style={{ ...inputStyle, minHeight: 72, resize: 'vertical' }} value={form.wreply_uris}
            onChange={e => setForm(f => ({ ...f, wreply_uris: e.target.value }))}
            placeholder={'https://tenant.sharepoint.com/_trust/\nhttps://tenant.sharepoint.com/_trust/default.aspx'} />
        </div>
        <div>
          <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Token lifetime (seconds)</label>
          <input style={inputStyle} type="number" value={form.token_lifetime_seconds}
            onChange={e => setForm(f => ({ ...f, token_lifetime_seconds: parseInt(e.target.value) || 3600 }))} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 22 }}>
          <input type="checkbox" id="rp-active" checked={form.is_active}
            onChange={e => setForm(f => ({ ...f, is_active: e.target.checked }))} />
          <label htmlFor="rp-active" style={{ fontSize: 13 }}>Enabled</label>
        </div>
      </div>
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button style={{ padding: '7px 14px', borderRadius: 8, fontSize: 13, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: 'pointer' }}
          onClick={onCancel}>Cancel</button>
        <button style={btnPrimary} onClick={() => onSave(form)}
          disabled={!form.name || !form.realm || !form.wreply_uris.trim() || saving}>
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>
    </div>
  )
}

export default function WsFedRPsPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)

  const { data: rps = [], isLoading } = useQuery<WsFedRP[]>({
    queryKey: ['wsfed-rps', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/wsfed/relying-parties`).then(r =>
      Array.isArray(r.data) ? r.data : (r.data?.items ?? [])),
    enabled: !!orgId,
  })

  const formToBody = (f: RPForm) => ({
    name: f.name,
    realm: f.realm,
    wreply_uris: f.wreply_uris.split('\n').map(s => s.trim()).filter(Boolean),
    token_lifetime_seconds: f.token_lifetime_seconds,
    is_active: f.is_active,
  })

  const createMutation = useMutation({
    mutationFn: (f: RPForm) => api.post(`/organizations/${orgId}/wsfed/relying-parties`, formToBody(f)),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['wsfed-rps', orgId] }); toast.success('Relying party created'); setCreating(false) },
    onError: () => toast.error('Failed to create'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, f }: { id: string; f: RPForm }) =>
      api.put(`/organizations/${orgId}/wsfed/relying-parties/${id}`, formToBody(f)),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['wsfed-rps', orgId] }); toast.success('Saved'); setEditId(null) },
    onError: () => toast.error('Failed to save'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/wsfed/relying-parties/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['wsfed-rps', orgId] }); toast.success('Deleted') },
    onError: () => toast.error('Failed to delete'),
  })

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Globe2 size={22} color="var(--clavex-primary)" />
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>WS-Federation Relying Parties</h1>
            <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
              SharePoint, Microsoft Dynamics, and legacy WS-Fed applications
            </p>
          </div>
        </div>
        <button style={btnPrimary} onClick={() => setCreating(true)}>
          <Plus size={14} /> New relying party
        </button>
      </div>

      {/* Create form */}
      {creating && (
        <div style={{ ...card, marginBottom: 20 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 16px' }}>New relying party</h2>
          <RPForm initial={emptyForm()} onSave={f => createMutation.mutate(f)}
            onCancel={() => setCreating(false)} saving={createMutation.isPending} />
        </div>
      )}

      {isLoading ? (
        <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>
      ) : rps.length === 0 && !creating ? (
        <div style={{ ...card, textAlign: 'center', padding: 40, color: 'var(--clavex-neutral)' }}>
          <Globe2 size={36} style={{ opacity: 0.3, marginBottom: 12 }} />
          <p style={{ fontSize: 14 }}>No WS-Federation relying parties configured</p>
          <p style={{ fontSize: 12 }}>Use this for SharePoint, Dynamics, and other WS-Fed applications.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {rps.map(rp => (
            <div key={rp.id} style={card}>
              {editId === rp.id ? (
                <>
                  <h2 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 16px' }}>Edit {rp.name}</h2>
                  <RPForm
                    initial={{ name: rp.name, realm: rp.realm, wreply_uris: rp.wreply_uris.join('\n'), token_lifetime_seconds: rp.token_lifetime_seconds, is_active: rp.is_active }}
                    onSave={f => updateMutation.mutate({ id: rp.id, f })}
                    onCancel={() => setEditId(null)}
                    saving={updateMutation.isPending}
                  />
                </>
              ) : (
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      <span style={{ fontWeight: 600, fontSize: 15 }}>{rp.name}</span>
                      <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 12, background: rp.is_active ? '#dcfce7' : '#f1f5f9', color: rp.is_active ? '#15803d' : '#64748b' }}>
                        {rp.is_active ? 'active' : 'disabled'}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--clavex-neutral)', display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <div><strong>Realm:</strong> <code>{rp.realm}</code></div>
                      <div><strong>Token lifetime:</strong> {rp.token_lifetime_seconds}s</div>
                      <div><strong>Reply URLs:</strong></div>
                      {rp.wreply_uris.map(u => <code key={u} style={{ fontSize: 11 }}>{u}</code>)}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button style={{ padding: '6px 10px', borderRadius: 8, fontSize: 12, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, color: 'var(--clavex-text)' }}
                      onClick={() => setEditId(rp.id)}>
                      <Pencil size={12} /> Edit
                    </button>
                    <button style={{ padding: '6px 10px', borderRadius: 8, fontSize: 12, border: 'none', background: '#fee2e2', color: '#dc2626', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}
                      onClick={() => { if (confirm(`Delete "${rp.name}"?`)) deleteMutation.mutate(rp.id) }}>
                      <Trash2 size={12} /> Delete
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
