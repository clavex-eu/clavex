import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Pencil, Share2, X } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'

interface ScimPushConfig {
  id: string
  name: string
  endpoint_url: string
  enabled_events: string[]
  is_active: boolean
  created_at: string
}

const ALL_EVENTS = ['user.created', 'user.updated', 'user.deactivated']

interface Props { orgId: string }

export default function ScimPushPage({ orgId }: Props) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editItem, setEditItem] = useState<ScimPushConfig | null>(null)
  const [form, setForm] = useState({ name: '', endpoint_url: '', bearer_token: '', events: ALL_EVENTS })
  const [editForm, setEditForm] = useState({ name: '', endpoint_url: '', bearer_token: '', events: ALL_EVENTS, is_active: true })

  const { data: configs = [], isLoading } = useQuery<ScimPushConfig[]>({
    queryKey: ['scim-push', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/scim-push`).then(r => r.data),
  })

  const create = useMutation({
    mutationFn: (body: object) => api.post(`/organizations/${orgId}/scim-push`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scim-push', orgId] })
      toast.success('SCIM push target created')
      setShowCreate(false)
      setForm({ name: '', endpoint_url: '', bearer_token: '', events: ALL_EVENTS })
    },
    onError: () => toast.error('Failed to create SCIM push target'),
  })

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      api.patch(`/organizations/${orgId}/scim-push/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scim-push', orgId] })
      toast.success('Updated')
      setEditItem(null)
    },
    onError: () => toast.error('Failed to update'),
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/scim-push/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scim-push', orgId] }); toast.success('Deleted') },
    onError: () => toast.error('Failed to delete'),
  })

  const toggleEv = (list: string[], ev: string) =>
    list.includes(ev) ? list.filter(e => e !== ev) : [...list, ev]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">Sync</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Sync users outbound to external directories (AD, Google Workspace, Slack) via SCIM 2.0.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium text-white"
          style={{ background: 'var(--clavex-primary)' }}
        >
          <Plus className="h-4 w-4" /> Add target
        </button>
      </div>

      {/* Info banner */}
      <div className="mb-6 p-4 rounded-xl border border-blue-100 bg-blue-50 text-sm text-blue-800">
        <strong>How it works:</strong> When a user is created, updated, or deactivated in Clavex,
        a SCIM 2.0 PUT / PATCH request is automatically sent to each active target below.
        Uses <code className="text-xs bg-blue-100 px-1 rounded">Authorization: Bearer</code> authentication.
      </div>

      {isLoading ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : configs.length === 0 ? (
        <div className="text-center py-16 text-gray-400">
          <Share2 className="h-10 w-10 mx-auto mb-3 opacity-40" />
          <p className="text-sm">No SCIM push targets configured.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {configs.map(cfg => (
            <div key={cfg.id} className="flex items-center gap-4 bg-white rounded-xl border border-gray-200 px-5 py-4">
              <Share2 className="h-5 w-5 text-indigo-400 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-gray-900">{cfg.name}</p>
                <p className="text-xs text-gray-500 font-mono truncate mt-0.5">{cfg.endpoint_url}</p>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {cfg.enabled_events.map(ev => (
                    <span key={ev} className="text-xs rounded-full px-2 py-0.5 bg-indigo-50 text-indigo-700 font-mono">{ev}</span>
                  ))}
                </div>
              </div>
              <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${cfg.is_active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                {cfg.is_active ? 'Active' : 'Inactive'}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => { setEditItem(cfg); setEditForm({ name: cfg.name, endpoint_url: cfg.endpoint_url, bearer_token: '', events: cfg.enabled_events, is_active: cfg.is_active }) }}
                  className="text-gray-400 hover:text-gray-700"
                >
                  <Pencil className="h-4 w-4" />
                </button>
                <button
                  onClick={() => { if (confirm('Delete this SCIM push target?')) remove.mutate(cfg.id) }}
                  className="text-gray-400 hover:text-red-500"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-lg shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold">Add SCIM push target</h2>
              <button onClick={() => setShowCreate(false)} className="text-gray-400 hover:text-gray-700"><X className="h-4 w-4" /></button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Active Directory" value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">SCIM endpoint URL</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm font-mono" placeholder="https://dir.example.com/scim/v2" value={form.endpoint_url}
                  onChange={e => setForm(f => ({ ...f, endpoint_url: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Bearer token</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm font-mono" type="password" value={form.bearer_token}
                  onChange={e => setForm(f => ({ ...f, bearer_token: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-2">Events to sync</label>
                <div className="space-y-1.5">
                  {ALL_EVENTS.map(ev => (
                    <label key={ev} className="flex items-center gap-2 text-sm cursor-pointer">
                      <input type="checkbox" checked={form.events.includes(ev)}
                        onChange={() => setForm(f => ({ ...f, events: toggleEv(f.events, ev) }))} />
                      <span className="font-mono">{ev}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex gap-3 justify-end mt-5">
              <button onClick={() => setShowCreate(false)} className="px-4 py-1.5 rounded-lg text-sm border text-gray-600">Cancel</button>
              <button
                disabled={!form.name || !form.endpoint_url || !form.bearer_token || form.events.length === 0 || create.isPending}
                onClick={() => create.mutate({ name: form.name, endpoint_url: form.endpoint_url, bearer_token: form.bearer_token, enabled_events: form.events })}
                className="px-4 py-1.5 rounded-lg text-sm text-white disabled:opacity-50"
                style={{ background: 'var(--clavex-primary)' }}
              >
                {create.isPending ? 'Creating…' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit modal */}
      {editItem && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-lg shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold">Edit SCIM push target</h2>
              <button onClick={() => setEditItem(null)} className="text-gray-400 hover:text-gray-700"><X className="h-4 w-4" /></button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" value={editForm.name}
                  onChange={e => setEditForm(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">SCIM endpoint URL</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm font-mono" value={editForm.endpoint_url}
                  onChange={e => setEditForm(f => ({ ...f, endpoint_url: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Bearer token <span className="text-gray-400">(leave blank to keep)</span></label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm font-mono" type="password" value={editForm.bearer_token}
                  onChange={e => setEditForm(f => ({ ...f, bearer_token: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-2">Events</label>
                <div className="space-y-1.5">
                  {ALL_EVENTS.map(ev => (
                    <label key={ev} className="flex items-center gap-2 text-sm cursor-pointer">
                      <input type="checkbox" checked={editForm.events.includes(ev)}
                        onChange={() => setEditForm(f => ({ ...f, events: toggleEv(f.events, ev) }))} />
                      <span className="font-mono">{ev}</span>
                    </label>
                  ))}
                </div>
              </div>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input type="checkbox" checked={editForm.is_active}
                  onChange={e => setEditForm(f => ({ ...f, is_active: e.target.checked }))} />
                Active
              </label>
            </div>
            <div className="flex gap-3 justify-end mt-5">
              <button onClick={() => setEditItem(null)} className="px-4 py-1.5 rounded-lg text-sm border text-gray-600">Cancel</button>
              <button
                disabled={!editForm.name || !editForm.endpoint_url || editForm.events.length === 0 || update.isPending}
                onClick={() => update.mutate({ id: editItem.id, body: {
                  name: editForm.name, endpoint_url: editForm.endpoint_url,
                  ...(editForm.bearer_token ? { bearer_token: editForm.bearer_token } : {}),
                  enabled_events: editForm.events, is_active: editForm.is_active
                }})}
                className="px-4 py-1.5 rounded-lg text-sm text-white disabled:opacity-50"
                style={{ background: 'var(--clavex-primary)' }}
              >
                {update.isPending ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
