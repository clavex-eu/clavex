import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import { Plus, Trash2, Pencil, Webhook, Copy, Check, History, RefreshCw, X } from 'lucide-react'
import { ManagedBadge } from '@/components/ui'

interface WebhookEntry {
  id: string
  url: string
  events: string[]
  is_active: boolean
  created_at: string
  managed_by?: string | null
  managed_ref?: string | null
}

interface CreatedWebhook extends WebhookEntry {
  secret: string
}

interface Delivery {
  id: string
  webhook_id: string
  delivery_id: string
  event: string
  payload: Record<string, unknown>
  attempt: number
  status: 'pending' | 'success' | 'failed'
  http_status: number | null
  error: string | null
  duration_ms: number | null
  attempted_at: string
}

const ALL_EVENTS = ['user.created', 'user.updated', 'user.deleted']

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button onClick={copy} className="ml-2 text-gray-400 hover:text-gray-700">
      {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  )
}

function StatusBadge({ status }: { status: Delivery['status'] }) {
  const map = {
    success: 'bg-green-100 text-green-700',
    failed:  'bg-red-100 text-red-700',
    pending: 'bg-amber-100 text-amber-700',
  }
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${map[status]}`}>
      {status}
    </span>
  )
}

function HttpBadge({ code }: { code: number | null }) {
  if (!code) return <span className="text-xs text-gray-400">—</span>
  const ok = code >= 200 && code < 300
  return (
    <span className={`text-xs font-mono font-semibold ${ok ? 'text-green-700' : 'text-red-700'}`}>
      {code}
    </span>
  )
}

// ── Delivery drawer ──────────────────────────────────────────────────────────

interface DeliveryDrawerProps {
  orgId: string
  webhook: WebhookEntry
  onClose: () => void
}

function DeliveryDrawer({ orgId, webhook, onClose }: DeliveryDrawerProps) {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<Delivery | null>(null)

  const { data: deliveries = [], isLoading, refetch } = useQuery<Delivery[]>({
    queryKey: ['deliveries', orgId, webhook.id],
    queryFn: () => api.get(`/organizations/${orgId}/webhooks/${webhook.id}/deliveries`).then(r => r.data),
    refetchInterval: 10_000, // live-refresh every 10s
  })

  const retry = useMutation({
    mutationFn: (deliveryId: string) =>
      api.post(`/organizations/${orgId}/webhooks/${webhook.id}/deliveries/${deliveryId}/retry`),
    onSuccess: () => {
      toast.success('Retry queued')
      setTimeout(() => { qc.invalidateQueries({ queryKey: ['deliveries', orgId, webhook.id] }) }, 1500)
    },
    onError: () => toast.error('Retry failed'),
  })

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div className="flex-1 bg-black/40" onClick={onClose} />

      {/* Drawer panel */}
      <div className="w-full max-w-2xl bg-white flex flex-col h-full shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-gray-900">Delivery history</h2>
            <p className="text-xs text-gray-500 truncate mt-0.5">{webhook.url}</p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <button
              onClick={() => refetch()}
              className="p-1.5 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100"
              title="Refresh"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
            <button onClick={onClose} className="p-1.5 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Body: split left list + right detail */}
        <div className="flex flex-1 overflow-hidden">
          {/* Delivery list */}
          <div className="w-56 border-r flex-shrink-0 overflow-y-auto">
            {isLoading ? (
              <p className="text-xs text-gray-400 p-4">Caricamento…</p>
            ) : deliveries.length === 0 ? (
              <p className="text-xs text-gray-400 p-4">Nessuna consegna ancora.</p>
            ) : (
              deliveries.map(d => (
                <button
                  key={d.id}
                  onClick={() => setSelected(d)}
                  className={`w-full text-left px-4 py-3 border-b text-xs hover:bg-gray-50 transition-colors ${selected?.id === d.id ? 'bg-indigo-50 border-l-2 border-l-indigo-500' : ''}`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <StatusBadge status={d.status} />
                    <HttpBadge code={d.http_status} />
                  </div>
                  <p className="font-mono text-gray-600 truncate">{d.event}</p>
                  <p className="text-gray-400 mt-0.5">{new Date(d.attempted_at).toLocaleString()}</p>
                  {d.attempt > 1 && (
                    <p className="text-amber-600 mt-0.5">attempt {d.attempt}</p>
                  )}
                </button>
              ))
            )}
          </div>

          {/* Detail panel */}
          <div className="flex-1 overflow-y-auto">
            {!selected ? (
              <div className="flex flex-col items-center justify-center h-full text-gray-400">
                <History className="h-8 w-8 mb-2 opacity-40" />
                <p className="text-sm">Seleziona una consegna</p>
              </div>
            ) : (
              <div className="p-5">
                {/* Summary row */}
                <div className="flex items-center gap-3 mb-4">
                  <StatusBadge status={selected.status} />
                  <HttpBadge code={selected.http_status} />
                  <span className="text-xs text-gray-500">attempt {selected.attempt}</span>
                  {selected.duration_ms != null && (
                    <span className="text-xs text-gray-500">{selected.duration_ms} ms</span>
                  )}
                  <div className="flex-1" />
                  <button
                    onClick={() => retry.mutate(selected.id)}
                    disabled={retry.isPending}
                    className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg font-medium text-white disabled:opacity-50"
                    style={{ background: 'var(--clavex-primary)' }}
                    title="Resend this delivery"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    {retry.isPending ? 'Queuing…' : 'Retry'}
                  </button>
                </div>

                {/* Error */}
                {selected.error && (
                  <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                    <p className="text-xs font-semibold text-red-700 mb-1">Error</p>
                    <p className="text-xs font-mono text-red-600">{selected.error}</p>
                  </div>
                )}

                {/* Metadata */}
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs mb-4">
                  <span className="text-gray-500">Delivery ID</span>
                  <span className="font-mono text-gray-700 truncate">{selected.delivery_id}</span>
                  <span className="text-gray-500">Event</span>
                  <span className="font-mono text-gray-700">{selected.event}</span>
                  <span className="text-gray-500">Attempted at</span>
                  <span className="text-gray-700">{new Date(selected.attempted_at).toLocaleString()}</span>
                </div>

                {/* Payload */}
                <p className="text-xs font-semibold text-gray-600 mb-1">Payload</p>
                <pre className="text-xs bg-gray-50 border rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-all">
                  {JSON.stringify(selected.payload, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

interface Props { orgId: string }

export default function WebhooksPage({ orgId }: Props) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editItem, setEditItem] = useState<WebhookEntry | null>(null)
  const [deliveriesFor, setDeliveriesFor] = useState<WebhookEntry | null>(null)
  const [newSecret, setNewSecret] = useState<string | null>(null)
  const [form, setForm] = useState({ url: '', events: [] as string[] })
  const [editForm, setEditForm] = useState({ url: '', events: [] as string[], is_active: true })

  const { data: webhooks = [], isLoading } = useQuery<WebhookEntry[]>({
    queryKey: ['webhooks', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/webhooks`).then(r => toArr(r.data)),
    enabled: !!orgId,
  })

  const create = useMutation({
    mutationFn: (body: { url: string; events: string[] }) =>
      api.post<CreatedWebhook>(`/organizations/${orgId}/webhooks`, body).then(r => r.data),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['webhooks', orgId] })
      setNewSecret(data.secret)
      setShowCreate(false)
      setForm({ url: '', events: [] })
    },
    onError: () => toast.error('Failed to create webhook'),
  })

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: { url: string; events: string[]; is_active: boolean } }) =>
      api.patch(`/organizations/${orgId}/webhooks/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['webhooks', orgId] })
      toast.success('Webhook updated')
      setEditItem(null)
    },
    onError: () => toast.error('Failed to update webhook'),
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/webhooks/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['webhooks', orgId] }); toast.success('Webhook deleted') },
    onError: () => toast.error('Failed to delete webhook'),
  })

  const toggleEvent = (list: string[], ev: string) =>
    list.includes(ev) ? list.filter(e => e !== ev) : [...list, ev]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">Stream</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Ricevi notifiche HTTP firmati con HMAC-SHA256 per eventi utente.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium text-white"
          style={{ background: 'var(--clavex-primary)' }}
        >
          <Plus className="h-4 w-4" /> Nuovo webhook
        </button>
      </div>

      {/* Secret reveal banner */}
      {newSecret && (
        <div className="mb-6 p-4 rounded-xl border border-amber-200 bg-amber-50">
          <p className="text-sm font-semibold text-amber-800 mb-1">⚠️ Salva subito il signing secret — non verrà più mostrato.</p>
          <div className="flex items-center font-mono text-xs text-amber-900 bg-amber-100 rounded px-3 py-2 mt-1">
            <span className="flex-1 truncate">{newSecret}</span>
            <CopyButton text={newSecret} />
          </div>
          <p className="text-xs text-amber-700 mt-2">
            Usa questo secret per verificare l'header <code>X-Clavex-Signature</code> dei payload in arrivo.
          </p>
          <button
            onClick={() => setNewSecret(null)}
            className="mt-3 text-xs text-amber-700 underline"
          >
            Ho salvato il secret
          </button>
        </div>
      )}

      {/* List */}
      {isLoading ? (
        <p className="text-sm text-gray-500">Caricamento…</p>
      ) : webhooks.length === 0 ? (
        <div className="text-center py-16 text-gray-400">
          <Webhook className="h-10 w-10 mx-auto mb-3 opacity-40" />
          <p className="text-sm">Nessun webhook configurato.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {webhooks.map(wh => (
            <div key={wh.id} className="flex items-center gap-4 bg-white rounded-xl border border-gray-200 px-5 py-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <p className="text-sm font-medium text-gray-900 truncate">{wh.url}</p>
                  <ManagedBadge managedBy={wh.managed_by} managedRef={wh.managed_ref} />
                </div>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {wh.events.map(ev => (
                    <span key={ev} className="text-xs rounded-full px-2 py-0.5 bg-indigo-50 text-indigo-700 font-mono">{ev}</span>
                  ))}
                </div>
              </div>
              <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${wh.is_active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                {wh.is_active ? 'Attivo' : 'Disattivo'}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setDeliveriesFor(wh)}
                  className="text-gray-400 hover:text-indigo-600"
                  title="Delivery history"
                >
                  <History className="h-4 w-4" />
                </button>
                <button
                  onClick={() => { setEditItem(wh); setEditForm({ url: wh.url, events: wh.events, is_active: wh.is_active }) }}
                  className="text-gray-400 hover:text-gray-700"
                >
                  <Pencil className="h-4 w-4" />
                </button>
                <button
                  onClick={() => { if (confirm('Eliminare questo webhook?')) remove.mutate(wh.id) }}
                  className="text-gray-400 hover:text-red-500"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Delivery history drawer */}
      {deliveriesFor && (
        <DeliveryDrawer
          orgId={orgId}
          webhook={deliveriesFor}
          onClose={() => setDeliveriesFor(null)}
        />
      )}

      {/* Create modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-md shadow-xl">
            <h2 className="text-base font-semibold mb-4">Nuovo webhook</h2>
            <label className="block text-xs font-medium text-gray-600 mb-1">URL endpoint</label>
            <input
              className="w-full border rounded-lg px-3 py-2 text-sm mb-4"
              placeholder="https://example.com/webhooks/clavex"
              value={form.url}
              onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
            />
            <label className="block text-xs font-medium text-gray-600 mb-2">Eventi</label>
            <div className="space-y-2 mb-5">
              {ALL_EVENTS.map(ev => (
                <label key={ev} className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.events.includes(ev)}
                    onChange={() => setForm(f => ({ ...f, events: toggleEvent(f.events, ev) }))}
                  />
                  <span className="font-mono">{ev}</span>
                </label>
              ))}
            </div>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setShowCreate(false)} className="px-4 py-1.5 rounded-lg text-sm border text-gray-600">Annulla</button>
              <button
                disabled={!form.url || form.events.length === 0 || create.isPending}
                onClick={() => create.mutate(form)}
                className="px-4 py-1.5 rounded-lg text-sm text-white disabled:opacity-50"
                style={{ background: 'var(--clavex-primary)' }}
              >
                {create.isPending ? 'Creando…' : 'Crea'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit modal */}
      {editItem && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-md shadow-xl">
            <h2 className="text-base font-semibold mb-4">Modifica webhook</h2>
            <label className="block text-xs font-medium text-gray-600 mb-1">URL endpoint</label>
            <input
              className="w-full border rounded-lg px-3 py-2 text-sm mb-4"
              value={editForm.url}
              onChange={e => setEditForm(f => ({ ...f, url: e.target.value }))}
            />
            <label className="block text-xs font-medium text-gray-600 mb-2">Eventi</label>
            <div className="space-y-2 mb-4">
              {ALL_EVENTS.map(ev => (
                <label key={ev} className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={editForm.events.includes(ev)}
                    onChange={() => setEditForm(f => ({ ...f, events: toggleEvent(f.events, ev) }))}
                  />
                  <span className="font-mono">{ev}</span>
                </label>
              ))}
            </div>
            <label className="flex items-center gap-2 text-sm cursor-pointer mb-5">
              <input
                type="checkbox"
                checked={editForm.is_active}
                onChange={e => setEditForm(f => ({ ...f, is_active: e.target.checked }))}
              />
              Attivo
            </label>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setEditItem(null)} className="px-4 py-1.5 rounded-lg text-sm border text-gray-600">Annulla</button>
              <button
                disabled={!editForm.url || editForm.events.length === 0 || update.isPending}
                onClick={() => update.mutate({ id: editItem.id, body: editForm })}
                className="px-4 py-1.5 rounded-lg text-sm text-white disabled:opacity-50"
                style={{ background: 'var(--clavex-primary)' }}
              >
                {update.isPending ? 'Salvando…' : 'Salva'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

