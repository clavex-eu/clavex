import { useEffect, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Plus, Trash2, RefreshCw, Radio, CheckCircle, XCircle, AlertCircle, Zap, Save } from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SSFStream {
  id?: string
  delivery_method: 'push' | 'poll'
  endpoint_url?: string
  description?: string
  status: 'enabled' | 'paused' | 'disabled'
  event_types: string[]
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ALL_EVENT_TYPES = [
  { value: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',              label: 'Session Revoked (CAEP)',        cat: 'CAEP' },
  { value: 'https://schemas.openid.net/secevent/caep/event-type/credential-change',            label: 'Credential Change (CAEP)',      cat: 'CAEP' },
  { value: 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',       label: 'Assurance Level Change (CAEP)', cat: 'CAEP' },
  { value: 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',     label: 'Device Compliance (CAEP)',      cat: 'CAEP' },
  { value: 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',             label: 'Account Disabled (RISC)',       cat: 'RISC' },
  { value: 'https://schemas.openid.net/secevent/risc/event-type/account-enabled',              label: 'Account Enabled (RISC)',        cat: 'RISC' },
  { value: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',               label: 'Account Purged (RISC)',         cat: 'RISC' },
  { value: 'https://schemas.openid.net/secevent/risc/event-type/sessions-revoked',             label: 'Sessions Revoked (RISC)',       cat: 'RISC' },
  { value: 'https://schemas.openid.net/secevent/risc/event-type/identifier-changed',           label: 'Identifier Changed (RISC)',     cat: 'RISC' },
  { value: 'https://schemas.openid.net/secevent/risc/event-type/identifier-recycled',          label: 'Identifier Recycled (RISC)',    cat: 'RISC' },
]

const STATUS_COLORS: Record<string, string> = {
  enabled:  'var(--clavex-primary)',
  paused:   '#fbbf24',
  disabled: '#f87171',
}

const STATUS_ICONS: Record<string, typeof CheckCircle> = {
  enabled:  CheckCircle,
  paused:   AlertCircle,
  disabled: XCircle,
}

// ── Styles ────────────────────────────────────────────────────────────────────

const card: React.CSSProperties = { background: 'white', border: '0.5px solid var(--clavex-border)', borderRadius: 12, padding: '20px 24px' }
const inp: React.CSSProperties = { background: 'white', color: 'var(--clavex-ink)', border: '0.5px solid var(--clavex-border-subtle)', borderRadius: 8, padding: '7px 11px', fontSize: 13, outline: 'none', width: '100%' }
const sel: React.CSSProperties = { ...inp, cursor: 'pointer' }
const lbl: React.CSSProperties = { display: 'block', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--clavex-ink-muted)', marginBottom: 4 }

// ── Stream Form ───────────────────────────────────────────────────────────────

function StreamForm({ stream, onSave, onCancel }: {
  stream: Partial<SSFStream>
  onSave: (s: SSFStream) => Promise<void>
  onCancel: () => void
}) {
  const [form, setForm] = useState<SSFStream>({
    delivery_method: stream.delivery_method ?? 'push',
    endpoint_url: stream.endpoint_url ?? '',
    description: stream.description ?? '',
    status: stream.status ?? 'enabled',
    event_types: stream.event_types ?? [],
  })
  const [saving, setSaving] = useState(false)

  const toggleEvent = (v: string) => {
    setForm((f) => ({
      ...f,
      event_types: f.event_types.includes(v)
        ? f.event_types.filter((e) => e !== v)
        : [...f.event_types, v],
    }))
  }

  const selectAll = () => setForm((f) => ({ ...f, event_types: ALL_EVENT_TYPES.map((e) => e.value) }))
  const clearAll  = () => setForm((f) => ({ ...f, event_types: [] }))

  const handle = async () => {
    if (form.delivery_method === 'push' && !form.endpoint_url) {
      toast.error('Endpoint URL is required for push delivery')
      return
    }
    if (form.event_types.length === 0) {
      toast.error('Select at least one event type')
      return
    }
    setSaving(true)
    try {
      await onSave(form)
    } finally {
      setSaving(false)
    }
  }

  const cats = Array.from(new Set(ALL_EVENT_TYPES.map((e) => e.cat)))

  return (
    <div style={{ ...card, borderColor: 'var(--clavex-primary)' }} className="space-y-5">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label style={lbl}>Delivery method</label>
          <select style={sel} value={form.delivery_method}
            onChange={(e) => setForm((f) => ({ ...f, delivery_method: e.target.value as 'push' | 'poll' }))}>
            <option value="push">Push (HTTP POST to endpoint)</option>
            <option value="poll">Pull polling (client fetches)</option>
          </select>
        </div>
        <div>
          <label style={lbl}>Status</label>
          <select style={sel} value={form.status}
            onChange={(e) => setForm((f) => ({ ...f, status: e.target.value as SSFStream['status'] }))}>
            <option value="enabled">Enabled</option>
            <option value="paused">Paused</option>
            <option value="disabled">Disabled</option>
          </select>
        </div>
        {form.delivery_method === 'push' && (
          <div className="md:col-span-2">
            <label style={lbl}>Endpoint URL <span style={{ color: '#f87171' }}>*</span></label>
            <input style={inp} type="url" value={form.endpoint_url} placeholder="https://your-app.example.com/ssf/receiver"
              onChange={(e) => setForm((f) => ({ ...f, endpoint_url: e.target.value }))} />
            <p className="text-[11px] mt-1" style={{ color: 'var(--clavex-neutral)' }}>
              Clavex will POST signed JWTs (RFC 8935 SET) to this URL when events occur.
            </p>
          </div>
        )}
        <div className="md:col-span-2">
          <label style={lbl}>Description (optional)</label>
          <input style={inp} value={form.description} placeholder="e.g. SIEM integration, Zero Trust PDP"
            onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
        </div>
      </div>

      {/* Event type selector */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label style={lbl}>Event types</label>
          <div className="flex gap-2">
            <button onClick={selectAll} className="text-xs px-2 py-0.5 rounded" style={{ color: 'var(--clavex-primary)', background: 'rgba(93,202,165,0.1)' }}>All</button>
            <button onClick={clearAll} className="text-xs px-2 py-0.5 rounded" style={{ color: 'var(--clavex-neutral)', background: 'rgba(0,0,0,0.05)' }}>Clear</button>
          </div>
        </div>
        {cats.map((cat) => (
          <div key={cat} className="mb-3">
            <p className="text-[11px] font-semibold mb-1.5 uppercase tracking-wider" style={{ color: 'var(--clavex-ink-muted)' }}>{cat}</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
              {ALL_EVENT_TYPES.filter((e) => e.cat === cat).map((evt) => {
                const checked = form.event_types.includes(evt.value)
                return (
                  <label key={evt.value} className="flex items-center gap-2 rounded-lg px-3 py-2 cursor-pointer"
                    style={{ background: checked ? 'rgba(93,202,165,0.1)' : 'rgba(0,0,0,0.02)', border: `0.5px solid ${checked ? 'var(--clavex-primary)' : 'var(--clavex-border-subtle)'}` }}>
                    <input type="checkbox" checked={checked} onChange={() => toggleEvent(evt.value)} className="accent-green-400" />
                    <span className="text-xs" style={{ color: 'var(--clavex-ink)' }}>{evt.label}</span>
                  </label>
                )
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="flex justify-end gap-3">
        <button onClick={onCancel} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--clavex-ink-subtle)' }}>Cancel</button>
        <button onClick={handle} disabled={saving}
          className="px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2"
          style={{ background: 'var(--clavex-primary)', color: 'white' }}>
          {saving ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
          Save stream
        </button>
      </div>
    </div>
  )
}

// ── Stream card ───────────────────────────────────────────────────────────────

function StreamCard({ stream, onEdit, onDelete, onVerify }: {
  stream: SSFStream & { id: string }
  onEdit: () => void
  onDelete: () => void
  onVerify: () => Promise<void>
}) {
  const [verifying, setVerifying] = useState(false)
  const StatusIcon = STATUS_ICONS[stream.status] ?? CheckCircle

  const handleVerify = async () => {
    setVerifying(true)
    try { await onVerify() } finally { setVerifying(false) }
  }

  return (
    <div style={card}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: `${STATUS_COLORS[stream.status]}18` }}>
            <Radio size={14} style={{ color: STATUS_COLORS[stream.status] }} />
          </div>
          <div className="min-w-0">
            <p className="font-semibold text-sm truncate" style={{ color: 'var(--clavex-ink)' }}>
              {stream.description || (stream.delivery_method === 'push' ? 'Push stream' : 'Pull stream')}
            </p>
            <p className="text-xs font-mono truncate mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>
              {stream.endpoint_url ?? 'poll endpoint'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full"
            style={{ background: `${STATUS_COLORS[stream.status]}18`, color: STATUS_COLORS[stream.status] }}>
            <StatusIcon size={10} /> {stream.status}
          </span>
        </div>
      </div>

      {/* Event types */}
      <div className="mt-3 flex flex-wrap gap-1">
        {stream.event_types.map((e) => {
              const label = ALL_EVENT_TYPES.find((x) => x.value === e)?.label ?? e.split('/').slice(-1)[0] ?? e
          return (
            <span key={e} className="text-[10px] px-1.5 py-0.5 rounded"
              style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }}>
              {label}
            </span>
          )
        })}
      </div>

      <div className="flex gap-2 mt-4">
        <button onClick={onEdit} className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs"
          style={{ background: 'rgba(0,0,0,0.04)', color: 'var(--clavex-ink-subtle)' }}>
          Edit
        </button>
        <button onClick={handleVerify} disabled={verifying}
          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs"
          style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }}>
          {verifying ? <RefreshCw size={10} className="animate-spin" /> : <Zap size={10} />}
          Verify
        </button>
        <button onClick={onDelete}
          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs ml-auto"
          style={{ background: 'rgba(239,68,68,0.08)', color: '#f87171' }}>
          <Trash2 size={10} /> Delete
        </button>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function SSFStreamsPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const [stream, setStream] = useState<(SSFStream & { id: string }) | null>(null)
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState(false)
  const [creating, setCreating] = useState(false)

  const load = useCallback(async () => {
    if (!orgId) return
    setLoading(true)
    try {
      const res = await api.get(`/organizations/${orgId}/ssf/stream`)
      setStream(res.data)
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status
      if (status !== 404) toast.error('Failed to load SSF stream')
      setStream(null)
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { load() }, [load])

  const handleCreate = async (s: SSFStream) => {
    try {
      const res = await api.post(`/organizations/${orgId}/ssf/stream`, s)
      setStream(res.data)
      setCreating(false)
      toast.success('SSF stream created')
    } catch {
      toast.error('Failed to create stream')
      throw new Error('save failed')
    }
  }

  const handleUpdate = async (s: SSFStream) => {
    if (!stream?.id || !orgId) return
    try {
      const res = await api.patch(`/organizations/${orgId}/ssf/stream`, s)
      setStream(res.data)
      setEditing(false)
      toast.success('Stream updated')
    } catch {
      toast.error('Update failed')
      throw new Error('save failed')
    }
  }

  const handleDelete = async () => {
    if (!orgId || !stream) return
    try {
      await api.delete(`/organizations/${orgId}/ssf/stream`)
      setStream(null)
      toast.success('Stream deleted')
    } catch {
      toast.error('Delete failed')
    }
  }

  const handleVerify = async () => {
    if (!orgId) return
    try {
      await api.post(`/organizations/${orgId}/ssf/stream/verify`)
      toast.success('Verification event delivered successfully')
    } catch {
      toast.error('Verification failed — check your endpoint')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>Clavex Signals</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
            Push real-time security events (RFC 8935) to your SIEM, Zero Trust PDP, or SOAR platform
          </p>
        </div>
        {!stream && !creating && (
          <button onClick={() => setCreating(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold"
            style={{ background: 'var(--clavex-primary)', color: 'white' }}>
            <Plus size={14} /> New stream
          </button>
        )}
      </div>

      {/* Info box */}
      <div className="rounded-xl px-4 py-3 flex items-start gap-3"
        style={{ background: 'rgba(93,202,165,0.08)', border: '0.5px solid rgba(93,202,165,0.25)' }}>
        <Radio size={14} className="mt-0.5 flex-shrink-0" style={{ color: 'var(--clavex-primary)' }} />
        <p className="text-xs leading-relaxed" style={{ color: 'var(--clavex-ink-subtle)' }}>
          <strong>Shared Signals Framework (IETF RFC 8935 / 8936)</strong> — Clavex signs Security Event Tokens (SET/JWT)
          and delivers them to your endpoint within milliseconds of any account, session, or credential event.
          Use this for zero-latency token revocation in Zero Trust architectures (CAEP) or risk signal sharing (RISC).
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-24">
          <RefreshCw size={24} className="animate-spin" style={{ color: 'var(--clavex-primary)' }} />
        </div>
      ) : creating ? (
        <StreamForm stream={{}} onSave={handleCreate} onCancel={() => setCreating(false)} />
      ) : editing && stream ? (
        <StreamForm stream={stream} onSave={handleUpdate} onCancel={() => setEditing(false)} />
      ) : stream ? (
        <StreamCard
          stream={stream}
          onEdit={() => setEditing(true)}
          onDelete={handleDelete}
          onVerify={handleVerify}
        />
      ) : (
        <div className="text-center py-16" style={card}>
          <Radio size={32} className="mx-auto mb-3" style={{ color: 'var(--clavex-border)' }} />
          <p className="font-semibold" style={{ color: 'var(--clavex-ink)' }}>No SSF stream configured</p>
          <p className="text-sm mt-1 mb-4" style={{ color: 'var(--clavex-neutral)' }}>
            Create a stream to start receiving real-time security events.
          </p>
          <button onClick={() => setCreating(true)}
            className="px-4 py-2 rounded-lg text-sm font-semibold"
            style={{ background: 'var(--clavex-primary)', color: 'white' }}>
            Create stream
          </button>
        </div>
      )}
    </div>
  )
}
