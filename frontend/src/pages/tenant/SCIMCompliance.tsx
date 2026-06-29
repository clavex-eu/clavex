import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import {
  AlertTriangle, CheckCircle, ShieldAlert, Filter, RefreshCw,
  ChevronLeft, ChevronRight, Download, Users, UserX, UserPlus,
  UserCog, Trash2, Info,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SCIMAuditEvent {
  id: number
  event_id: string
  time: string
  action: string
  provider: string
  resource_id?: string
  ip_address?: string
  user_agent?: string
  status: string
  metadata?: Record<string, unknown>
}

interface Anomaly {
  detected_at: string
  window_start: string
  window_end: string
  count: number
  severity: 'warning' | 'critical'
  rule: string
  regulation: string
}

interface ComplianceRef {
  standard: string
  control: string
}

interface SCIMComplianceResponse {
  events: SCIMAuditEvent[]
  next_cursor: number
  total: number
  provider_counts: Record<string, number>
  action_counts: Record<string, number>
  anomalies: Anomaly[]
  generated_at: string
  compliance_refs: ComplianceRef[]
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ACTION_LABELS: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  'scim.user.create':     { label: 'Provisioned',   color: '#22c55e', icon: <UserPlus size={13} /> },
  'scim.user.update':     { label: 'Updated',        color: '#3b82f6', icon: <UserCog size={13} /> },
  'scim.user.deactivate': { label: 'Deactivated',    color: '#f59e0b', icon: <UserX size={13} /> },
  'scim.user.delete':     { label: 'Deleted',        color: '#ef4444', icon: <Trash2 size={13} /> },
}

const PROVIDER_OPTIONS = ['', 'azure_ad', 'okta', 'google_workspace', 'onelogin', 'jumpcloud', 'ping_identity', 'other']
const PROVIDER_LABELS: Record<string, string> = {
  '': 'All providers',
  'azure_ad': 'Azure AD',
  'okta': 'Okta',
  'google_workspace': 'Google Workspace',
  'onelogin': 'OneLogin',
  'jumpcloud': 'JumpCloud',
  'ping_identity': 'Ping Identity',
  'other': 'Other',
}
const ACTION_OPTIONS = ['', 'scim.user.create', 'scim.user.update', 'scim.user.deactivate', 'scim.user.delete']

// ── Component ─────────────────────────────────────────────────────────────────

export default function SCIMCompliance() {
  const orgId = useAuthStore(s => s.orgId)

  const [provider, setProvider] = useState('')
  const [action, setAction]     = useState('')
  const [since, setSince]       = useState('')
  const [until, setUntil]       = useState('')
  const [cursor, setCursor]     = useState(0)
  const [cursorStack, setCursorStack] = useState<number[]>([])

  const params = new URLSearchParams({ limit: '50' })
  if (provider) params.set('provider', provider)
  if (action)   params.set('action', action)
  if (since)    params.set('since', new Date(since).toISOString())
  if (until)    params.set('until', new Date(until).toISOString())
  if (cursor)   params.set('cursor', String(cursor))

  const { data, isLoading, refetch, isFetching } = useQuery<SCIMComplianceResponse>({
    queryKey: ['scim-compliance', orgId, provider, action, since, until, cursor],
    queryFn: () => api.get(`/organizations/${orgId}/compliance/scim/audit?${params}`).then(r => r.data),
    enabled: !!orgId,
    staleTime: 30_000,
  })

  function handleNextPage() {
    if (!data?.next_cursor) return
    setCursorStack(s => [...s, cursor])
    setCursor(data.next_cursor)
  }

  function handlePrevPage() {
    const prev = cursorStack[cursorStack.length - 1] ?? 0
    setCursorStack(s => s.slice(0, -1))
    setCursor(prev)
  }

  function resetFilters() {
    setProvider(''); setAction(''); setSince(''); setUntil('')
    setCursor(0); setCursorStack([])
  }

  function downloadCSV() {
    if (!data?.events.length) return
    const headers = ['time', 'action', 'provider', 'resource_id', 'ip_address', 'status']
    const rows = data.events.map(e => [
      e.time, e.action, e.provider, e.resource_id ?? '', e.ip_address ?? '', e.status,
    ])
    const csv = [headers, ...rows].map(r => r.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `scim-compliance-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg"
            style={{ background: 'rgba(93,202,165,0.12)' }}>
            <ShieldAlert size={20} style={{ color: 'var(--clavex-accent)' }} />
          </div>
          <div>
            <h1 className="text-lg font-semibold" style={{ color: 'var(--clavex-ink)' }}>
              SCIM Inbound Audit Trail
            </h1>
            <p className="text-sm" style={{ color: 'var(--clavex-muted)' }}>
              Identity provisioning chain-of-custody — SOX ITGC · NIS2 Art.21 · ISO 27001 A.9.2
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
            <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} /> Refresh
          </button>
          <button onClick={downloadCSV} disabled={!data?.events.length}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
            <Download size={12} /> Export CSV
          </button>
        </div>
      </div>

      {/* Anomaly alerts */}
      {(data?.anomalies ?? []).length > 0 && (
        <div className="space-y-2">
          {data!.anomalies.map((a, i) => (
            <div key={i} className="flex items-start gap-3 p-4 rounded-lg"
              style={{
                background: a.severity === 'critical' ? 'rgba(239,68,68,0.08)' : 'rgba(245,158,11,0.08)',
                border: `1px solid ${a.severity === 'critical' ? 'rgba(239,68,68,0.4)' : 'rgba(245,158,11,0.4)'}`,
              }}>
              <AlertTriangle size={16} className="flex-shrink-0 mt-0.5"
                style={{ color: a.severity === 'critical' ? '#ef4444' : '#f59e0b' }} />
              <div className="space-y-0.5">
                <p className="text-sm font-semibold" style={{ color: a.severity === 'critical' ? '#ef4444' : '#f59e0b' }}>
                  {a.severity === 'critical' ? '🚨 CRITICAL' : '⚠️ WARNING'} — Mass deprovisioning detected
                </p>
                <p className="text-xs" style={{ color: 'var(--clavex-muted)' }}>
                  <strong>{a.count}</strong> deactivations/deletions between{' '}
                  {new Date(a.window_start).toLocaleString()} and{' '}
                  {new Date(a.window_end).toLocaleString()}
                </p>
                <p className="text-xs" style={{ color: 'var(--clavex-muted)' }}>
                  Rule: {a.rule} · Regulation: {a.regulation}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Stats bar */}
      {data && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Object.entries(data.action_counts).map(([act, count]) => {
            const meta = ACTION_LABELS[act]
            return (
              <div key={act} className="rounded-lg p-3 flex items-center gap-3"
                style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
                <span style={{ color: meta?.color ?? 'var(--clavex-muted)' }}>{meta?.icon ?? <Users size={13} />}</span>
                <div>
                  <p className="text-lg font-semibold" style={{ color: 'var(--clavex-ink)' }}>{count}</p>
                  <p className="text-xs" style={{ color: 'var(--clavex-muted)' }}>{meta?.label ?? act}</p>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Provider breakdown */}
      {data && Object.keys(data.provider_counts).length > 0 && (
        <div className="rounded-xl p-4"
          style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
          <p className="text-xs font-medium mb-3" style={{ color: 'var(--clavex-muted)' }}>
            Operations by provider
          </p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(data.provider_counts).map(([prov, count]) => (
              <span key={prov} className="px-2.5 py-1 rounded-full text-xs font-medium"
                style={{ background: 'rgba(93,202,165,0.12)', color: 'var(--clavex-accent)', border: '1px solid rgba(93,202,165,0.25)' }}>
                {prov} · {count}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="rounded-xl p-4 flex flex-wrap items-end gap-3"
        style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
        <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--clavex-muted)' }}>
          <Filter size={13} /> Filters
        </div>

        <select value={provider} onChange={e => { setProvider(e.target.value); setCursor(0); setCursorStack([]) }}
          className="rounded-lg px-2.5 py-1.5 text-xs"
          style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-ink)' }}>
          {PROVIDER_OPTIONS.map(p => (
            <option key={p} value={p}>{PROVIDER_LABELS[p] ?? p}</option>
          ))}
        </select>

        <select value={action} onChange={e => { setAction(e.target.value); setCursor(0); setCursorStack([]) }}
          className="rounded-lg px-2.5 py-1.5 text-xs"
          style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-ink)' }}>
          {ACTION_OPTIONS.map(a => (
            <option key={a} value={a}>{a ? (ACTION_LABELS[a]?.label ?? a) : 'All actions'}</option>
          ))}
        </select>

        <div className="flex items-center gap-1">
          <span className="text-xs" style={{ color: 'var(--clavex-muted)' }}>From</span>
          <input type="datetime-local" value={since} onChange={e => { setSince(e.target.value); setCursor(0); setCursorStack([]) }}
            className="rounded-lg px-2 py-1 text-xs"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-ink)' }} />
        </div>

        <div className="flex items-center gap-1">
          <span className="text-xs" style={{ color: 'var(--clavex-muted)' }}>To</span>
          <input type="datetime-local" value={until} onChange={e => { setUntil(e.target.value); setCursor(0); setCursorStack([]) }}
            className="rounded-lg px-2 py-1 text-xs"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-ink)' }} />
        </div>

        <button onClick={resetFilters}
          className="text-xs px-2.5 py-1.5 rounded-lg"
          style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
          Clear
        </button>
      </div>

      {/* Events table */}
      <div className="rounded-xl overflow-hidden"
        style={{ border: '1px solid var(--clavex-border)' }}>
        <table className="w-full text-xs">
          <thead>
            <tr style={{ background: 'var(--clavex-card)', borderBottom: '1px solid var(--clavex-border)' }}>
              {['Timestamp', 'Action', 'Provider', 'User', 'IP Address', 'Status'].map(h => (
                <th key={h} className="px-4 py-2.5 text-left font-medium" style={{ color: 'var(--clavex-muted)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'var(--clavex-muted)' }}>Loading…</td></tr>
            )}
            {!isLoading && (!data?.events.length) && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center">
                  <div className="flex flex-col items-center gap-2">
                    <Info size={20} style={{ color: 'var(--clavex-muted)' }} />
                    <p style={{ color: 'var(--clavex-muted)' }}>No SCIM events found for the selected filters.</p>
                    <p className="text-xs" style={{ color: 'var(--clavex-muted)' }}>Events appear here after the first inbound SCIM provisioning operation.</p>
                  </div>
                </td>
              </tr>
            )}
            {data?.events.map(e => {
              const meta = ACTION_LABELS[e.action]
              const email = e.metadata?.email as string | undefined
              return (
                <tr key={e.id} style={{ borderBottom: '1px solid var(--clavex-border)', background: 'var(--clavex-surface)' }}>
                  <td className="px-4 py-2.5 font-mono" style={{ color: 'var(--clavex-muted)' }}>
                    {new Date(e.time).toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="flex items-center gap-1.5 font-medium"
                      style={{ color: meta?.color ?? 'var(--clavex-muted)' }}>
                      {meta?.icon} {meta?.label ?? e.action}
                    </span>
                  </td>
                  <td className="px-4 py-2.5" style={{ color: 'var(--clavex-ink)' }}>
                    {e.provider}
                  </td>
                  <td className="px-4 py-2.5 font-mono" style={{ color: 'var(--clavex-muted)' }}>
                    {email ?? e.resource_id ?? '—'}
                  </td>
                  <td className="px-4 py-2.5 font-mono" style={{ color: 'var(--clavex-muted)' }}>
                    {e.ip_address ?? '—'}
                  </td>
                  <td className="px-4 py-2.5">
                    {e.status === 'success'
                      ? <span className="flex items-center gap-1" style={{ color: '#22c55e' }}><CheckCircle size={11} /> OK</span>
                      : <span className="flex items-center gap-1" style={{ color: '#ef4444' }}><AlertTriangle size={11} /> {e.status}</span>
                    }
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3"
          style={{ background: 'var(--clavex-card)', borderTop: '1px solid var(--clavex-border)' }}>
          <span className="text-xs" style={{ color: 'var(--clavex-muted)' }}>
            {data ? `${data.total.toLocaleString()} total events` : ''}
          </span>
          <div className="flex gap-2">
            <button onClick={handlePrevPage} disabled={cursorStack.length === 0}
              className="flex items-center gap-1 px-2.5 py-1 rounded text-xs disabled:opacity-40"
              style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: cursorStack.length ? 'pointer' : 'default' }}>
              <ChevronLeft size={12} /> Prev
            </button>
            <button onClick={handleNextPage} disabled={!data?.next_cursor}
              className="flex items-center gap-1 px-2.5 py-1 rounded text-xs disabled:opacity-40"
              style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: data?.next_cursor ? 'pointer' : 'default' }}>
              Next <ChevronRight size={12} />
            </button>
          </div>
        </div>
      </div>

      {/* Compliance refs */}
      {data?.compliance_refs && (
        <div className="rounded-xl p-4"
          style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
          <p className="text-xs font-medium mb-2" style={{ color: 'var(--clavex-muted)' }}>Regulatory basis</p>
          <div className="flex flex-wrap gap-2">
            {data.compliance_refs.map(ref => (
              <span key={ref.standard} className="text-xs px-2.5 py-1 rounded-full"
                style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)' }}>
                <strong style={{ color: 'var(--clavex-ink)' }}>{ref.standard}</strong> — {ref.control}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
