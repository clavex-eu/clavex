import { useState, useRef, useCallback } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  FlaskConical, Upload, Download, Trash2, ChevronDown, ChevronRight,
  CheckCircle, XCircle, Shield, TriangleAlert, FileJson, BarChart2,
  Loader2, Info, Copy,
} from 'lucide-react'

interface SimulateTraceItem {
  rule_name: string
  priority: number
  enabled: boolean
  matched: boolean
  action: string
}

interface Outcome {
  action: string
  rule_name?: string
  reason?: string
  mfa_forced?: boolean
}

interface BatchResult {
  label: string
  index: number
  outcome: Outcome
  mfa_required: boolean
  trace: SimulateTraceItem[]
  input: Record<string, unknown>
  evaluated_at: string
}

interface BatchSummary {
  total: number
  allowed: number
  denied: number
  mfa_required: number
  step_up_needed: number
  deny_rate: number
  by_action: Record<string, number>
}

interface BatchResponse {
  results: BatchResult[]
  summary: BatchSummary
  evaluated_at: string
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ACTION_META: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  allow:       { label: 'Allow',       color: '#22c55e', icon: <CheckCircle size={12} /> },
  deny:        { label: 'Deny',        color: '#ef4444', icon: <XCircle size={12} /> },
  require_mfa: { label: 'MFA',         color: '#f59e0b', icon: <Shield size={12} /> },
  step_up:     { label: 'Step-up',     color: '#a855f7', icon: <Shield size={12} /> },
}

function actionMeta(action: string) {
  return ACTION_META[action] ?? { label: action, color: '#6b7280', icon: <Info size={12} /> }
}

// ── Example JSON payload ──────────────────────────────────────────────────────

const EXAMPLE_JSON = JSON.stringify(
  {
    scenarios: [
      { label: 'alice — office', user_id: '<uuid>', ip_address: '195.8.12.1', country: 'IT' },
      { label: 'bob — vpn',     user_id: '<uuid>', ip_address: '185.220.101.1', country: 'US' },
      { label: 'eve — tor exit', user_id: '<uuid>', ip_address: '94.102.49.190', country: 'NL' },
    ],
  },
  null,
  2,
)

// ── Summary cards ─────────────────────────────────────────────────────────────

function SummaryCard({ label, value, color, sub }: { label: string; value: number | string; color: string; sub?: string }) {
  return (
    <div className="rounded-xl p-4 space-y-1"
      style={{ background: 'var(--clavex-card)', border: `1px solid ${color}33` }}>
      <div className="text-2xl font-bold tabular-nums" style={{ color }}>{value}</div>
      <div className="text-xs font-medium" style={{ color: 'var(--clavex-ink)' }}>{label}</div>
      {sub && <div className="text-xs" style={{ color: 'var(--clavex-muted)' }}>{sub}</div>}
    </div>
  )
}

// ── Result row ────────────────────────────────────────────────────────────────

function ResultRow({ r, expanded, onToggle }: {
  r: BatchResult
  expanded: boolean
  onToggle: () => void
}) {
  const meta = actionMeta(r.outcome.action)
  const matchedRules = r.trace.filter(t => t.matched)

  return (
    <>
      <tr
        onClick={onToggle}
        className="cursor-pointer hover:bg-white/5 transition-colors"
        style={{ borderBottom: '1px solid var(--clavex-border)' }}>

        <td className="px-3 py-2 text-xs" style={{ color: 'var(--clavex-muted)' }}>
          {r.index + 1}
        </td>
        <td className="px-3 py-2 text-xs font-medium" style={{ color: 'var(--clavex-ink)' }}>
          {r.label || r.input.user_id as string || '—'}
        </td>
        <td className="px-3 py-2">
          <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium"
            style={{ background: `${meta.color}1a`, color: meta.color, border: `1px solid ${meta.color}33` }}>
            {meta.icon} {meta.label}
          </span>
        </td>
        <td className="px-3 py-2 text-xs font-mono" style={{ color: 'var(--clavex-muted)' }}>
          {r.input.ip_address as string ?? '—'}
        </td>
        <td className="px-3 py-2 text-xs" style={{ color: 'var(--clavex-muted)' }}>
          {r.input.country as string ?? '—'}
        </td>
        <td className="px-3 py-2 text-xs" style={{ color: 'var(--clavex-muted)' }}>
          {matchedRules.length > 0 ? matchedRules.map(m => m.rule_name).join(', ') : 'default'}
        </td>
        <td className="px-3 py-2">
          {r.mfa_required && (
            <span className="text-xs px-1.5 py-0.5 rounded"
              style={{ background: 'rgba(245,158,11,0.1)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)' }}>
              MFA
            </span>
          )}
        </td>
        <td className="px-3 py-2 text-xs" style={{ color: 'var(--clavex-muted)' }}>
          {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </td>
      </tr>

      {expanded && (
        <tr style={{ background: 'var(--clavex-surface)', borderBottom: '1px solid var(--clavex-border)' }}>
          <td colSpan={8} className="px-4 py-3">
            <div className="space-y-2">
              {/* Trace */}
              <p className="text-xs font-medium" style={{ color: 'var(--clavex-ink)' }}>Rule trace</p>
              <div className="flex flex-wrap gap-1.5">
                {r.trace.map((t, i) => {
                  const tm = actionMeta(t.action)
                  return (
                    <span key={i}
                      className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full"
                      style={{
                        background: t.matched ? `${tm.color}15` : 'var(--clavex-card)',
                        color: t.matched ? tm.color : 'var(--clavex-muted)',
                        border: `1px solid ${t.matched ? `${tm.color}40` : 'var(--clavex-border)'}`,
                        opacity: t.enabled ? 1 : 0.5,
                      }}>
                      {t.matched ? '✓' : '—'} {t.rule_name}
                    </span>
                  )
                })}
              </div>
              {/* Raw input */}
              <details className="text-xs">
                <summary className="cursor-pointer" style={{ color: 'var(--clavex-muted)' }}>Raw input / outcome</summary>
                <pre className="mt-1 p-2 rounded text-xs overflow-auto"
                  style={{ background: 'var(--clavex-card)', color: 'var(--clavex-ink)', fontFamily: 'monospace', maxHeight: 140 }}>
                  {JSON.stringify({ input: r.input, outcome: r.outcome }, null, 2)}
                </pre>
              </details>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function PolicyBatchSimulate() {
  const orgId = useAuthStore(s => s.orgId)

  const [jsonText,    setJsonText]    = useState('')
  const [jsonError,   setJsonError]   = useState('')
  const [response,    setResponse]    = useState<BatchResponse | null>(null)
  const [expandedIdx, setExpandedIdx] = useState<Set<number>>(new Set())
  const [filterAction, setFilterAction] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  // ── mutation ───────────────────────────────────────────────────────────────

  const mutation = useMutation({
    mutationFn: (body: unknown) =>
      api.post(`/organizations/${orgId}/auth-policies/simulate/batch`, body).then(r => r.data as BatchResponse),
    onSuccess: (data) => {
      setResponse(data)
      toast.success(`${data.summary.total} scenario${data.summary.total !== 1 ? 's' : ''} evaluated`)
    },
    onError: () => toast.error('Simulation failed — check your JSON'),
  })

  // ── file drop / input ──────────────────────────────────────────────────────

  const handleFile = (file: File) => {
    const reader = new FileReader()
    reader.onload = e => setJsonText(e.target?.result as string ?? '')
    reader.readAsText(file)
  }

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [])

  // ── submit ─────────────────────────────────────────────────────────────────

  function handleRun() {
    setJsonError('')
    let parsed: unknown
    try {
      parsed = JSON.parse(jsonText)
    } catch {
      setJsonError('Invalid JSON — check the syntax')
      return
    }
    if (!orgId) { toast.error('Not authenticated'); return }
    mutation.mutate(parsed)
  }

  // ── export CSV ────────────────────────────────────────────────────────────

  function exportCSV() {
    if (!response) return
    const header = 'index,label,action,mfa_required,matched_rules,ip_address,country'
    const rows = response.results.map(r => {
      const matched = r.trace.filter(t => t.matched).map(t => t.rule_name).join(' | ')
      return [r.index + 1, r.label, r.outcome.action, r.mfa_required, matched, r.input.ip_address ?? '', r.input.country ?? ''].join(',')
    })
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `policy-batch-simulate-${Date.now()}.csv`
    a.click()
  }

  // ── filtered results ──────────────────────────────────────────────────────

  const filtered = response
    ? (filterAction ? response.results.filter(r => r.outcome.action === filterAction) : response.results)
    : []

  // ── render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">

      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-10 h-10 rounded-lg"
          style={{ background: 'rgba(93,202,165,0.12)' }}>
          <FlaskConical size={20} style={{ color: 'var(--clavex-accent)' }} />
        </div>
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--clavex-ink)' }}>
            Policy Batch Simulate
          </h1>
          <p className="text-sm" style={{ color: 'var(--clavex-muted)' }}>
            Test up to 1 000 subject/IP/country combinations against the live policy — before activating it in production.
          </p>
        </div>
      </div>

      {/* Input area */}
      <div className="rounded-xl overflow-hidden"
        style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>

        {/* Toolbar */}
        <div className="flex items-center gap-2 px-3 py-2.5 border-b"
          style={{ borderColor: 'var(--clavex-border)', background: 'var(--clavex-surface)' }}>
          <FileJson size={13} style={{ color: 'var(--clavex-accent)' }} />
          <span className="text-xs font-medium" style={{ color: 'var(--clavex-ink)' }}>Scenario payload (JSON)</span>
          <div className="ml-auto flex gap-2">
            <button onClick={() => setJsonText(EXAMPLE_JSON)}
              className="text-xs px-2.5 py-1.5 rounded-lg flex items-center gap-1"
              style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
              <Info size={11} /> Load example
            </button>
            <button onClick={() => fileRef.current?.click()}
              className="text-xs px-2.5 py-1.5 rounded-lg flex items-center gap-1"
              style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
              <Upload size={11} /> Upload file
            </button>
            <input ref={fileRef} type="file" accept=".json" className="hidden"
              onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])} />
            <button onClick={() => { navigator.clipboard.writeText(jsonText); toast.success('Copied') }}
              disabled={!jsonText}
              className="text-xs px-2.5 py-1.5 rounded-lg flex items-center gap-1"
              style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: jsonText ? 'pointer' : 'not-allowed', opacity: jsonText ? 1 : 0.5 }}>
              <Copy size={11} /> Copy
            </button>
          </div>
        </div>

        {/* Editor area — drop target */}
        <div
          onDrop={onDrop}
          onDragOver={e => e.preventDefault()}
          className="relative">
          <textarea
            value={jsonText}
            onChange={e => { setJsonText(e.target.value); setJsonError('') }}
            placeholder='{"scenarios": [{"label": "alice", "user_id": "...", "ip_address": "1.2.3.4", "country": "IT"}]}'
            spellCheck={false}
            className="w-full p-4 text-xs font-mono resize-none outline-none"
            style={{
              background: 'var(--clavex-card)',
              color: 'var(--clavex-ink)',
              minHeight: 180,
              border: 'none',
            }}
          />
          {!jsonText && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none"
              style={{ color: 'var(--clavex-muted)', opacity: 0.4 }}>
              <div className="flex flex-col items-center gap-2 text-sm">
                <Upload size={24} />
                <span>Drop a .json file or paste scenarios above</span>
              </div>
            </div>
          )}
        </div>

        {/* Error */}
        {jsonError && (
          <div className="flex items-center gap-2 px-3 py-2 text-xs border-t"
            style={{ borderColor: 'var(--clavex-border)', background: 'rgba(239,68,68,0.06)', color: '#ef4444' }}>
            <TriangleAlert size={12} /> {jsonError}
          </div>
        )}

        {/* Run button */}
        <div className="flex items-center gap-3 px-3 py-3 border-t"
          style={{ borderColor: 'var(--clavex-border)', background: 'var(--clavex-surface)' }}>
          <button onClick={handleRun} disabled={!jsonText || mutation.isPending}
            className="flex items-center gap-1.5 px-5 py-2 rounded-lg text-sm font-medium"
            style={{
              background: 'var(--clavex-accent)',
              color: '#0d1f1a',
              opacity: !jsonText || mutation.isPending ? 0.6 : 1,
              cursor: !jsonText || mutation.isPending ? 'not-allowed' : 'pointer',
            }}>
            {mutation.isPending
              ? <><Loader2 size={14} className="animate-spin" /> Simulating…</>
              : <><FlaskConical size={14} /> Run simulation</>}
          </button>
          {response && (
            <span className="text-xs" style={{ color: 'var(--clavex-muted)' }}>
              Evaluated at {new Date(response.evaluated_at).toLocaleTimeString()}
            </span>
          )}
          <button onClick={() => { setResponse(null); setJsonText(''); setExpandedIdx(new Set()) }}
            disabled={!response && !jsonText}
            className="ml-auto flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
            <Trash2 size={11} /> Clear
          </button>
        </div>
      </div>

      {/* Results */}
      {response && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-5 gap-3">
            <SummaryCard label="Total" value={response.summary.total} color="var(--clavex-accent)" />
            <SummaryCard label="Allowed" value={response.summary.allowed} color="#22c55e"
              sub={`${Math.round((response.summary.allowed / response.summary.total) * 100)}%`} />
            <SummaryCard label="Denied" value={response.summary.denied} color="#ef4444"
              sub={`${Math.round(response.summary.deny_rate * 100)}% deny rate`} />
            <SummaryCard label="MFA required" value={response.summary.mfa_required} color="#f59e0b" />
            <SummaryCard label="Step-up" value={response.summary.step_up_needed} color="#a855f7" />
          </div>

          {/* Deny rate progress bar */}
          <div className="rounded-xl p-4 space-y-2"
            style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5" style={{ color: 'var(--clavex-ink)' }}>
                <BarChart2 size={13} style={{ color: 'var(--clavex-accent)' }} /> Outcome distribution
              </span>
              <div className="flex gap-3">
                {Object.entries(response.summary.by_action).map(([action, count]) => {
                  const m = actionMeta(action)
                  return (
                    <span key={action} className="flex items-center gap-1" style={{ color: m.color }}>
                      {m.icon} {count} {m.label}
                    </span>
                  )
                })}
              </div>
            </div>
            <div className="flex h-3 rounded-full overflow-hidden gap-0.5">
              {Object.entries(response.summary.by_action).map(([action, count]) => {
                const m = actionMeta(action)
                const pct = (count / response.summary.total) * 100
                return (
                  <div key={action} title={`${m.label}: ${count}`}
                    style={{ width: `${pct}%`, background: m.color, minWidth: count > 0 ? 2 : 0 }} />
                )
              })}
            </div>
          </div>

          {/* Result table */}
          <div className="rounded-xl overflow-hidden"
            style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>

            {/* Table toolbar */}
            <div className="flex items-center gap-2 px-3 py-2.5 border-b"
              style={{ borderColor: 'var(--clavex-border)', background: 'var(--clavex-surface)' }}>
              <span className="text-xs font-medium" style={{ color: 'var(--clavex-ink)' }}>
                Results {filterAction ? `(filtered: ${filtered.length})` : `(${response.results.length})`}
              </span>

              {/* Filter */}
              <select value={filterAction} onChange={e => setFilterAction(e.target.value)}
                className="ml-2 text-xs px-2 py-1 rounded-lg"
                style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-ink)', cursor: 'pointer' }}>
                <option value="">All outcomes</option>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
                <option value="require_mfa">MFA</option>
                <option value="step_up">Step-up</option>
              </select>

              <div className="ml-auto flex gap-2">
                <button onClick={() => setExpandedIdx(new Set(filtered.map(r => r.index)))}
                  className="text-xs px-2.5 py-1 rounded-lg"
                  style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
                  Expand all
                </button>
                <button onClick={() => setExpandedIdx(new Set())}
                  className="text-xs px-2.5 py-1 rounded-lg"
                  style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
                  Collapse all
                </button>
                <button onClick={exportCSV}
                  className="flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg"
                  style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
                  <Download size={11} /> CSV
                </button>
              </div>
            </div>

            <div className="overflow-auto" style={{ maxHeight: 460 }}>
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr style={{ background: 'var(--clavex-surface)', borderBottom: '1px solid var(--clavex-border)' }}>
                    {['#', 'Label / User', 'Outcome', 'IP', 'Country', 'Matched rule', 'MFA', ''].map(h => (
                      <th key={h} className="px-3 py-2 text-xs font-medium" style={{ color: 'var(--clavex-muted)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(r => (
                    <ResultRow key={r.index} r={r}
                      expanded={expandedIdx.has(r.index)}
                      onToggle={() => setExpandedIdx(prev => {
                        const next = new Set(prev)
                        next.has(r.index) ? next.delete(r.index) : next.add(r.index)
                        return next
                      })} />
                  ))}
                </tbody>
              </table>
              {filtered.length === 0 && (
                <div className="flex items-center justify-center py-10 text-sm"
                  style={{ color: 'var(--clavex-muted)' }}>
                  No results match the filter.
                </div>
              )}
            </div>
          </div>

          {/* Hint for high deny rate */}
          {response.summary.deny_rate > 0.2 && (
            <div className="flex items-start gap-2 rounded-xl p-4 text-xs"
              style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)', color: '#ef4444' }}>
              <TriangleAlert size={14} className="flex-shrink-0 mt-0.5" />
              <span>
                <strong>{Math.round(response.summary.deny_rate * 100)}%</strong> of simulated users would be denied.
                Review your deny rules before enabling this policy in production.
              </span>
            </div>
          )}
        </>
      )}

      {/* Schema reference */}
      {!response && (
        <div className="rounded-xl p-4 space-y-2"
          style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
          <p className="text-xs font-medium" style={{ color: 'var(--clavex-ink)' }}>Scenario fields</p>
          <div className="grid grid-cols-3 gap-2 text-xs" style={{ color: 'var(--clavex-muted)' }}>
            {[
              ['label',        'string', 'Optional identifier echoed in results'],
              ['user_id',      'uuid',   'Look up MFA enrollment, last login, anomaly signals'],
              ['client_id',    'string', 'OIDC client_id for client-based rules'],
              ['ip_address',   'string', 'Source IP; falls back to request IP'],
              ['country',      'ISO 3166','Overrides geo-IP lookup'],
              ['user_agent',   'string', 'Device / browser string'],
              ['request_time', 'RFC3339','Simulate a past or future timestamp'],
            ].map(([field, type, desc]) => (
              <div key={field} className="rounded-lg p-2.5 space-y-0.5"
                style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)' }}>
                <div className="flex items-center justify-between">
                  <code style={{ color: 'var(--clavex-accent)', fontFamily: 'monospace' }}>{field}</code>
                  <span style={{ opacity: 0.6 }}>{type}</span>
                </div>
                <p className="leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
