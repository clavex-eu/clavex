import { useState } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Play, CheckCircle, XCircle, AlertCircle, ChevronRight, Info } from 'lucide-react'

interface SimulateRequest {
  user_id: string
  client_id: string
  ip_address: string
  country: string
  user_agent: string
  request_time: string
}

interface TraceItem {
  rule_name: string
  priority: number
  enabled: boolean
  matched: boolean
  action: string
}

interface SimulateResponse {
  outcome: { action: string; reason?: string }
  mfa_required: boolean
  trace: TraceItem[]
  input: Record<string, unknown>
  evaluated_at: string
}

const OUTCOME_STYLES: Record<string, { color: string; bg: string; icon: typeof CheckCircle }> = {
  allow:  { color: 'var(--clavex-primary)', bg: 'rgba(93,202,165,0.1)',  icon: CheckCircle  },
  deny:   { color: '#f87171',               bg: 'rgba(239,68,68,0.1)',   icon: XCircle      },
  mfa:    { color: '#fbbf24',               bg: 'rgba(234,179,8,0.1)',   icon: AlertCircle  },
  block:  { color: '#f87171',               bg: 'rgba(239,68,68,0.12)',  icon: XCircle      },
}

function outcomeStyle(action: string) {
  return OUTCOME_STYLES[action?.toLowerCase()] ?? OUTCOME_STYLES['allow']
}

const fieldStyle = {
  background: 'white',
  color: 'var(--clavex-ink)',
  border: '0.5px solid var(--clavex-border-subtle)',
  borderRadius: 8,
  padding: '8px 12px',
  fontSize: 13,
  width: '100%',
  outline: 'none',
} as const

export default function PolicySimulatePage() {
  const orgId = useAuthStore((s) => s.orgId)
  const [form, setForm] = useState<SimulateRequest>({
    user_id: '',
    client_id: '',
    ip_address: '',
    country: '',
    user_agent: '',
    request_time: '',
  })
  const [result, setResult] = useState<SimulateResponse | null>(null)
  const [loading, setLoading] = useState(false)

  const set = (k: keyof SimulateRequest) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }))

  const run = async () => {
    if (!orgId) return
    setLoading(true)
    setResult(null)
    try {
      const body = { ...form }
      // Strip empty fields so the server applies defaults
      Object.keys(body).forEach((k) => {
        if (body[k as keyof SimulateRequest] === '') delete (body as Record<string, unknown>)[k]
      })
      const res = await api.post(`/organizations/${orgId}/auth-policies/simulate`, body)
      setResult(res.data)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg ?? 'Simulation failed')
    } finally {
      setLoading(false)
    }
  }

  const cardStyle = {
    background: 'white',
    border: '0.5px solid var(--clavex-border)',
    borderRadius: 12,
    padding: '20px 24px',
  }

  const OutcomeIcon = result ? outcomeStyle(result.outcome.action).icon : null

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>Policy Dry-Run</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
          Simulate an auth flow with any user / IP / country — see exactly which rule fires
        </p>
      </div>

      <div className="grid grid-cols-5 gap-5">
        {/* Input form */}
        <div className="col-span-2 space-y-4">
          <div style={cardStyle}>
            <h2 className="text-sm font-semibold mb-4" style={{ color: 'var(--clavex-ink)' }}>Simulation Input</h2>
            <div className="space-y-3">
              {([
                { key: 'user_id',      label: 'User ID',       ph: 'uuid or leave empty' },
                { key: 'client_id',    label: 'Client ID',     ph: 'oidc-client-id'       },
                { key: 'ip_address',   label: 'IP Address',    ph: '1.2.3.4'              },
                { key: 'country',      label: 'Country (ISO)', ph: 'DE, FR, US …'         },
                { key: 'user_agent',   label: 'User-Agent',    ph: 'Mozilla/5.0 …'        },
                { key: 'request_time', label: 'Request Time',  ph: '2025-06-15T14:00:00Z' },
              ] as { key: keyof SimulateRequest; label: string; ph: string }[]).map(({ key, label, ph }) => (
                <div key={key}>
                  <label className="block text-xs font-medium mb-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
                    {label}
                  </label>
                  <input
                    style={fieldStyle}
                    placeholder={ph}
                    value={form[key]}
                    onChange={set(key)}
                  />
                </div>
              ))}
            </div>
            <button
              onClick={run}
              disabled={loading}
              className="mt-5 w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-opacity"
              style={{
                background: 'var(--clavex-primary)',
                color: 'white',
                opacity: loading ? 0.6 : 1,
              }}
            >
              <Play size={14} />
              {loading ? 'Running…' : 'Run Simulation'}
            </button>
          </div>

          {/* Quick presets */}
          <div style={cardStyle}>
            <h2 className="flex items-center gap-1.5 text-xs font-semibold mb-3" style={{ color: 'var(--clavex-ink-subtle)' }}>
              <Info size={11} /> Quick Presets
            </h2>
            <div className="space-y-2">
              {[
                { label: 'Tor / Datacenter IP', ip: '185.220.101.1', country: 'NL' },
                { label: 'Unusual hour (2 AM UTC)', time: new Date(Date.UTC(new Date().getFullYear(), 0, 15, 2, 0)).toISOString() },
                { label: 'Unknown country', country: 'KP' },
              ].map(({ label, ...patch }) => (
                <button
                  key={label}
                  onClick={() => setForm((f) => ({ ...f, ...patch }))}
                  className="w-full text-left px-3 py-2 rounded-lg text-xs flex items-center gap-2 transition-colors"
                  style={{ background: 'rgba(93,202,165,0.04)', color: 'var(--clavex-ink-muted)', border: '1px solid rgba(93,202,165,0.08)' }}
                >
                  <ChevronRight size={10} style={{ color: 'var(--clavex-primary)' }} />
                  {label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Results panel */}
        <div className="col-span-3 space-y-4">
          {!result ? (
            <div className="flex items-center justify-center h-64" style={{ ...cardStyle, color: 'var(--clavex-neutral)', fontSize: 13 }}>
              Run a simulation to see results
            </div>
          ) : (
            <>
              {/* Outcome banner */}
              <div
                className="flex items-center gap-4 p-4 rounded-xl"
                style={{ background: outcomeStyle(result.outcome.action).bg, border: `1px solid ${outcomeStyle(result.outcome.action).color}40` }}
              >
                {OutcomeIcon && <OutcomeIcon size={28} style={{ color: outcomeStyle(result.outcome.action).color, flexShrink: 0 }} />}
                <div>
                  <p className="text-lg font-bold uppercase" style={{ color: outcomeStyle(result.outcome.action).color }}>
                    {result.outcome.action}
                  </p>
                  {result.mfa_required && (
                    <p className="text-xs mt-0.5" style={{ color: '#fbbf24' }}>⚠ MFA would be required</p>
                  )}
                  {result.outcome.reason && (
                    <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-ink-subtle)' }}>{result.outcome.reason}</p>
                  )}
                </div>
                <div className="ml-auto text-right">
                  <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>evaluated at</p>
                  <p className="text-xs font-mono" style={{ color: 'var(--clavex-ink-subtle)' }}>
                    {new Date(result.evaluated_at).toLocaleTimeString()}
                  </p>
                </div>
              </div>

              {/* Rule trace */}
              <div style={cardStyle}>
                <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--clavex-ink)' }}>Rule Evaluation Trace</h2>
                {result.trace.length === 0 ? (
                  <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>No rules configured for this org</p>
                ) : (
                  <div className="space-y-2">
                    {result.trace.map((item, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-3 px-3 py-2.5 rounded-lg"
                        style={{
                          background: item.matched
                            ? 'rgba(93,202,165,0.06)'
                            : 'rgba(93,202,165,0.02)',
                          border: `1px solid ${item.matched ? 'rgba(93,202,165,0.2)' : 'rgba(93,202,165,0.05)'}`,
                          opacity: item.enabled ? 1 : 0.45,
                        }}
                      >
                        {/* Match indicator */}
                        <span
                          className="flex-shrink-0 w-2 h-2 rounded-full"
                          style={{ background: item.matched ? 'var(--clavex-primary)' : 'rgba(196,223,240,0.15)' }}
                        />
                        {/* Rule info */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-medium truncate" style={{ color: 'var(--clavex-ink)' }}>
                              {item.rule_name}
                            </span>
                            {!item.enabled && (
                              <span className="text-[10px] px-1.5 rounded" style={{ background: 'rgba(196,223,240,0.08)', color: 'var(--clavex-neutral)' }}>
                                disabled
                              </span>
                            )}
                          </div>
                          <p className="text-[10px] mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>
                            priority {item.priority}
                          </p>
                        </div>
                        {/* Action badge */}
                        <span
                          className="flex-shrink-0 text-[10px] px-2 py-0.5 rounded font-medium"
                          style={{
                            background: outcomeStyle(item.action).bg,
                            color: outcomeStyle(item.action).color,
                          }}
                        >
                          {item.action}
                        </span>
                        {/* Matched indicator */}
                        <span
                          className="flex-shrink-0 text-[10px] font-semibold"
                          style={{ color: item.matched ? 'var(--clavex-primary)' : 'rgba(196,223,240,0.2)' }}
                        >
                          {item.matched ? '✓ matched' : '—'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Resolved input */}
              <div style={cardStyle}>
                <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--clavex-ink)' }}>Resolved Input Signals</h2>
                <pre
                  className="text-[11px] overflow-x-auto rounded-lg p-3"
                  style={{ background: 'var(--clavex-dark)', color: 'var(--clavex-ink-muted)', lineHeight: 1.7 }}
                >
                  {JSON.stringify(result.input, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
