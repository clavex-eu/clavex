import { useEffect, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { AlertTriangle, Globe, User, MapPin, Activity, RefreshCw } from 'lucide-react'

interface UserRiskEntry {
  user_id: string
  email: string
  failure_count: number
  total_logins: number
}

interface CountryCount {
  country_code: string
  count: number
}

interface HourlyBucket {
  hour: string
  logins: number
  failures: number
}

interface ImpossibleTravelAlert {
  user_id: string
  email: string
  country1: string
  country2: string
  occurred_at: string
}

interface RiskSummary {
  top_risky_users: UserRiskEntry[]
  country_breakdown: CountryCount[]
  hourly_trend: HourlyBucket[]
  impossible_travel_alerts: ImpossibleTravelAlert[]
}

const cardStyle = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}

function RiskBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(93,202,165,0.08)' }}>
      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
    </div>
  )
}

function Sparkline({ data }: { data: HourlyBucket[] }) {
  if (!data.length) return <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>No data in last 24 h</p>
  const maxLogins = Math.max(...data.map((d) => d.logins), 1)
  const h = 48

  return (
    <div className="flex items-end gap-0.5" style={{ height: h }}>
      {data.map((d, i) => {
        const loginH = Math.round((d.logins / maxLogins) * h)
        const failH = Math.round((d.failures / maxLogins) * h)
        const hour = new Date(d.hour).getUTCHours().toString().padStart(2, '0') + ':00'
        return (
          <div key={i} className="flex-1 flex flex-col items-center justify-end gap-0.5 group relative" style={{ height: h }}>
            {/* Tooltip */}
            <div className="absolute bottom-full mb-1 hidden group-hover:block z-10 pointer-events-none">
              <div className="rounded px-2 py-1 text-[10px] whitespace-nowrap"
                style={{ background: 'var(--clavex-dark)', color: 'var(--clavex-ink)', border: '1px solid rgba(93,202,165,0.2)' }}>
                {hour} · {d.logins} logins · {d.failures} fail
              </div>
            </div>
            {/* Failure bar */}
            {d.failures > 0 && (
              <div className="w-full rounded-t-sm" style={{ height: failH, background: 'rgba(239,68,68,0.6)' }} />
            )}
            {/* Login bar */}
            <div className="w-full rounded-t-sm" style={{ height: loginH, background: 'rgba(93,202,165,0.4)' }} />
          </div>
        )
      })}
    </div>
  )
}

function flagEmoji(cc: string) {
  if (!cc || cc.length !== 2) return '🌐'
  const cp = Array.from(cc.toUpperCase()).map((c) => c.charCodeAt(0) - 65 + 0x1F1E6)
  return String.fromCodePoint(...cp)
}

export default function RiskDashboardPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const [data, setData] = useState<RiskSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null)

  const load = useCallback(async () => {
    if (!orgId) return
    setLoading(true)
    try {
      const res = await api.get(`/organizations/${orgId}/risk-dashboard`)
      setData(res.data)
      setRefreshedAt(new Date())
    } catch {
      toast.error('Failed to load risk dashboard')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { load() }, [load])

  const totalCountry = data?.country_breakdown.reduce((a, c) => a + c.count, 0) ?? 1

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>Risk Dashboard</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
            Org-level identity risk aggregation · login_history
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm"
          style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }}
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          {refreshedAt ? `Updated ${refreshedAt.toLocaleTimeString()}` : 'Refresh'}
        </button>
      </div>

      {loading && !data ? (
        <div className="flex items-center justify-center py-24">
          <RefreshCw size={24} className="animate-spin" style={{ color: 'var(--clavex-primary)' }} />
        </div>
      ) : !data ? null : (
        <>
          {/* Impossible-travel alerts */}
          {data.impossible_travel_alerts.length > 0 && (
            <div className="rounded-xl p-4" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}>
              <h2 className="flex items-center gap-2 text-sm font-semibold mb-3" style={{ color: '#f87171' }}>
                <AlertTriangle size={14} /> Impossible Travel Alerts (last 24 h)
              </h2>
              <div className="space-y-2">
                {data.impossible_travel_alerts.map((a, i) => (
                  <div key={i} className="flex items-center gap-4 text-sm" style={{ color: 'rgba(196,223,240,0.8)' }}>
                    <User size={12} style={{ color: '#f87171', flexShrink: 0 }} />
                    <span className="truncate max-w-[180px]">{a.email || a.user_id.slice(0, 8)}</span>
                    <span className="flex items-center gap-1.5 font-medium">
                      <span>{flagEmoji(a.country1)} {a.country1}</span>
                      <span style={{ color: 'var(--clavex-neutral)' }}>→</span>
                      <span>{flagEmoji(a.country2)} {a.country2}</span>
                    </span>
                    <span className="text-xs ml-auto" style={{ color: 'var(--clavex-neutral)', flexShrink: 0 }}>
                      {new Date(a.occurred_at).toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-3 gap-4">
            {/* Top risky users */}
            <div style={cardStyle}>
              <h2 className="flex items-center gap-2 text-sm font-semibold mb-3" style={{ color: 'var(--clavex-ink)' }}>
                <User size={14} style={{ color: '#f87171' }} /> Top Risky Users (24 h)
              </h2>
              {data.top_risky_users.length === 0 ? (
                <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>No failures in last 24 h — all clear</p>
              ) : (
                <div className="space-y-3">
                  {data.top_risky_users.map((u) => {
                    const failRate = u.total_logins > 0 ? u.failure_count / u.total_logins : 0
                    const level = failRate > 0.5 ? '#f87171' : failRate > 0.2 ? '#fbbf24' : '#e8f4f0'
                    const maxFail = Math.max(...data.top_risky_users.map((x) => x.failure_count), 1)
                    return (
                      <div key={u.user_id}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs truncate max-w-[160px]" style={{ color: 'var(--clavex-ink)' }}>
                            {u.email || u.user_id.slice(0, 12)}
                          </span>
                          <span className="text-xs font-mono font-medium" style={{ color: level }}>
                            {u.failure_count} fail
                          </span>
                        </div>
                        <RiskBar value={u.failure_count} max={maxFail} color={level} />
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Geo breakdown */}
            <div style={cardStyle}>
              <h2 className="flex items-center gap-2 text-sm font-semibold mb-3" style={{ color: 'var(--clavex-ink)' }}>
                <Globe size={14} style={{ color: 'var(--clavex-primary)' }} /> Login Geography (7 d)
              </h2>
              {data.country_breakdown.length === 0 ? (
                <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>No geo data available</p>
              ) : (
                <div className="space-y-2.5 max-h-[280px] overflow-y-auto pr-1">
                  {data.country_breakdown.map((c) => (
                    <div key={c.country_code}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs flex items-center gap-1.5" style={{ color: 'var(--clavex-ink)' }}>
                          <span>{flagEmoji(c.country_code)}</span>
                          <span>{c.country_code}</span>
                        </span>
                        <span className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
                          {c.count} ({Math.round((c.count / totalCountry) * 100)}%)
                        </span>
                      </div>
                      <RiskBar value={c.count} max={data.country_breakdown[0].count} color="rgba(93,202,165,0.55)" />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* 24h trend sparkline */}
            <div style={cardStyle}>
              <h2 className="flex items-center gap-2 text-sm font-semibold mb-3" style={{ color: 'var(--clavex-ink)' }}>
                <Activity size={14} style={{ color: '#a78bfa' }} /> Anomaly Trend (24 h)
              </h2>
              <Sparkline data={data.hourly_trend} />
              <div className="flex items-center gap-4 mt-3">
                <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
                  <span className="inline-block w-2 h-2 rounded-sm" style={{ background: 'rgba(93,202,165,0.4)' }} />
                  Logins
                </div>
                <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
                  <span className="inline-block w-2 h-2 rounded-sm" style={{ background: 'rgba(239,68,68,0.6)' }} />
                  Failures
                </div>
              </div>
              {data.hourly_trend.length > 0 && (() => {
                const total24 = data.hourly_trend.reduce((s, b) => s + b.logins, 0)
                const fail24 = data.hourly_trend.reduce((s, b) => s + b.failures, 0)
                return (
                  <div className="mt-4 pt-3 flex gap-6" style={{ borderTop: '1px solid rgba(93,202,165,0.08)' }}>
                    <div>
                      <p className="text-xl font-bold" style={{ color: 'var(--clavex-primary)' }}>{total24}</p>
                      <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>logins 24 h</p>
                    </div>
                    <div>
                      <p className="text-xl font-bold" style={{ color: fail24 > 0 ? '#f87171' : 'var(--clavex-primary)' }}>
                        {fail24}
                      </p>
                      <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>failures 24 h</p>
                    </div>
                    <div>
                      <p className="text-xl font-bold" style={{ color: '#a78bfa' }}>
                        {data.impossible_travel_alerts.length}
                      </p>
                      <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>impossible travel</p>
                    </div>
                  </div>
                )
              })()}
            </div>
          </div>

          {/* Map placeholder with country list */}
          <div style={cardStyle}>
            <h2 className="flex items-center gap-2 text-sm font-semibold mb-4" style={{ color: 'var(--clavex-ink)' }}>
              <MapPin size={14} style={{ color: 'var(--clavex-primary)' }} /> Login Origins (last 7 days)
            </h2>
            <div className="flex flex-wrap gap-2">
              {data.country_breakdown.map((c) => (
                <div
                  key={c.country_code}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs"
                  style={{
                    background: 'rgba(93,202,165,0.07)',
                    border: '1px solid rgba(93,202,165,0.15)',
                    color: 'var(--clavex-ink)',
                  }}
                >
                  <span>{flagEmoji(c.country_code)}</span>
                  <span className="font-medium">{c.country_code}</span>
                  <span style={{ color: 'var(--clavex-neutral)' }}>· {c.count}</span>
                </div>
              ))}
              {data.country_breakdown.length === 0 && (
                <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>No login data in the last 7 days</p>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
