import { useEffect, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { ShieldAlert, Globe, Wifi, TrendingDown, TrendingUp, Minus, RefreshCw, AlertTriangle } from 'lucide-react'

// ── API types ─────────────────────────────────────────────────────────────────

interface BlockedIP {
  ip_address: string
  confidence: number
  is_tor_exit: boolean
  login_count: number
  last_seen: string
}

interface TorBucket {
  hour: string
  count: number
}

interface TopIP {
  ip_address: string
  login_count: number
  max_confidence: number
  is_tor_exit: boolean
}

interface WeekOverWeek {
  this_week: number
  last_week: number
  delta: number
}

interface ShieldData {
  blocked_last_hour: BlockedIP[]
  tor_hourly_trend: TorBucket[]
  top_ips_this_week: TopIP[]
  week_over_week: WeekOverWeek
  enabled: boolean
}

// ── Styles ────────────────────────────────────────────────────────────────────

const card = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
} as const

// ── Sub-components ────────────────────────────────────────────────────────────

function ConfidenceBadge({ score }: { score: number }) {
  const color =
    score >= 75 ? '#ef4444'
    : score >= 40 ? '#f97316'
    : '#eab308'
  return (
    <span
      className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold"
      style={{ background: color + '18', color }}
    >
      {score}%
    </span>
  )
}

function TorBadge() {
  return (
    <span className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold"
      style={{ background: '#7c3aed18', color: '#7c3aed' }}>
      <Wifi className="w-3 h-3" />
      Tor
    </span>
  )
}

function TorSparkline({ data }: { data: TorBucket[] }) {
  if (!data.length)
    return (
      <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>
        No Tor logins in last 7 days
      </p>
    )

  const max = Math.max(...data.map((d) => d.count), 1)
  const h = 48

  return (
    <div className="flex items-end gap-px overflow-hidden" style={{ height: h }}>
      {data.map((d, i) => {
        const barH = Math.max(Math.round((d.count / max) * h), 2)
        const hour = new Date(d.hour).toISOString().slice(0, 13).replace('T', ' ')
        return (
          <div
            key={i}
            title={`${hour} UTC — ${d.count} Tor login${d.count !== 1 ? 's' : ''}`}
            className="flex-1 rounded-t cursor-default"
            style={{ height: barH, minWidth: 2, background: '#7c3aed' }}
          />
        )
      })}
    </div>
  )
}

function WoWIndicator({ wow }: { wow: WeekOverWeek }) {
  const improved = wow.delta < 0
  const flat = wow.delta === 0
  const Icon = flat ? Minus : improved ? TrendingDown : TrendingUp
  const color = flat ? 'var(--clavex-neutral)' : improved ? '#16a34a' : '#ef4444'
  const label = flat
    ? 'unchanged'
    : improved
      ? `${Math.abs(wow.delta)} fewer than last week`
      : `${wow.delta} more than last week`

  return (
    <div className="flex items-center gap-1.5">
      <Icon className="w-4 h-4" style={{ color }} />
      <span className="text-sm font-medium" style={{ color }}>
        {label}
      </span>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ShieldDashboard() {
  const orgId = useAuthStore((s) => s.orgId)
  const [data, setData] = useState<ShieldData | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    if (!orgId) return
    setLoading(true)
    try {
      const res = await api.get<ShieldData>(
        `/organizations/${orgId}/shield-dashboard`,
      )
      setData(res.data)
    } catch {
      toast.error('Failed to load Shield dashboard')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => {
    load()
    // Auto-refresh every 5 minutes.
    const id = setInterval(load, 5 * 60 * 1000)
    return () => clearInterval(id)
  }, [load])

  if (loading || !data)
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full" />
      </div>
    )

  const wow = data.week_over_week
  const noShieldData = !data.blocked_last_hour.length && !data.top_ips_this_week.length && !data.tor_hourly_trend.length && wow.this_week === 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-6 h-6" style={{ color: '#ef4444' }} />
          <div>
            <h1 className="text-xl font-semibold" style={{ color: 'var(--clavex-dark)' }}>
              Clavex Shield
            </h1>
            <p className="text-sm" style={{ color: 'var(--clavex-neutral)' }}>
              Threat intelligence — AbuseIPDB · Tor exit nodes
            </p>
          </div>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm border transition-colors hover:bg-gray-50"
          style={{ borderColor: 'var(--clavex-border)', color: 'var(--clavex-neutral)' }}
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Shield not configured — enrichment is off */}
      {!data.enabled && (
        <div
          className="rounded-xl border px-5 py-4 flex items-start gap-3"
          style={{ background: '#fffbeb', borderColor: '#fde68a' }}
        >
          <AlertTriangle className="w-5 h-5 mt-0.5 flex-shrink-0" style={{ color: '#d97706' }} />
          <div>
            <p className="text-sm font-medium" style={{ color: '#92400e' }}>
              Shield is not enabled
            </p>
            <p className="text-xs mt-0.5" style={{ color: '#b45309' }}>
              Configure an AbuseIPDB key in <code className="font-mono">auth.abuseipdb_key</code> to
              enable threat-intel enrichment. Login IPs will then be checked against AbuseIPDB and
              Tor exit-node lists.
            </p>
          </div>
        </div>
      )}

      {/* Shield active but no threats observed yet */}
      {data.enabled && noShieldData && (
        <div
          className="rounded-xl border px-5 py-4 flex items-start gap-3"
          style={{ background: '#f0fdf4', borderColor: '#bbf7d0' }}
        >
          <ShieldAlert className="w-5 h-5 mt-0.5 flex-shrink-0" style={{ color: '#16a34a' }} />
          <div>
            <p className="text-sm font-medium" style={{ color: '#166534' }}>
              Shield is active — no threats yet
            </p>
            <p className="text-xs mt-0.5" style={{ color: '#15803d' }}>
              Threat-intel enrichment is running. Flagged or Tor exit-node logins will appear here
              as they occur.
            </p>
          </div>
        </div>
      )}

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KPI
          label="Blocked last hour"
          value={data.blocked_last_hour.length}
          color="#ef4444"
        />
        <KPI
          label="Tor logins (7 d)"
          value={data.tor_hourly_trend.reduce((s, b) => s + b.count, 0)}
          color="#7c3aed"
        />
        <KPI
          label="Flagged IPs (this week)"
          value={data.top_ips_this_week.length}
          color="#f97316"
        />
        <KPI
          label="Malicious logins (this week)"
          value={wow.this_week}
          color="#dc2626"
        />
      </div>

      {/* Week-over-week banner */}
      <div style={card} className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <p className="text-sm font-medium" style={{ color: 'var(--clavex-dark)' }}>
            Week over week
          </p>
          <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>
            Malicious login attempts: <strong>{wow.this_week}</strong> this week vs{' '}
            <strong>{wow.last_week}</strong> last week
          </p>
        </div>
        <WoWIndicator wow={wow} />
      </div>

      {/* Two-column: Blocked IPs + Top IPs */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Blocked last hour */}
        <div style={card}>
          <div className="flex items-center gap-2 mb-4">
            <Globe className="w-4 h-4" style={{ color: '#ef4444' }} />
            <h2 className="text-sm font-semibold" style={{ color: 'var(--clavex-dark)' }}>
              Blocked IPs — last hour
            </h2>
          </div>
          {data.blocked_last_hour.length === 0 ? (
            <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>
              No blocked IPs in the last hour
            </p>
          ) : (
            <div className="space-y-2.5">
              {data.blocked_last_hour.map((ip) => (
                <div key={ip.ip_address} className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <code
                      className="text-xs font-mono truncate"
                      style={{ color: 'var(--clavex-dark)' }}
                    >
                      {ip.ip_address}
                    </code>
                    {ip.is_tor_exit && <TorBadge />}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>
                      ×{ip.login_count}
                    </span>
                    <ConfidenceBadge score={ip.confidence} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top 10 IPs this week */}
        <div style={card}>
          <div className="flex items-center gap-2 mb-4">
            <ShieldAlert className="w-4 h-4" style={{ color: '#f97316' }} />
            <h2 className="text-sm font-semibold" style={{ color: 'var(--clavex-dark)' }}>
              Top 10 flagged IPs — this week
            </h2>
          </div>
          {data.top_ips_this_week.length === 0 ? (
            <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>
              No flagged IPs this week
            </p>
          ) : (
            <div className="space-y-2.5">
              {data.top_ips_this_week.map((ip, idx) => (
                <div key={ip.ip_address} className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <span
                      className="text-xs font-mono w-4 text-right flex-shrink-0"
                      style={{ color: 'var(--clavex-neutral)' }}
                    >
                      {idx + 1}.
                    </span>
                    <code
                      className="text-xs font-mono truncate"
                      style={{ color: 'var(--clavex-dark)' }}
                    >
                      {ip.ip_address}
                    </code>
                    {ip.is_tor_exit && <TorBadge />}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>
                      ×{ip.login_count}
                    </span>
                    <ConfidenceBadge score={ip.max_confidence} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Tor trend sparkline */}
      <div style={card}>
        <div className="flex items-center gap-2 mb-3">
          <Wifi className="w-4 h-4" style={{ color: '#7c3aed' }} />
          <h2 className="text-sm font-semibold" style={{ color: 'var(--clavex-dark)' }}>
            Tor exit node login trend — last 7 days
          </h2>
        </div>
        <TorSparkline data={data.tor_hourly_trend} />
        <p className="text-xs mt-2" style={{ color: 'var(--clavex-neutral)' }}>
          Each bar represents one hour. Height = number of logins from Tor exit nodes.
        </p>
      </div>
    </div>
  )
}

function KPI({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={card} className="flex flex-col gap-1">
      <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>
        {label}
      </p>
      <p className="text-2xl font-bold tabular-nums" style={{ color }}>
        {value.toLocaleString()}
      </p>
    </div>
  )
}
