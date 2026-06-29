import { useEffect, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import { AlertTriangle, MapPin, RefreshCw, ShieldAlert, TrendingUp, Wifi, User, Clock } from 'lucide-react'
import world from '@/data/world-110m'

// ── Types ─────────────────────────────────────────────────────────────────────

interface LoginEntry {
  id: string
  user_id?: string
  email?: string
  success: boolean
  ip_address?: string
  country_code?: string
  city?: string
  asn_org?: string
  user_agent?: string
  failure_reason?: string
  created_at: string
  risk_score?: number
}

interface CountryCount { country_code: string; count: number }
interface HourlyBucket { hour: string; logins: number; failures: number }
interface ImpossibleTravelAlert { user_id: string; email: string; country1: string; country2: string; occurred_at: string }
interface TopFailedIP { ip: string; count: number; country_code?: string; asn_org?: string }

interface RiskSummary {
  top_risky_users: Array<{ user_id: string; email: string; failure_count: number; total_logins: number }>
  country_breakdown: CountryCount[]
  hourly_trend: HourlyBucket[]
  impossible_travel_alerts: ImpossibleTravelAlert[]
  top_failed_ips?: TopFailedIP[]
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function flagEmoji(cc?: string) {
  if (!cc || cc.length !== 2) return '🌐'
  const cp = Array.from(cc.toUpperCase()).map((c) => c.charCodeAt(0) - 65 + 0x1F1E6)
  return String.fromCodePoint(...cp)
}

function relTime(ts: string) {
  const diff = (Date.now() - new Date(ts).getTime()) / 1000
  if (diff < 60) return `${Math.round(diff)}s ago`
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`
  return new Date(ts).toLocaleDateString()
}

function heatColor(ratio: number) {
  // 0 = very light green → 1 = full primary
  const r = Math.round(93 + (0 - 93) * ratio)
  const g = Math.round(202 + (180 - 202) * ratio)
  const b = Math.round(165 + (50 - 165) * ratio)
  return `rgb(${r},${g},${b})`
}

// ── Common styles ─────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}

// ── Country heatmap ───────────────────────────────────────────────────────────

const TOP_COUNTRIES = [
  'US','GB','DE','FR','IT','ES','IN','BR','CA','AU',
  'NL','PL','SE','NO','DK','FI','CH','AT','BE','PT',
  'JP','KR','CN','SG','AE','ZA','MX','AR','TR','RU',
]

function CountryHeatmap({ data }: { data: CountryCount[] }) {
  const maxCount = Math.max(...data.map((d) => d.count), 1)
  const byCC: Record<string, number> = {}
  for (const d of data) byCC[d.country_code] = d.count

  // Show top 30 known countries + any extra from data not in top list
  const extras = data.filter((d) => !TOP_COUNTRIES.includes(d.country_code)).slice(0, 10).map((d) => d.country_code)
  const all = [...new Set([...TOP_COUNTRIES, ...extras])]

  return (
    <div>
      <div className="grid gap-1" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(52px, 1fr))' }}>
        {all.map((cc) => {
          const count = byCC[cc] ?? 0
          const ratio = count / maxCount
          return (
            <div key={cc} className="relative group rounded-lg flex flex-col items-center justify-center py-2 cursor-default"
              style={{ background: count ? heatColor(ratio) : 'rgba(0,0,0,0.03)', transition: 'background 0.2s' }}>
              <span className="text-lg leading-none">{flagEmoji(cc)}</span>
              <span className="text-[10px] font-mono mt-0.5" style={{ color: count ? 'white' : 'var(--clavex-neutral)' }}>
                {cc}
              </span>
              {/* Tooltip */}
              {count > 0 && (
                <div className="absolute bottom-full mb-1 hidden group-hover:block z-20 pointer-events-none">
                  <div className="rounded px-2 py-1 text-xs whitespace-nowrap shadow-lg"
                    style={{ background: 'var(--clavex-ink)', color: 'white' }}>
                    {count} logins
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
      <p className="text-[11px] mt-2" style={{ color: 'var(--clavex-neutral)' }}>
        Darker = more logins · hover a cell for count
      </p>
    </div>
  )
}

// ── World choropleth ──────────────────────────────────────────────────────────
// Equirectangular projection (lon/lat → x/y) over a bundled low-res Natural Earth
// dataset. No map library — just SVG paths shaded by login volume.

const MAP_W = 720
const MAP_H = 360

function projectRing(ring: number[][]): string {
  let d = ''
  for (let i = 0; i < ring.length; i++) {
    const x = ((ring[i][0] + 180) / 360) * MAP_W
    const y = ((90 - ring[i][1]) / 180) * MAP_H
    d += (i === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1)
  }
  return d + 'Z'
}

function countryPath(geo: { t: string; c: number[][][] | number[][][][] }): string {
  if (geo.t === 'Polygon') return (geo.c as number[][][]).map(projectRing).join('')
  return (geo.c as number[][][][]).map((poly) => poly.map(projectRing).join('')).join('')
}

function WorldChoropleth({ data }: { data: CountryCount[] }) {
  const byCC: Record<string, number> = {}
  for (const d of data) if (d.country_code) byCC[d.country_code] = d.count
  const maxCount = Math.max(...data.map((d) => d.count), 1)

  return (
    <div>
      {/* viewBox crops the empty poles (Antarctica / high Arctic) */}
      <svg viewBox="0 12 720 296" style={{ width: '100%', height: 'auto', display: 'block' }}
        role="img" aria-label="World login distribution map">
        <rect x="0" y="12" width="720" height="296" fill="rgba(93,202,165,0.03)" rx="6" />
        {world.map((geo) => {
          const count = byCC[geo.a2] ?? 0
          const ratio = count / maxCount
          return (
            <path key={geo.a2} d={countryPath(geo)}
              fill={count ? heatColor(ratio) : 'rgba(0,0,0,0.05)'}
              stroke="white" strokeWidth={0.3}
              style={{ cursor: count ? 'pointer' : 'default', transition: 'fill 0.2s' }}>
              <title>{flagEmoji(geo.a2)} {geo.a2}{count ? ` · ${count.toLocaleString()} logins` : ' · no logins'}</title>
            </path>
          )
        })}
      </svg>
      <p className="text-[11px] mt-2" style={{ color: 'var(--clavex-neutral)' }}>
        Countries shaded by login volume · hover a country for its count
      </p>
    </div>
  )
}

// ── Anomaly feed ──────────────────────────────────────────────────────────────

function AnomalyFeed({ alerts, recentLogins }: { alerts: ImpossibleTravelAlert[]; recentLogins: LoginEntry[] }) {
  // Merge impossible-travel + high-risk logins into a single chronological feed
  const items: Array<{ type: 'travel' | 'datacenter' | 'new_country' | 'high_risk'; text: string; sub: string; ts: string; color: string }> = []

  for (const a of alerts) {
    items.push({
      type: 'travel',
      text: `Impossible travel detected`,
      sub: `${a.email} · ${flagEmoji(a.country1)} ${a.country1} → ${flagEmoji(a.country2)} ${a.country2}`,
      ts: a.occurred_at,
      color: '#f87171',
    })
  }

  for (const l of recentLogins) {
    if (!l.success && l.asn_org?.toLowerCase().includes('cloud')) {
      items.push({
        type: 'datacenter',
        text: `Login attempt from datacenter ASN`,
        sub: `${l.ip_address} · ${l.asn_org} · ${flagEmoji(l.country_code)}`,
        ts: l.created_at,
        color: '#fbbf24',
      })
    }
    if (l.risk_score && l.risk_score >= 70) {
      items.push({
        type: 'high_risk',
        text: `High-risk login (score ${l.risk_score})`,
        sub: `${l.email ?? 'unknown'} · ${l.ip_address} · ${flagEmoji(l.country_code)} ${l.city ?? ''}`,
        ts: l.created_at,
        color: '#f87171',
      })
    }
  }

  items.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime())

  if (items.length === 0) {
    return (
      <div className="text-center py-8" style={{ color: 'var(--clavex-neutral)' }}>
        <ShieldAlert size={24} className="mx-auto mb-2 opacity-30" />
        <p className="text-sm">No anomalies detected in the last 24 hours</p>
      </div>
    )
  }

  return (
    <div className="space-y-2 max-h-64 overflow-y-auto">
      {items.map((item, i) => (
        <div key={i} className="flex items-start gap-3 rounded-lg px-3 py-2.5"
          style={{ background: `${item.color}10`, border: `0.5px solid ${item.color}30` }}>
          <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" style={{ color: item.color }} />
          <div className="min-w-0">
            <p className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>{item.text}</p>
            <p className="text-xs truncate mt-0.5" style={{ color: 'var(--clavex-ink-subtle)' }}>{item.sub}</p>
          </div>
          <span className="text-xs flex-shrink-0 ml-auto" style={{ color: 'var(--clavex-neutral)' }}>{relTime(item.ts)}</span>
        </div>
      ))}
    </div>
  )
}

// ── Sparkline ─────────────────────────────────────────────────────────────────

function Sparkline({ data }: { data: HourlyBucket[] }) {
  if (!data.length) return <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>No data</p>
  const maxLogins = Math.max(...data.map((d) => d.logins), 1)
  const H = 56

  return (
    <div className="flex items-end gap-px" style={{ height: H }}>
      {data.map((d, i) => {
        const loginH = Math.round((d.logins / maxLogins) * H)
        const failH = Math.round((d.failures / maxLogins) * H)
        const hour = new Date(d.hour).getUTCHours().toString().padStart(2, '0') + 'h'
        return (
          <div key={i} className="flex-1 flex flex-col items-center justify-end group relative" style={{ height: H }}>
            <div className="absolute bottom-full mb-1 hidden group-hover:block z-10 pointer-events-none">
              <div className="rounded px-2 py-1 text-[10px] whitespace-nowrap shadow"
                style={{ background: 'var(--clavex-ink)', color: 'white' }}>
                {hour} · {d.logins}↑ {d.failures}✗
              </div>
            </div>
            {d.failures > 0 && (
              <div style={{ width: '100%', height: failH, background: 'rgba(239,68,68,0.5)', borderRadius: '2px 2px 0 0' }} />
            )}
            <div style={{ width: '100%', height: Math.max(loginH - failH, 2), background: 'rgba(93,202,165,0.45)', borderRadius: '2px 2px 0 0' }} />
          </div>
        )
      })}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function LoginIntelligencePage() {
  const orgId = useAuthStore((s) => s.orgId)
  const [summary, setSummary] = useState<RiskSummary | null>(null)
  const [recentLogins, setRecentLogins] = useState<LoginEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)

  const load = useCallback(async () => {
    if (!orgId) return
    setLoading(true)
    try {
      const [riskRes, histRes] = await Promise.all([
        api.get(`/organizations/${orgId}/risk-dashboard`),
        api.get(`/organizations/${orgId}/login-history`, { params: { limit: 50 } }),
      ])
      setSummary(riskRes.data)
      setRecentLogins(toArr<LoginEntry>(histRes.data))
      setUpdatedAt(new Date())
    } catch {
      toast.error('Failed to load login intelligence data')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { load() }, [load])

  // Auto-refresh every 60 s
  useEffect(() => {
    const t = setInterval(load, 60_000)
    return () => clearInterval(t)
  }, [load])

  const totalLogins = summary?.country_breakdown.reduce((a, c) => a + c.count, 0) ?? 0
  const totalFailed = recentLogins.filter((l) => !l.success).length
  const uniqueIPs = new Set(recentLogins.map((l) => l.ip_address).filter(Boolean)).size

  // Build top failed IPs from local data if not in API response
  const topFailedIPs: TopFailedIP[] = summary?.top_failed_ips ?? (() => {
    const ipMap: Record<string, TopFailedIP> = {}
    for (const l of recentLogins) {
      if (!l.success && l.ip_address) {
        if (!ipMap[l.ip_address]) ipMap[l.ip_address] = { ip: l.ip_address, count: 0, country_code: l.country_code, asn_org: l.asn_org }
        ipMap[l.ip_address].count++
      }
    }
    return Object.values(ipMap).sort((a, b) => b.count - a.count).slice(0, 10)
  })()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>Login Intelligence</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
            Geographic heatmap · anomaly signals · failed IP feed
            {updatedAt && <span className="ml-2" style={{ color: 'var(--clavex-neutral)' }}>· Updated {updatedAt.toLocaleTimeString()}</span>}
          </p>
        </div>
        <button onClick={load} disabled={loading}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm"
          style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {loading && !summary ? (
        <div className="flex items-center justify-center py-24">
          <RefreshCw size={24} className="animate-spin" style={{ color: 'var(--clavex-primary)' }} />
        </div>
      ) : (
        <>
          {/* KPI strip */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { icon: TrendingUp, label: 'Total logins', value: totalLogins.toLocaleString(), color: 'var(--clavex-primary)' },
              { icon: ShieldAlert, label: 'Failed logins', value: totalFailed.toLocaleString(), color: '#f87171' },
              { icon: Wifi, label: 'Unique IPs', value: uniqueIPs.toLocaleString(), color: '#a78bfa' },
              { icon: AlertTriangle, label: 'Anomalies', value: (summary?.impossible_travel_alerts.length ?? 0).toLocaleString(), color: '#fbbf24' },
            ].map(({ icon: Icon, label, value, color }) => (
              <div key={label} style={card} className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                  style={{ background: `${color}18` }}>
                  <Icon size={16} style={{ color }} />
                </div>
                <div>
                  <p className="text-xl font-bold" style={{ color: 'var(--clavex-ink)' }}>{value}</p>
                  <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>{label}</p>
                </div>
              </div>
            ))}
          </div>

          {/* World map */}
          <div style={card}>
            <h2 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--clavex-ink)' }}>
              <MapPin size={14} style={{ color: 'var(--clavex-primary)' }} /> Geographic distribution
            </h2>
            <WorldChoropleth data={summary?.country_breakdown ?? []} />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {/* Geographic heatmap */}
            <div style={card}>
              <h2 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--clavex-ink)' }}>
                <MapPin size={14} style={{ color: 'var(--clavex-primary)' }} /> Geographic heatmap
              </h2>
              <CountryHeatmap data={summary?.country_breakdown ?? []} />
            </div>

            {/* Anomaly feed */}
            <div style={card}>
              <h2 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--clavex-ink)' }}>
                <AlertTriangle size={14} style={{ color: '#fbbf24' }} /> Anomaly signals
              </h2>
              <AnomalyFeed
                alerts={summary?.impossible_travel_alerts ?? []}
                recentLogins={recentLogins}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {/* Hourly trend */}
            <div style={card}>
              <h2 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--clavex-ink)' }}>
                <Clock size={14} style={{ color: 'var(--clavex-primary)' }} /> Login volume · last 24 h
                <span className="ml-auto flex items-center gap-2 text-xs font-normal" style={{ color: 'var(--clavex-neutral)' }}>
                  <span className="w-2 h-2 rounded-sm inline-block" style={{ background: 'rgba(93,202,165,0.45)' }} /> logins
                  <span className="w-2 h-2 rounded-sm inline-block" style={{ background: 'rgba(239,68,68,0.5)' }} /> failures
                </span>
              </h2>
              <Sparkline data={summary?.hourly_trend ?? []} />
            </div>

            {/* Top failed IPs */}
            <div style={card}>
              <h2 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--clavex-ink)' }}>
                <Wifi size={14} style={{ color: '#f87171' }} /> Top failed login IPs
              </h2>
              {topFailedIPs.length === 0 ? (
                <p className="text-sm text-center py-8" style={{ color: 'var(--clavex-neutral)' }}>No failed logins recorded</p>
              ) : (
                <div className="space-y-1.5">
                  {topFailedIPs.map((ip, i) => (
                    <div key={ip.ip} className="flex items-center gap-3">
                      <span className="text-xs w-4 text-right flex-shrink-0" style={{ color: 'var(--clavex-neutral)' }}>{i + 1}</span>
                      <span className="font-mono text-xs flex-1 truncate" style={{ color: 'var(--clavex-ink)' }}>{ip.ip}</span>
                      {ip.country_code && <span className="text-sm">{flagEmoji(ip.country_code)}</span>}
                      {ip.asn_org && (
                        <span className="text-xs truncate max-w-[120px]" style={{ color: 'var(--clavex-neutral)' }} title={ip.asn_org}>
                          {ip.asn_org}
                        </span>
                      )}
                      <span className="ml-auto text-xs font-semibold flex-shrink-0 px-2 py-0.5 rounded-full"
                        style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171' }}>
                        {ip.count} fails
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Recent login activity table */}
          <div style={card}>
            <h2 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--clavex-ink)' }}>
              <User size={14} style={{ color: 'var(--clavex-primary)' }} /> Recent login events
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                    {['Status', 'User', 'IP', 'Country', 'ASN', 'Time'].map((h) => (
                      <th key={h} className="text-left pb-2 pr-4 font-medium text-xs uppercase tracking-wide" style={{ color: 'var(--clavex-ink-muted)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {recentLogins.slice(0, 20).map((l) => (
                    <tr key={l.id} style={{ borderBottom: '0.5px solid var(--clavex-border-subtle)' }}>
                      <td className="py-2 pr-4">
                        <span className="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 rounded"
                          style={{ background: l.success ? 'rgba(93,202,165,0.12)' : 'rgba(239,68,68,0.1)', color: l.success ? 'var(--clavex-primary)' : '#f87171' }}>
                          {l.success ? '✓' : '✗'} {l.success ? 'OK' : 'FAIL'}
                        </span>
                      </td>
                      <td className="py-2 pr-4 text-xs truncate max-w-[140px]" style={{ color: 'var(--clavex-ink)' }}>{l.email ?? '—'}</td>
                      <td className="py-2 pr-4 font-mono text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>{l.ip_address ?? '—'}</td>
                      <td className="py-2 pr-4 text-sm">{flagEmoji(l.country_code)} <span className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>{l.country_code}</span></td>
                      <td className="py-2 pr-4 text-xs truncate max-w-[120px]" style={{ color: 'var(--clavex-neutral)' }} title={l.asn_org}>{l.asn_org ?? '—'}</td>
                      <td className="py-2 text-xs" style={{ color: 'var(--clavex-neutral)', whiteSpace: 'nowrap' }}>{relTime(l.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
