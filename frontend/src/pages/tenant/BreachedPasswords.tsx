import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { ShieldAlert, ShieldX, AlertTriangle, RefreshCw, User, ChevronLeft, ChevronRight } from 'lucide-react'

interface BreachUserEntry {
  user_id: string
  email: string
  first_name?: string
  last_name?: string
  is_active: boolean
  last_login_at?: string
  last_breach_detected_at?: string
  breach_category?: string
  hibp_count?: number
}

interface BreachCategoryCount {
  category: string
  count: number
}

interface BreachDashboard {
  users_action_required: number
  blocked_30d: number
  warned_30d: number
  force_reset_30d: number
  total_detected: number
  category_breakdown: BreachCategoryCount[]
  users_at_risk: BreachUserEntry[]
  page: number
  per_page: number
  total_users: number
}

const PER_PAGE = 20

const CATEGORY_LABELS: Record<string, { label: string; color: string; bg: string }> = {
  exact_match:      { label: 'Exact match',      color: '#dc2626', bg: '#fee2e2' },
  common_password:  { label: 'Common password',  color: '#d97706', bg: '#fef3c7' },
  sub_address:      { label: 'Sub-address leak', color: '#7c3aed', bg: '#ede9fe' },
}

function CategoryBreakdown({ breakdown }: { breakdown: BreachCategoryCount[] }) {
  if (!breakdown || breakdown.length === 0) return null
  const total = breakdown.reduce((s, b) => s + b.count, 0)
  return (
    <div style={{ ...cardStyle, marginBottom: 20 }}>
      <h2 style={{ fontSize: 13, fontWeight: 600, margin: '0 0 12px', color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
        Breach categories
      </h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {breakdown.map(b => {
          const meta = CATEGORY_LABELS[b.category] ?? { label: b.category, color: '#64748b', bg: '#f1f5f9' }
          const pct = total > 0 ? Math.round((b.count / total) * 100) : 0
          return (
            <div key={b.category}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                <span>
                  <span style={{ display: 'inline-block', padding: '2px 8px', borderRadius: 12, background: meta.bg, color: meta.color, fontSize: 11, fontWeight: 500 }}>
                    {meta.label}
                  </span>
                </span>
                <span style={{ color: 'var(--clavex-neutral)' }}>{b.count.toLocaleString()} ({pct}%)</span>
              </div>
              <div style={{ height: 6, background: 'var(--clavex-border)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: meta.color, borderRadius: 3, transition: 'width 0.4s' }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

const cardStyle: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType
  label: string
  value: number
  color: string
}) {
  return (
    <div style={{ ...cardStyle, display: 'flex', alignItems: 'center', gap: 16 }}>
      <div
        style={{
          width: 40,
          height: 40,
          borderRadius: 8,
          background: color + '18',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}
      >
        <Icon size={20} color={color} />
      </div>
      <div>
        <p style={{ fontSize: 22, fontWeight: 700, margin: 0, color: 'var(--clavex-text)' }}>{value.toLocaleString()}</p>
        <p style={{ fontSize: 12, margin: 0, color: 'var(--clavex-neutral)' }}>{label}</p>
      </div>
    </div>
  )
}

function formatDate(iso?: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export default function BreachedPasswords() {
  const { orgId } = useAuthStore()
  const [page, setPage] = useState(1)

  const { data, isLoading, refetch, isFetching } = useQuery<BreachDashboard>({
    queryKey: ['breached-passwords', orgId, page],
    queryFn: async () => {
      const res = await api.get(`/organizations/${orgId}/security/breached-passwords`, {
        params: { page, per_page: PER_PAGE },
      })
      return res.data
    },
    enabled: !!orgId,
    staleTime: 60_000,
  })

  const handleRefresh = useCallback(() => {
    refetch().catch(() => toast.error('Failed to refresh'))
  }, [refetch])

  const totalPages = data ? Math.ceil((data.total_users || 0) / PER_PAGE) : 1

  return (
    <div style={{ padding: '32px 40px', maxWidth: 1100 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <ShieldAlert size={24} color="var(--clavex-danger, #e53e3e)" />
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--clavex-text)' }}>
              Breached Passwords
            </h1>
            <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
              Users with passwords found in known data breaches (HIBP)
            </p>
          </div>
        </div>
        <button
          onClick={handleRefresh}
          disabled={isFetching}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '7px 14px', borderRadius: 8,
            border: '0.5px solid var(--clavex-border)', background: 'white',
            cursor: isFetching ? 'not-allowed' : 'pointer',
            fontSize: 13, color: 'var(--clavex-text)',
          }}
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {isLoading && !data ? (
        <p style={{ color: 'var(--clavex-neutral)', fontSize: 14 }}>Loading…</p>
      ) : data ? (
        <>
          {/* Summary cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 20 }}>
            <StatCard icon={ShieldX} label="Total detections (all time)" value={data.total_detected ?? 0} color="#e53e3e" />
            <StatCard icon={ShieldX} label="Action required (force reset)" value={data.users_action_required} color="#c53030" />
            <StatCard icon={AlertTriangle} label="Logins blocked (30d)" value={data.blocked_30d} color="#dd6b20" />
            <StatCard icon={AlertTriangle} label="Warnings shown (30d)" value={data.warned_30d} color="#d69e2e" />
            <StatCard icon={ShieldAlert} label="Force-reset triggered (30d)" value={data.force_reset_30d} color="#805ad5" />
          </div>

          {/* Category breakdown */}
          {data.category_breakdown && data.category_breakdown.length > 0 && (
            <CategoryBreakdown breakdown={data.category_breakdown} />
          )}

          {/* At-risk user table */}
          <div style={cardStyle}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <h2 style={{ fontSize: 15, fontWeight: 600, margin: 0, color: 'var(--clavex-text)' }}>
                Users at risk
                {(data.total_users ?? 0) > 0 && (
                  <span style={{ marginLeft: 8, fontSize: 12, fontWeight: 500, background: '#fed7d7', color: '#c53030', borderRadius: 12, padding: '2px 8px' }}>
                    {(data.total_users).toLocaleString()}
                  </span>
                )}
              </h2>
              {totalPages > 1 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>Page {data.page} of {totalPages}</span>
                  <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                    style={{ padding: '4px 8px', borderRadius: 6, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: page <= 1 ? 'not-allowed' : 'pointer', opacity: page <= 1 ? 0.4 : 1 }}>
                    <ChevronLeft size={14} />
                  </button>
                  <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
                    style={{ padding: '4px 8px', borderRadius: 6, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: page >= totalPages ? 'not-allowed' : 'pointer', opacity: page >= totalPages ? 0.4 : 1 }}>
                    <ChevronRight size={14} />
                  </button>
                </div>
              )}
            </div>

            {data.users_at_risk.length === 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, padding: '32px 0', color: 'var(--clavex-neutral)' }}>
                <ShieldAlert size={32} style={{ opacity: 0.3 }} />
                <p style={{ fontSize: 14, margin: 0 }}>No users currently require a password reset</p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <thead>
                    <tr style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                      {['User', 'Category', 'HIBP count', 'Status', 'Last login', 'Breach detected'].map(h => (
                        <th key={h} style={{ textAlign: 'left', padding: '0 12px 10px', color: 'var(--clavex-neutral)', fontWeight: 500 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {data.users_at_risk.map(u => {
                      const catMeta = u.breach_category ? (CATEGORY_LABELS[u.breach_category] ?? { label: u.breach_category, color: '#64748b', bg: '#f1f5f9' }) : null
                      return (
                        <tr key={u.user_id} style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                          <td style={{ padding: '12px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                              <div style={{ width: 30, height: 30, borderRadius: '50%', background: '#fed7d720', border: '1px solid #fed7d7', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <User size={14} color="#c53030" />
                              </div>
                              <div>
                                <p style={{ margin: 0, fontWeight: 500, color: 'var(--clavex-text)' }}>
                                  {[u.first_name, u.last_name].filter(Boolean).join(' ') || u.email}
                                </p>
                                {(u.first_name || u.last_name) && (
                                  <p style={{ margin: 0, fontSize: 11, color: 'var(--clavex-neutral)' }}>{u.email}</p>
                                )}
                              </div>
                            </div>
                          </td>
                          <td style={{ padding: '12px' }}>
                            {catMeta ? (
                              <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 12, background: catMeta.bg, color: catMeta.color, fontWeight: 500 }}>
                                {catMeta.label}
                              </span>
                            ) : <span style={{ color: 'var(--clavex-neutral)' }}>—</span>}
                          </td>
                          <td style={{ padding: '12px', color: 'var(--clavex-neutral)' }}>{u.hibp_count != null ? u.hibp_count.toLocaleString() : '—'}</td>
                          <td style={{ padding: '12px' }}>
                            <span style={{ fontSize: 11, fontWeight: 500, padding: '3px 8px', borderRadius: 12, background: u.is_active ? '#fed7d7' : '#e2e8f0', color: u.is_active ? '#c53030' : '#4a5568' }}>
                              {u.is_active ? 'Force reset pending' : 'Suspended'}
                            </span>
                          </td>
                          <td style={{ padding: '12px', color: 'var(--clavex-neutral)' }}>{formatDate(u.last_login_at)}</td>
                          <td style={{ padding: '12px', color: 'var(--clavex-neutral)' }}>{formatDate(u.last_breach_detected_at)}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16, paddingTop: 16, borderTop: '0.5px solid var(--clavex-border)' }}>
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                  style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 14px', borderRadius: 8, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: page <= 1 ? 'not-allowed' : 'pointer', opacity: page <= 1 ? 0.4 : 1, fontSize: 13 }}>
                  <ChevronLeft size={14} /> Previous
                </button>
                <span style={{ display: 'flex', alignItems: 'center', fontSize: 12, color: 'var(--clavex-neutral)', padding: '0 8px' }}>{page} / {totalPages}</span>
                <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
                  style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 14px', borderRadius: 8, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: page >= totalPages ? 'not-allowed' : 'pointer', opacity: page >= totalPages ? 0.4 : 1, fontSize: 13 }}>
                  Next <ChevronRight size={14} />
                </button>
              </div>
            )}
          </div>
        </>
      ) : null}
    </div>
  )
}
