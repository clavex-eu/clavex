import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import { Activity, RefreshCw } from 'lucide-react'
import { Badge, Button, Card, PageHeader, Spinner } from '@/components/ui'

interface ClientLifecycleItem {
  client_id: string
  name: string
  is_active: boolean
  grant_types: string[]
  last_used_at?: string
  days_since_use?: number
  staleness_signal: 'active' | 'stale' | 'never_used' | 'unknown'
  created_at: string
}

interface GroupLifecycleItem {
  id: string
  name: string
  member_count: number
  last_activity_at?: string
  days_since_use?: number
  staleness_signal: 'active' | 'stale' | 'empty' | 'unknown'
  created_at: string
}

interface LifecycleReport {
  org_id: string
  generated_at: string
  clients: ClientLifecycleItem[]
  groups: GroupLifecycleItem[]
}

const signalBadge: Record<string, { variant: 'green' | 'yellow' | 'red' | 'gray'; label: string }> = {
  active:     { variant: 'green',  label: 'Active' },
  stale:      { variant: 'yellow', label: 'Stale' },
  never_used: { variant: 'red',    label: 'Never used' },
  empty:      { variant: 'red',    label: 'Empty' },
  unknown:    { variant: 'gray',   label: 'Unknown' },
}

function fmt(iso?: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

export default function LifecycleReportPage() {
  const orgId = useAuthStore((s) => s.orgId)

  const { data, isLoading, dataUpdatedAt, refetch, isFetching } = useQuery<LifecycleReport>({
    queryKey: ['lifecycle-report', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/lifecycle-report`).then((r) => r.data),
    enabled: !!orgId,
    staleTime: 5 * 60 * 1000,
  })

  if (isLoading) return <Spinner />

  const clients = data?.clients ?? []
  const groups  = data?.groups  ?? []

  return (
    <div className="space-y-6">
      <PageHeader
        title="Lifecycle Report"
        subtitle="Identify stale OIDC clients and empty groups to keep your tenant clean."
        action={
          <Button
            variant="secondary"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            {dataUpdatedAt ? `Last: ${new Date(dataUpdatedAt).toLocaleTimeString()}` : 'Refresh'}
          </Button>
        }
      />

      {/* ── OIDC Clients ───────────────────────────────────────────────── */}
      <Card className="overflow-hidden">
        <div className="flex items-center gap-3 px-6 py-4" style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
          <div
            className="flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0"
            style={{ background: 'rgba(93,202,165,0.12)' }}
          >
            <Activity size={16} style={{ color: 'var(--clavex-accent, #5DCAA5)' }} />
          </div>
          <div>
            <p className="text-sm font-semibold">OIDC Clients</p>
            <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>{clients.length} client(s) in report</p>
          </div>
        </div>

        {clients.length === 0 ? (
          <p className="text-sm text-center py-10" style={{ color: 'var(--clavex-ink-subtle)' }}>No client data available.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--clavex-surface)' }}>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Client</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Status</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Staleness</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Last used</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Days idle</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Grant types</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Created</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => {
                  const sig = signalBadge[c.staleness_signal] ?? signalBadge.unknown
                  return (
                    <tr key={c.client_id} style={{ borderTop: '0.5px solid var(--clavex-border)' }}>
                      <td className="px-5 py-3">
                        <p className="font-medium text-xs">{c.name || c.client_id}</p>
                        <p className="text-[11px] font-mono" style={{ color: 'var(--clavex-ink-subtle)' }}>{c.client_id}</p>
                      </td>
                      <td className="px-5 py-3">
                        <Badge variant={c.is_active ? 'green' : 'gray'}>{c.is_active ? 'Enabled' : 'Disabled'}</Badge>
                      </td>
                      <td className="px-5 py-3">
                        <Badge variant={sig.variant}>{sig.label}</Badge>
                      </td>
                      <td className="px-5 py-3 text-xs">{fmt(c.last_used_at)}</td>
                      <td className="px-5 py-3 text-xs">{c.days_since_use != null ? `${c.days_since_use}d` : '—'}</td>
                      <td className="px-5 py-3">
                        <div className="flex flex-wrap gap-1">
                          {c.grant_types.map((g) => (
                            <span key={g} className="text-[10px] rounded px-1.5 py-0.5 font-mono" style={{ background: 'var(--clavex-surface)', color: 'var(--clavex-ink-subtle)' }}>{g}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-5 py-3 text-xs">{fmt(c.created_at)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* ── Groups ─────────────────────────────────────────────────────── */}
      <Card className="overflow-hidden">
        <div className="flex items-center gap-3 px-6 py-4" style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
          <div
            className="flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0"
            style={{ background: 'rgba(93,202,165,0.12)' }}
          >
            <Activity size={16} style={{ color: 'var(--clavex-accent, #5DCAA5)' }} />
          </div>
          <div>
            <p className="text-sm font-semibold">Groups</p>
            <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>{groups.length} group(s) in report</p>
          </div>
        </div>

        {groups.length === 0 ? (
          <p className="text-sm text-center py-10" style={{ color: 'var(--clavex-ink-subtle)' }}>No group data available.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--clavex-surface)' }}>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Group</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Members</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Staleness</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Last activity</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Days idle</th>
                  <th className="text-left px-5 py-2.5 text-xs font-semibold">Created</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => {
                  const sig = signalBadge[g.staleness_signal] ?? signalBadge.unknown
                  return (
                    <tr key={g.id} style={{ borderTop: '0.5px solid var(--clavex-border)' }}>
                      <td className="px-5 py-3">
                        <p className="font-medium text-xs">{g.name}</p>
                        <p className="text-[11px] font-mono" style={{ color: 'var(--clavex-ink-subtle)' }}>{g.id}</p>
                      </td>
                      <td className="px-5 py-3 text-xs">{g.member_count}</td>
                      <td className="px-5 py-3">
                        <Badge variant={sig.variant}>{sig.label}</Badge>
                      </td>
                      <td className="px-5 py-3 text-xs">{fmt(g.last_activity_at)}</td>
                      <td className="px-5 py-3 text-xs">{g.days_since_use != null ? `${g.days_since_use}d` : '—'}</td>
                      <td className="px-5 py-3 text-xs">{fmt(g.created_at)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
