import { useQuery } from '@tanstack/react-query'
import api, { toArr } from '@/lib/api'
import { Card, PageHeader, EmptyState, Spinner } from '@/components/ui'

interface AuditEntry {
  id: number
  actor_email?: string
  action: string
  resource_type?: string
  resource_id?: string
  ip_address?: string
  status: string
  time: string
}

const STATUS_STYLE: Record<string, React.CSSProperties> = {
  success: { background: '#E1F5EE', color: '#0F6E56' },
  failure: { background: '#FCEBEB', color: '#A32D2D' },
  error:   { background: '#FCEBEB', color: '#A32D2D' },
}

interface Props {
  orgId: string
  breadcrumb?: React.ReactNode
}

export default function AuditLogPage({ orgId, breadcrumb }: Props) {
  const { data: entries = [], isLoading, isError, error } = useQuery<AuditEntry[]>({
    queryKey: ['audit', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/audit`).then((r) => toArr(r.data)),
  })

  return (
    <div>
      {breadcrumb}
      <PageHeader title="Audit Log" />

      {isLoading ? (
        <Spinner />
      ) : isError ? (
        <Card>
          <EmptyState message={`Errore nel caricamento dei log: ${(error as any)?.response?.data?.message ?? (error as any)?.message ?? 'Errore sconosciuto'}`} />
        </Card>
      ) : (
        <Card>
          {entries.length === 0 ? (
            <EmptyState message="No audit events yet." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm" style={{ borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                    <th className="text-left px-6 py-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--clavex-neutral)', width: 160 }}>Time</th>
                    <th className="text-left px-3 py-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--clavex-neutral)', width: 200 }}>Actor</th>
                    <th className="text-left px-3 py-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--clavex-neutral)' }}>Action</th>
                    <th className="text-left px-3 py-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--clavex-neutral)', width: 80 }}>Status</th>
                    <th className="text-left px-3 py-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--clavex-neutral)' }}>Resource</th>
                    <th className="text-right px-6 py-2 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--clavex-neutral)', width: 140 }}>IP</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => (
                    <tr key={e.id} style={{ borderBottom: '0.5px solid var(--clavex-surface)' }} className="hover:bg-[#FAFAF8] transition-colors">
                      <td className="px-6 py-3 text-xs font-mono" style={{ color: 'var(--clavex-neutral)', whiteSpace: 'nowrap' }}>
                        {new Date(e.time).toLocaleString()}
                      </td>
                      <td className="px-3 py-3 max-w-[200px]">
                        <span className="block truncate text-xs font-mono" style={{ color: 'var(--clavex-ink)' }} title={e.actor_email}>{e.actor_email ?? '—'}</span>
                      </td>
                      <td className="px-3 py-3">
                        <span className="font-medium text-xs" style={{ color: 'var(--clavex-ink)' }}>{e.action}</span>
                      </td>
                      <td className="px-3 py-3">
                        <span
                          className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold tracking-wide"
                          style={STATUS_STYLE[e.status] ?? { background: '#F5F4F0', color: '#5F5E5A' }}
                        >
                          {e.status}
                        </span>
                      </td>
                      <td className="px-3 py-3 max-w-[200px]">
                        {e.resource_type && (
                          <span className="text-xs truncate block" style={{ color: 'var(--clavex-neutral)' }} title={`${e.resource_type}${e.resource_id ? ` · ${e.resource_id}` : ''}`}>
                            <span style={{ color: 'var(--clavex-ink)' }}>{e.resource_type}</span>
                            {e.resource_id && <span className="ml-1 font-mono">{e.resource_id}</span>}
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-3 text-right text-xs font-mono" style={{ color: 'var(--clavex-neutral)', whiteSpace: 'nowrap' }}>
                        {e.ip_address ?? ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
