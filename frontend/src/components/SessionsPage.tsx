import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Monitor, Trash2, RefreshCw, UserX } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Button, Badge, EmptyState, PageHeader } from '@/components/ui'

interface ActiveSession {
  id: string
  org_id: string
  client_id: string
  user_id?: string
  family_id: string
  scope: string
  expires_at: string
  created_at: string
}

function scopeBadges(scope: string) {
  return scope.split(' ').filter(Boolean).map((s) => (
    <Badge key={s} variant="blue" className="text-xs">{s}</Badge>
  ))
}

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function expiresAt(iso: string) {
  const d = new Date(iso)
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
}

export default function SessionsPage({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [revoking, setRevoking] = useState<string | null>(null)

  const { data: sessions = [], isLoading } = useQuery<ActiveSession[]>({
    queryKey: ['sessions', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/sessions`).then((r) => Array.isArray(r.data) ? r.data : (r.data?.items ?? [])),
    enabled: !!orgId,
  })

  const revokeSingle = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/sessions/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sessions', orgId] })
      toast.success('Session revoked')
    },
    onError: () => toast.error('Failed to revoke session'),
    onSettled: () => setRevoking(null),
  })

  const handleRevoke = (id: string) => {
    setRevoking(id)
    revokeSingle.mutate(id)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Active Sessions"
        subtitle="All live refresh tokens for this organization"
        action={
          <Button
            variant="secondary"
            onClick={() => qc.invalidateQueries({ queryKey: ['sessions', orgId] })}
          >
            <RefreshCw className="h-4 w-4 mr-1.5" />
            Refresh
          </Button>
        }
      />

      {isLoading ? (
        <div style={{ padding: '48px 0', textAlign: 'center', color: 'var(--clavex-ink-muted)' }}>
          Loading sessions…
        </div>
      ) : sessions.length === 0 ? (
        <EmptyState
          icon={Monitor}
          title="No active sessions"
          message="Sessions appear here when end users authenticate via registered OIDC clients. Admin console logins are not shown."
        />
      ) : (
        <div className="overflow-x-auto rounded-xl" style={{ border: '0.5px solid var(--clavex-border)' }}>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '0.5px solid var(--clavex-border)', background: 'var(--clavex-surface-2)' }}>
                {['Client', 'User', 'Scopes', 'Created', 'Expires', ''].map((h) => (
                  <th
                    key={h}
                    className="text-left px-4 py-3"
                    style={{ fontWeight: 600, fontSize: 11, letterSpacing: '0.05em', color: 'var(--clavex-ink-muted)', textTransform: 'uppercase' }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr
                  key={s.id}
                  style={{ borderBottom: '0.5px solid var(--clavex-border)' }}
                  className="hover:bg-[var(--clavex-surface-2)] transition-colors"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div
                        className="h-7 w-7 rounded-lg flex items-center justify-center flex-shrink-0"
                        style={{ background: 'rgba(29,158,117,0.1)', border: '0.5px solid rgba(29,158,117,0.2)' }}
                      >
                        <Monitor className="h-3.5 w-3.5" style={{ color: 'var(--clavex-primary)' }} />
                      </div>
                      <span
                        className="font-mono text-xs"
                        style={{ color: 'var(--clavex-ink)', fontWeight: 500 }}
                      >
                        {s.client_id}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {s.user_id ? (
                      <span className="font-mono text-xs" style={{ color: 'var(--clavex-ink-muted)' }}>
                        {s.user_id.slice(0, 8)}…
                      </span>
                    ) : (
                      <Badge variant="yellow" className="text-xs">M2M</Badge>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">{scopeBadges(s.scope)}</div>
                  </td>
                  <td className="px-4 py-3" style={{ color: 'var(--clavex-ink-muted)', fontSize: 12 }}>
                    {timeAgo(s.created_at)}
                  </td>
                  <td className="px-4 py-3" style={{ color: 'var(--clavex-ink-muted)', fontSize: 12 }}>
                    {expiresAt(s.expires_at)}
                  </td>
                  <td className="px-4 py-3">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handleRevoke(s.id)}
                      disabled={revoking === s.id}
                      title="Revoke this session"
                      style={{ color: 'var(--clavex-error)', padding: '4px 8px' }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {sessions.length > 0 && (
        <p style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>
          {sessions.length} active session{sessions.length !== 1 ? 's' : ''} — showing only non-expired, non-revoked refresh tokens.
        </p>
      )}
    </div>
  )
}

// ── Per-user sessions sub-component ──────────────────────────────────────────

export function UserSessionsPanel({ orgId, userId }: { orgId: string; userId: string }) {
  const qc = useQueryClient()

  const { data: sessions = [], isLoading } = useQuery<ActiveSession[]>({
    queryKey: ['sessions', orgId, userId],
    queryFn: () => api.get(`/organizations/${orgId}/users/${userId}/sessions`).then((r) => r.data),
  })

  const revokeAll = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/users/${userId}/sessions`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sessions', orgId, userId] })
      toast.success('All sessions revoked')
    },
    onError: () => toast.error('Failed to revoke sessions'),
  })

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p style={{ fontWeight: 600, fontSize: 13, color: 'var(--clavex-ink)' }}>
          Active Sessions
        </p>
        {sessions.length > 0 && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => revokeAll.mutate()}
            disabled={revokeAll.isPending}
            style={{ color: 'var(--clavex-error)', fontSize: 12 }}
          >
            <UserX className="h-3.5 w-3.5 mr-1" />
            Revoke all
          </Button>
        )}
      </div>
      {isLoading ? (
        <p style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>Loading…</p>
      ) : sessions.length === 0 ? (
        <p style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>No active sessions.</p>
      ) : (
        <ul className="space-y-1">
          {sessions.map((s) => (
            <li
              key={s.id}
              className="flex items-center justify-between rounded-lg px-3 py-2"
              style={{ background: 'var(--clavex-surface-2)', border: '0.5px solid var(--clavex-border)', fontSize: 12 }}
            >
              <span className="font-mono" style={{ color: 'var(--clavex-ink-muted)' }}>{s.client_id}</span>
              <span style={{ color: 'var(--clavex-ink-muted)' }}>{timeAgo(s.created_at)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
