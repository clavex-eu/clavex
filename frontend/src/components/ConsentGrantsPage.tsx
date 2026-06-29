import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck, Trash2, ChevronDown, ChevronRight, AlertTriangle, ExternalLink } from 'lucide-react'
import toast from 'react-hot-toast'
import api, { toArr } from '@/lib/api'
import { Badge, Button, PageHeader, EmptyState, Spinner, Modal } from '@/components/ui'

// ── Types ─────────────────────────────────────────────────────────────────────

interface AuthDetail {
  type: string
  [key: string]: unknown
}

interface RARGrant {
  id: string
  org_id: string
  user_id: string
  client_id: string
  scope: string
  authorization_details: AuthDetail[]
  granted_at: string
  last_used_at?: string
  revoked_at?: string
  is_active: boolean
}

interface Props {
  orgId: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso?: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

function scopeBadges(scope: string) {
  return scope
    .split(/\s+/)
    .filter(Boolean)
    .map((s) => (
      <Badge key={s} variant="blue" className="font-mono text-[9px]">
        {s}
      </Badge>
    ))
}

// ── AuthDetail card ───────────────────────────────────────────────────────────

function AuthDetailCard({ detail }: { detail: AuthDetail }) {
  const { type, ...rest } = detail
  const [open, setOpen] = useState(false)

  return (
    <div className="rounded-lg border border-gray-200 bg-white overflow-hidden text-sm">
      <button
        className="flex w-full items-center justify-between px-3 py-2 hover:bg-gray-50 transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        <span className="font-semibold text-gray-800">{type}</span>
        {open ? (
          <ChevronDown className="h-4 w-4 text-gray-400" />
        ) : (
          <ChevronRight className="h-4 w-4 text-gray-400" />
        )}
      </button>
      {open && (
        <div className="border-t border-gray-100 bg-gray-50 px-3 py-2">
          <pre className="text-xs text-gray-600 whitespace-pre-wrap break-all">
            {JSON.stringify(rest, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

// ── GrantRow ──────────────────────────────────────────────────────────────────

function GrantRow({
  grant,
  onRevoke,
  revoking,
}: {
  grant: RARGrant
  onRevoke: (id: string) => void
  revoking: boolean
}) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      className={`rounded-xl border transition-colors ${
        grant.is_active
          ? 'border-gray-200 bg-white'
          : 'border-gray-100 bg-gray-50 opacity-60'
      }`}
    >
      {/* Header row */}
      <div className="flex items-start gap-3 px-4 py-3">
        <button
          className="mt-0.5 shrink-0 text-gray-400 hover:text-gray-700"
          onClick={() => setExpanded((v) => !v)}
          title={expanded ? 'Collapse' : 'Expand details'}
        >
          {expanded ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
        </button>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-gray-900 font-mono text-sm">
              {grant.client_id}
            </span>
            {grant.is_active ? (
              <Badge variant="green">Active</Badge>
            ) : (
              <Badge variant="gray">Revoked</Badge>
            )}
          </div>

          <div className="mt-1 flex flex-wrap gap-1">
            {scopeBadges(grant.scope)}
          </div>

          <div className="mt-1.5 grid grid-cols-2 gap-x-6 text-xs text-gray-500">
            <span>
              User: <span className="font-mono">{grant.user_id.slice(0, 8)}…</span>
            </span>
            <span>Granted: {fmtDate(grant.granted_at)}</span>
            <span>
              Last used:{' '}
              {grant.last_used_at ? fmtDate(grant.last_used_at) : 'never'}
            </span>
            {!grant.is_active && grant.revoked_at && (
              <span className="text-red-500">
                Revoked: {fmtDate(grant.revoked_at)}
              </span>
            )}
          </div>

          <div className="mt-1.5 flex items-center gap-1 text-xs text-gray-400">
            <ShieldCheck className="h-3.5 w-3.5 text-[#5DCAA5]" />
            <span>{grant.authorization_details.length} authorization_detail{grant.authorization_details.length !== 1 ? 's' : ''}</span>
          </div>
        </div>

        {grant.is_active && (
          <Button
            variant="danger"
            size="xs"
            loading={revoking}
            onClick={() => onRevoke(grant.id)}
            className="shrink-0"
            title="Revoke this grant"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Revoke
          </Button>
        )}
      </div>

      {/* Expandable detail panel */}
      {expanded && (
        <div className="border-t border-gray-100 px-4 py-3 space-y-2">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
            Authorization details
          </p>
          {grant.authorization_details.length === 0 ? (
            <p className="text-xs text-gray-400 italic">No details recorded.</p>
          ) : (
            grant.authorization_details.map((d, i) => (
              <AuthDetailCard key={i} detail={d} />
            ))
          )}
          <p className="text-xs text-gray-400 pt-1">
            Grant ID: <span className="font-mono">{grant.id}</span>
          </p>
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ConsentGrantsPage({ orgId }: Props) {
  const qc = useQueryClient()
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null)
  const [filter, setFilter] = useState<'all' | 'active' | 'revoked'>('active')

  const { data: grants = [], isLoading } = useQuery<RARGrant[]>({
    queryKey: ['rar-grants', orgId],
    queryFn: () =>
      api.get(`/organizations/${orgId}/grants`).then((r) => toArr(r.data)),
  })

  const revokeMutation = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/organizations/${orgId}/grants/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rar-grants', orgId] })
      toast.success('Grant revoked — the client will lose access on next token check.')
      setConfirmRevoke(null)
    },
    onError: () => toast.error('Failed to revoke grant'),
  })

  const filtered = grants.filter((g) => {
    if (filter === 'active') return g.is_active
    if (filter === 'revoked') return !g.is_active
    return true
  })

  const activeCount = grants.filter((g) => g.is_active).length

  return (
    <div className="space-y-6">
      <PageHeader
        title="Consent Grants"
        subtitle="Manage RFC 9396 (RAR) authorization_details grants. Each entry records what data access a user consented to, for which client. Revoking a grant is immediate and complies with PSD2 §66."
        action={
          activeCount > 0 ? (
            <Badge variant="green">{activeCount} active</Badge>
          ) : null
        }
      />

      {/* PSD2 info banner */}
      <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
        <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-700 space-y-1">
          <p className="font-semibold">PSD2 / Open Banking compliance</p>
          <p>
            Under PSD2 Article 66, users have the right to revoke payment initiation and
            account information access at any time. This dashboard provides granular
            visibility and revocation of each individual authorization_details grant.
          </p>
          <a
            href="https://datatracker.ietf.org/doc/html/rfc9396"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-0.5 underline"
          >
            RFC 9396 — Rich Authorization Requests
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-200 pb-0">
        {(['active', 'revoked', 'all'] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px ${
              filter === f
                ? 'border-[#5DCAA5] text-[#0F6E56]'
                : 'border-transparent text-gray-500 hover:text-gray-800'
            }`}
          >
            {f}
            {f === 'active' && activeCount > 0 && (
              <span className="ml-1.5 inline-flex items-center justify-center rounded-full bg-[#E1F5EE] text-[#0F6E56] text-[10px] font-bold w-4 h-4">
                {activeCount}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="No grants"
          message={
            filter === 'active'
              ? 'No active RAR grants for this organization. Grants are created when a user completes an authorization_code flow with authorization_details.'
              : 'No grants match the selected filter.'
          }
        />
      ) : (
        <div className="space-y-3">
          {filtered.map((g) => (
            <GrantRow
              key={g.id}
              grant={g}
              onRevoke={(id) => setConfirmRevoke(id)}
              revoking={revokeMutation.isPending && confirmRevoke === g.id}
            />
          ))}
        </div>
      )}

      {/* Revoke confirmation modal */}
      <Modal
        open={!!confirmRevoke}
        title="Revoke grant?"
        description="The client will immediately lose access to the consented authorization_details. This action cannot be undone — the user must re-authorize to restore access."
        onClose={() => setConfirmRevoke(null)}
        size="sm"
      >
        <div className="flex justify-end gap-2 mt-4">
          <Button variant="secondary" onClick={() => setConfirmRevoke(null)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            loading={revokeMutation.isPending}
            onClick={() => confirmRevoke && revokeMutation.mutate(confirmRevoke)}
          >
            Revoke grant
          </Button>
        </div>
      </Modal>
    </div>
  )
}
