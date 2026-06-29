import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import { Plus, Trash2, ClipboardCheck, X, Play, ChevronDown, ChevronUp, FileText, Users } from 'lucide-react'
import { Button, PageHeader, Card, EmptyState, Spinner } from '@/components/ui'

// ── Types ─────────────────────────────────────────────────────────────────────

type CampaignStatus = 'pending' | 'active' | 'completed' | 'cancelled'
type ItemDecision   = 'pending' | 'approved' | 'revoked' | 'auto_revoked'

interface Campaign {
  id: string
  name: string
  description?: string
  frequency: string
  status: CampaignStatus
  starts_at: string
  ends_at: string
  reminder_days: number[]
  auto_revoke: boolean
  created_by?: string
  created_at: string
  updated_at: string
  // computed
  total_items: number
  pending_items: number
  approved_items: number
  revoked_items: number
}

interface ReviewItem {
  id: string
  campaign_id: string
  user_id: string
  role_id: string
  reviewer_id: string
  decision: ItemDecision
  decided_at?: string
  comment?: string
  user_email: string
  user_name: string
  role_name: string
  reviewer_email: string
  reviewer_name: string
  created_at: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const STATUS_COLORS: Record<CampaignStatus, string> = {
  pending:   'bg-amber-100 text-amber-700',
  active:    'bg-blue-100 text-blue-700',
  completed: 'bg-emerald-100 text-emerald-700',
  cancelled: 'bg-gray-100 text-gray-500',
}

const DECISION_COLORS: Record<ItemDecision, string> = {
  pending:      'bg-amber-100 text-amber-700',
  approved:     'bg-emerald-100 text-emerald-700',
  revoked:      'bg-red-100 text-red-700',
  auto_revoked: 'bg-red-100 text-red-600',
}

function StatusBadge({ status }: { status: CampaignStatus }) {
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full capitalize ${STATUS_COLORS[status]}`}>
      {status}
    </span>
  )
}

function DecisionBadge({ decision }: { decision: ItemDecision }) {
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${DECISION_COLORS[decision]}`}>
      {decision.replace('_', ' ')}
    </span>
  )
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

function ProgressBar({ total, approved, revoked }: { total: number; approved: number; revoked: number; pending: number }) {
  if (total === 0) return <div className="h-1.5 bg-gray-100 rounded-full" />
  const ap = (approved / total) * 100
  const rv = ((approved + revoked) / total) * 100
  return (
    <div className="h-1.5 rounded-full bg-gray-100 overflow-hidden relative">
      <div className="absolute inset-y-0 left-0 bg-emerald-400 rounded-full transition-all" style={{ width: `${ap}%` }} />
      <div className="absolute inset-y-0 bg-red-400 rounded-full transition-all" style={{ left: `${ap}%`, width: `${rv - ap}%` }} />
    </div>
  )
}

// ── Create campaign modal ──────────────────────────────────────────────────────

interface CreateForm {
  name: string
  description: string
  frequency: string
  starts_at: string
  ends_at: string
  reminder_days: string     // comma-separated e.g. "3,1"
  auto_revoke: boolean
}

function CreateCampaignModal({ orgId, onClose }: { orgId: string; onClose: () => void }) {
  const qc = useQueryClient()

  const [form, setForm] = useState<CreateForm>({
    name: '',
    description: '',
    frequency: 'quarterly',
    starts_at: '',
    ends_at: '',
    reminder_days: '3,1',
    auto_revoke: true,
  })

  const save = useMutation({
    mutationFn: () => {
      const days = form.reminder_days
        .split(',')
        .map((d) => parseInt(d.trim(), 10))
        .filter((d) => !isNaN(d) && d > 0)
      return api.post(`/organizations/${orgId}/access-reviews`, {
        name:          form.name,
        description:   form.description || undefined,
        frequency:     form.frequency,
        starts_at:     form.starts_at ? new Date(form.starts_at).toISOString() : undefined,
        ends_at:       form.ends_at   ? new Date(form.ends_at).toISOString()   : undefined,
        reminder_days: days,
        auto_revoke:   form.auto_revoke,
      })
    },
    onSuccess: () => {
      toast.success('Campaign created')
      qc.invalidateQueries({ queryKey: ['access-reviews', orgId] })
      onClose()
    },
    onError: () => toast.error('Create failed'),
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-lg overflow-y-auto max-h-[90vh]">
        <div className="flex items-center justify-between px-6 py-4 border-b">
          <h3 className="text-base font-semibold text-gray-900">New Access Review Campaign</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X className="h-5 w-5" /></button>
        </div>

        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Name *</label>
            <input
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"
              placeholder="e.g. Q2 2026 Access Review"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Description</label>
            <textarea
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400 resize-none"
              rows={2}
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Frequency</label>
              <select
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"
                value={form.frequency}
                onChange={(e) => setForm((f) => ({ ...f, frequency: e.target.value }))}
              >
                <option value="monthly">Monthly</option>
                <option value="quarterly">Quarterly</option>
                <option value="annual">Annual</option>
                <option value="one_time">One-time</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Reminder days before deadline</label>
              <input
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"
                placeholder="3,1"
                value={form.reminder_days}
                onChange={(e) => setForm((f) => ({ ...f, reminder_days: e.target.value }))}
              />
              <p className="text-xs text-gray-400 mt-0.5">Comma-separated number of days before deadline</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Start date *</label>
              <input
                type="datetime-local"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"
                value={form.starts_at}
                onChange={(e) => setForm((f) => ({ ...f, starts_at: e.target.value }))}
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Deadline *</label>
              <input
                type="datetime-local"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"
                value={form.ends_at}
                onChange={(e) => setForm((f) => ({ ...f, ends_at: e.target.value }))}
              />
            </div>
          </div>

          <div className="flex items-center gap-3 pt-1">
            <input
              type="checkbox"
              id="auto_revoke"
              checked={form.auto_revoke}
              onChange={(e) => setForm((f) => ({ ...f, auto_revoke: e.target.checked }))}
              className="h-4 w-4 rounded border-gray-300 text-indigo-600"
            />
            <label htmlFor="auto_revoke" className="text-sm text-gray-700">
              Auto-revoke pending items when deadline passes
            </label>
          </div>
        </div>

        <div className="flex justify-end gap-3 px-6 py-4 border-t bg-gray-50 rounded-b-xl">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900">Cancel</button>
          <button
            onClick={() => {
              if (!form.name.trim())    { toast.error('Name is required'); return }
              if (!form.starts_at)      { toast.error('Start date is required'); return }
              if (!form.ends_at)        { toast.error('Deadline is required'); return }
              save.mutate()
            }}
            disabled={save.isPending}
            style={{ background: 'var(--clavex-primary)', color: 'white', opacity: save.isPending ? 0.6 : 1 }}
            className="px-4 py-2 text-sm font-medium rounded-lg disabled:cursor-not-allowed"
          >
            {save.isPending ? 'Creating…' : 'Create Campaign'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Items drawer ──────────────────────────────────────────────────────────────

function ItemsDrawer({ orgId, campaign, onClose }: { orgId: string; campaign: Campaign; onClose: () => void }) {
  const { data: items = [], isLoading } = useQuery<ReviewItem[]>({
    queryKey: ['access-review-items', campaign.id],
    queryFn: () => api.get(`/organizations/${orgId}/access-reviews/${campaign.id}/items`).then((r) => toArr(r.data)),
  })

  const decisions: ItemDecision[] = ['pending', 'approved', 'revoked', 'auto_revoked']
  const byDecision = (d: ItemDecision) => items.filter((i) => i.decision === d)

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/30">
      <div className="bg-white w-full max-w-2xl flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b">
          <div>
            <h3 className="font-semibold text-gray-900">{campaign.name}</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              {campaign.total_items} items · deadline {fmtDate(campaign.ends_at)}
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X className="h-5 w-5" /></button>
        </div>

        {/* Summary */}
        <div className="grid grid-cols-4 gap-0 border-b text-center">
          {decisions.map((d) => (
            <div key={d} className="py-3 px-2 border-r last:border-r-0">
              <p className="text-lg font-bold text-gray-900">{byDecision(d).length}</p>
              <DecisionBadge decision={d} />
            </div>
          ))}
        </div>

        {/* Item list */}
        <div className="flex-1 overflow-y-auto p-4">
          {isLoading ? (
            <p className="text-sm text-gray-400 text-center py-8">Loading…</p>
          ) : items.length === 0 ? (
            <p className="text-sm text-gray-400 text-center py-8">No items yet — launch the campaign to generate them.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wide border-b">
                  <th className="pb-2 pr-3">User</th>
                  <th className="pb-2 pr-3">Role</th>
                  <th className="pb-2 pr-3">Reviewer</th>
                  <th className="pb-2">Decision</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id} className="border-b last:border-b-0">
                    <td className="py-2 pr-3">
                      <p className="font-medium text-gray-900 truncate max-w-[140px]">{item.user_name || item.user_email}</p>
                      <p className="text-xs text-gray-500 truncate max-w-[140px]">{item.user_email}</p>
                    </td>
                    <td className="py-2 pr-3">
                      <span className="text-xs px-2 py-0.5 rounded font-medium" style={{ background: 'var(--clavex-50)', color: 'var(--clavex-700)' }}>
                        {item.role_name}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-xs text-gray-500 truncate max-w-[120px]">
                      {item.reviewer_name || item.reviewer_email}
                    </td>
                    <td className="py-2">
                      <DecisionBadge decision={item.decision} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Report link */}
        <div className="px-4 py-3 border-t bg-gray-50">
          <a
            href={`/api/v1/organizations/${orgId}/access-reviews/${campaign.id}/report`}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 text-sm font-medium hover:opacity-75 transition-opacity"
            style={{ color: 'var(--clavex-primary)' }}
          >
            <FileText className="h-4 w-4" /> Download Audit Report (JSON)
          </a>
        </div>
      </div>
    </div>
  )
}

// ── Campaign card ─────────────────────────────────────────────────────────────

function CampaignCard({
  campaign,
  orgId,
  onViewItems,
}: {
  campaign: Campaign
  orgId: string
  onViewItems: (c: Campaign) => void
}) {
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)

  const launch = useMutation({
    mutationFn: () => api.post(`/organizations/${orgId}/access-reviews/${campaign.id}/launch`),
    onSuccess: () => {
      toast.success('Campaign launched — items generated and emails sent')
      qc.invalidateQueries({ queryKey: ['access-reviews', orgId] })
    },
    onError: () => toast.error('Launch failed'),
  })

  const cancel = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/access-reviews/${campaign.id}`),
    onSuccess: () => {
      toast.success('Campaign cancelled')
      qc.invalidateQueries({ queryKey: ['access-reviews', orgId] })
    },
    onError: () => toast.error('Cancel failed'),
  })

  const canLaunch = campaign.status === 'pending'
  const canCancel = campaign.status === 'pending' || campaign.status === 'active'

  return (
    <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
      <div
        className="flex items-start gap-3 px-5 py-4 cursor-pointer hover:bg-gray-50"
        onClick={() => setExpanded((v) => !v)}
      >
        {/* Icon */}
        <ClipboardCheck className={`h-5 w-5 mt-0.5 flex-shrink-0 ${campaign.status === 'active' ? 'text-blue-500' : campaign.status === 'completed' ? 'text-emerald-500' : 'text-gray-400'}`} />

        {/* Main info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-gray-900 text-sm">{campaign.name}</span>
            <StatusBadge status={campaign.status} />
            <span className="text-xs text-gray-400 capitalize">{campaign.frequency}</span>
          </div>
          <div className="mt-1 flex items-center gap-3 text-xs text-gray-500">
            <span>{fmtDate(campaign.starts_at)} → {fmtDate(campaign.ends_at)}</span>
            {campaign.auto_revoke && (
              <span className="text-amber-600 font-medium">auto-revoke on</span>
            )}
          </div>

          {/* Progress */}
          {campaign.total_items > 0 && (
            <div className="mt-2 max-w-xs">
              <ProgressBar
                total={campaign.total_items}
                approved={campaign.approved_items}
                revoked={campaign.revoked_items}
                pending={campaign.pending_items}
              />
              <p className="text-xs text-gray-400 mt-1">
                {campaign.pending_items} pending · {campaign.approved_items} approved · {campaign.revoked_items} revoked of {campaign.total_items}
              </p>
            </div>
          )}
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-1 flex-shrink-0" onClick={(e) => e.stopPropagation()}>
          {canLaunch && (
            <button
              onClick={() => {
                if (confirm('Launch this campaign? Items will be generated and emails sent to reviewers.')) {
                  launch.mutate()
                }
              }}
              disabled={launch.isPending}
              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white rounded-lg disabled:opacity-50"
              style={{ background: 'var(--clavex-primary)' }}
              title="Launch campaign"
            >
              <Play className="h-3.5 w-3.5" />
              {launch.isPending ? 'Launching…' : 'Launch'}
            </button>
          )}
          {campaign.status === 'active' && (
            <button
              onClick={() => onViewItems(campaign)}
              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium bg-white border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
            >
              <Users className="h-3.5 w-3.5" />
              Items
            </button>
          )}
          {campaign.status === 'completed' && (
            <button
              onClick={() => onViewItems(campaign)}
              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium bg-white border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
            >
              <FileText className="h-3.5 w-3.5" />
              Report
            </button>
          )}
          {canCancel && (
            <button
              onClick={() => {
                if (confirm(`Cancel campaign "${campaign.name}"?`)) cancel.mutate()
              }}
              disabled={cancel.isPending}
              className="p-1.5 rounded hover:bg-red-50 text-gray-400 hover:text-red-600"
              title="Cancel campaign"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {expanded ? <ChevronUp className="h-4 w-4 text-gray-400 flex-shrink-0 mt-1" /> : <ChevronDown className="h-4 w-4 text-gray-400 flex-shrink-0 mt-1" />}
      </div>

      {expanded && campaign.description && (
        <div className="px-5 py-3 border-t bg-gray-50 text-sm text-gray-600">
          {campaign.description}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AccessReviewsPage({ orgId }: { orgId: string }) {
  const [showCreate, setShowCreate] = useState(false)
  const [viewItems, setViewItems] = useState<Campaign | null>(null)

  const { data: campaigns = [], isLoading } = useQuery<Campaign[]>({
    queryKey: ['access-reviews', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/access-reviews`).then((r) => toArr(r.data)),
    refetchInterval: 30_000,
  })

  const active    = campaigns.filter((c) => c.status === 'active')
  const pending   = campaigns.filter((c) => c.status === 'pending')
  const closed    = campaigns.filter((c) => c.status === 'completed' || c.status === 'cancelled')

  return (
    <div>
      <PageHeader
        title="Access Reviews"
        subtitle="Periodic certification campaigns — managers certify their team's role assignments."
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" /> New Campaign
          </Button>
        }
      />

      {/* Summary stats */}
      {campaigns.length > 0 && (
        <div className="grid grid-cols-3 gap-4 mb-6">
          <Card className="px-5 py-4">
            <p className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--clavex-neutral)' }}>Active</p>
            <p className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>{active.length}</p>
          </Card>
          <Card className="px-5 py-4">
            <p className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--clavex-neutral)' }}>Pending launch</p>
            <p className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>{pending.length}</p>
          </Card>
          <Card className="px-5 py-4">
            <p className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--clavex-neutral)' }}>Closed</p>
            <p className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>{closed.length}</p>
          </Card>
        </div>
      )}

      {/* Campaign list */}
      {isLoading ? (
        <Spinner />
      ) : campaigns.length === 0 ? (
        <Card>
          <EmptyState icon={ClipboardCheck} title="No access review campaigns yet" message="Create a campaign to start certifying role assignments across your organisation." />
        </Card>
      ) : (
        <div className="space-y-6">
          {active.length > 0 && (
            <section>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Active ({active.length})</p>
              <div className="space-y-3">
                {active.map((c) => (
                  <CampaignCard key={c.id} campaign={c} orgId={orgId} onViewItems={setViewItems} />
                ))}
              </div>
            </section>
          )}
          {pending.length > 0 && (
            <section>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Pending Launch ({pending.length})</p>
              <div className="space-y-3">
                {pending.map((c) => (
                  <CampaignCard key={c.id} campaign={c} orgId={orgId} onViewItems={setViewItems} />
                ))}
              </div>
            </section>
          )}
          {closed.length > 0 && (
            <section>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Closed ({closed.length})</p>
              <div className="space-y-3">
                {closed.map((c) => (
                  <CampaignCard key={c.id} campaign={c} orgId={orgId} onViewItems={setViewItems} />
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {/* Modals / drawers */}
      {showCreate && <CreateCampaignModal orgId={orgId} onClose={() => setShowCreate(false)} />}
      {viewItems && <ItemsDrawer orgId={orgId} campaign={viewItems} onClose={() => setViewItems(null)} />}
    </div>
  )
}
