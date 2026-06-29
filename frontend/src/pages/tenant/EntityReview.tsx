import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import {
  ClipboardList, Plus, X, ChevronRight, ChevronDown,
  CheckCircle, XCircle, AlertCircle, Clock,
  Play, Ban, Loader2, RefreshCw,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

type EntityType = 'client' | 'group' | 'role'
type CampaignStatus = 'pending' | 'active' | 'completed' | 'cancelled'
type Decision = 'confirmed' | 'deprecated' | ''

interface Campaign {
  id: string
  org_id: string
  name: string
  description?: string
  entity_type: EntityType
  frequency_days: number
  starts_at: string
  ends_at: string
  reminder_days: number[]
  auto_disable: boolean
  status: CampaignStatus
  created_by?: string
  created_at: string
  total_items: number
  pending_items: number
  confirmed_items: number
  deprecated_items: number
}

interface ReviewItem {
  id: string
  campaign_id: string
  entity_type: EntityType
  entity_id: string
  entity_name: string
  reviewer_id: string
  decision: Decision
  comment?: string
  decided_at?: string
  review_token: string
}

// ── Shared styles ─────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}
const inp: React.CSSProperties = {
  background: 'white',
  color: 'var(--clavex-ink)',
  border: '0.5px solid var(--clavex-border-subtle)',
  borderRadius: 8,
  padding: '7px 11px',
  fontSize: 13,
  outline: 'none',
  width: '100%',
}
const lbl: React.CSSProperties = {
  display: 'block',
  fontSize: 11,
  fontWeight: 600,
  textTransform: 'uppercase' as const,
  letterSpacing: '0.06em',
  color: 'var(--clavex-ink-muted)',
  marginBottom: 4,
}
const btn = (variant: 'primary' | 'ghost' | 'danger' = 'primary'): React.CSSProperties => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  padding: '7px 14px',
  borderRadius: 8,
  fontSize: 13,
  fontWeight: 600,
  cursor: 'pointer',
  border: variant === 'ghost' ? '0.5px solid var(--clavex-border-subtle)' : 'none',
  background:
    variant === 'primary' ? 'var(--clavex-primary)'
    : variant === 'danger'  ? '#ef4444'
    : 'white',
  color: variant === 'ghost' ? 'var(--clavex-ink)' : 'white',
})

const STATUS_CONFIG: Record<CampaignStatus, { color: string; bg: string; icon: typeof Clock; label: string }> = {
  pending:   { color: '#92400e', bg: '#fef3c7', icon: Clock,        label: 'Pending'   },
  active:    { color: '#065f46', bg: '#d1fae5', icon: CheckCircle,  label: 'Active'    },
  completed: { color: '#1e3a8a', bg: '#dbeafe', icon: CheckCircle,  label: 'Completed' },
  cancelled: { color: '#6b7280', bg: '#f3f4f6', icon: Ban,          label: 'Cancelled' },
}

function StatusBadge({ status }: { status: CampaignStatus }) {
  const { color, bg, icon: Icon, label } = STATUS_CONFIG[status] ?? STATUS_CONFIG.pending
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, fontWeight: 600, padding: '3px 9px', borderRadius: 20, background: bg, color }}>
      <Icon size={11} />
      {label}
    </span>
  )
}

function EntityTypeBadge({ type }: { type: EntityType }) {
  const colors: Record<EntityType, string> = {
    client: '#0369a1',
    group:  '#7c3aed',
    role:   '#b45309',
  }
  return (
    <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4, fontFamily: 'monospace', fontWeight: 600, background: '#f8fafc', border: '0.5px solid var(--clavex-border-subtle)', color: colors[type] ?? '#374151' }}>
      {type}
    </span>
  )
}

// ── Item row ──────────────────────────────────────────────────────────────────

function ItemRow({ item, orgId }: { item: ReviewItem; orgId: string }) {
  const qc = useQueryClient()
  const [comment, setComment] = useState('')
  const [deciding, setDeciding] = useState(false)

  const decide = useMutation({
    mutationFn: ({ decision }: { decision: 'confirmed' | 'deprecated' }) =>
      api.post(`/organizations/${orgId}/entity-review/decide`, {
        token: item.review_token,
        decision,
        comment: comment.trim() || undefined,
      }),
    onSuccess: (_, { decision }) => {
      toast.success(`Entity ${decision}`)
      setDeciding(false)
      qc.invalidateQueries({ queryKey: ['entity-review-items', orgId, item.campaign_id] })
      qc.invalidateQueries({ queryKey: ['entity-review-campaigns', orgId] })
    },
    onError: () => toast.error('Decision failed'),
  })

  const decisionColor: Record<Decision, string> = {
    confirmed:  '#166534',
    deprecated: '#991b1b',
    '':         'var(--clavex-ink)',
  }

  const decided = !!item.decision

  return (
    <tr style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
      <td style={{ padding: '10px 16px', fontWeight: 600, color: 'var(--clavex-ink)', fontSize: 13 }}>{item.entity_name}</td>
      <td style={{ padding: '10px 16px' }}>
        <code style={{ fontSize: 11, color: 'var(--clavex-ink-muted)' }}>{item.entity_id.slice(0, 8)}…</code>
      </td>
      <td style={{ padding: '10px 16px' }}>
        {decided ? (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12, color: decisionColor[item.decision], fontWeight: 600 }}>
            {item.decision === 'confirmed' ? <CheckCircle size={13} /> : <XCircle size={13} />}
            {item.decision}
          </span>
        ) : (
          <span style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>pending</span>
        )}
      </td>
      <td style={{ padding: '10px 16px', textAlign: 'right' }}>
        {!decided && !deciding && (
          <button style={{ ...btn('ghost'), padding: '5px 10px', fontSize: 12 }} onClick={() => setDeciding(true)}>
            Review
          </button>
        )}
        {deciding && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <input
              style={{ ...inp, width: 140, padding: '4px 8px', fontSize: 12 }}
              placeholder="Comment (optional)"
              value={comment}
              onChange={e => setComment(e.target.value)}
            />
            <button
              style={{ ...btn('primary'), padding: '5px 10px', fontSize: 12 }}
              onClick={() => decide.mutate({ decision: 'confirmed' })}
              disabled={decide.isPending}
              title="Confirm"
            >
              <CheckCircle size={13} />
            </button>
            <button
              style={{ background: '#fef2f2', border: '0.5px solid #fecaca', color: '#991b1b', borderRadius: 8, padding: '5px 10px', fontSize: 12, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 4, fontWeight: 600 }}
              onClick={() => decide.mutate({ decision: 'deprecated' })}
              disabled={decide.isPending}
              title="Deprecate"
            >
              <XCircle size={13} /> Deprecate
            </button>
            <button
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--clavex-ink-muted)', padding: 4 }}
              onClick={() => setDeciding(false)}
            >
              <X size={13} />
            </button>
          </div>
        )}
      </td>
    </tr>
  )
}

// ── Campaign card ─────────────────────────────────────────────────────────────

function CampaignCard({ campaign, orgId }: { campaign: Campaign; orgId: string }) {
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [reviewerId, setReviewerId] = useState('')

  const { data: items = [], isLoading: itemsLoading } = useQuery<ReviewItem[]>({
    queryKey: ['entity-review-items', orgId, campaign.id],
    queryFn: () =>
      api.get(`/organizations/${orgId}/entity-review-campaigns/${campaign.id}/items`)
        .then(r => toArr<ReviewItem>(r.data)),
    enabled: expanded,
  })

  const activate = useMutation({
    mutationFn: (rid: string) =>
      api.post(`/organizations/${orgId}/entity-review-campaigns/${campaign.id}/activate`, {
        reviewer_id: rid,
      }),
    onSuccess: () => {
      toast.success('Campaign activated')
      qc.invalidateQueries({ queryKey: ['entity-review-campaigns', orgId] })
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg ?? 'Activation failed')
    },
  })

  const cancel = useMutation({
    mutationFn: () =>
      api.delete(`/organizations/${orgId}/entity-review-campaigns/${campaign.id}`),
    onSuccess: () => {
      toast.success('Campaign cancelled')
      qc.invalidateQueries({ queryKey: ['entity-review-campaigns', orgId] })
    },
    onError: () => toast.error('Cancel failed'),
  })

  const pct = campaign.total_items > 0
    ? Math.round(((campaign.confirmed_items + campaign.deprecated_items) / campaign.total_items) * 100)
    : 0

  return (
    <div style={{ ...card, padding: 0, overflow: 'hidden' }}>
      {/* Header */}
      <div
        style={{ padding: '14px 20px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 12 }}
        onClick={() => setExpanded(e => !e)}
      >
        {expanded
          ? <ChevronDown size={15} style={{ color: 'var(--clavex-ink-muted)', flexShrink: 0 }} />
          : <ChevronRight size={15} style={{ color: 'var(--clavex-ink-muted)', flexShrink: 0 }} />}

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
            <span style={{ fontWeight: 700, color: 'var(--clavex-ink)', fontSize: 14 }}>{campaign.name}</span>
            <EntityTypeBadge type={campaign.entity_type} />
            <StatusBadge status={campaign.status} />
          </div>
          {campaign.description && (
            <p style={{ fontSize: 12, color: 'var(--clavex-ink-muted)', margin: 0, lineHeight: 1.4 }}>{campaign.description}</p>
          )}
        </div>

        {/* Progress + meta */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexShrink: 0 }}>
          {campaign.total_items > 0 && (
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--clavex-ink)' }}>{pct}%</div>
              <div style={{ fontSize: 10, color: 'var(--clavex-ink-muted)' }}>
                {campaign.confirmed_items + campaign.deprecated_items}/{campaign.total_items} reviewed
              </div>
            </div>
          )}
          <div style={{ fontSize: 11, color: 'var(--clavex-ink-muted)', textAlign: 'right' }}>
            <div>Ends {new Date(campaign.ends_at).toLocaleDateString()}</div>
            {campaign.frequency_days > 0 && <div>Every {campaign.frequency_days}d</div>}
          </div>
        </div>
      </div>

      {expanded && (
        <div style={{ borderTop: '0.5px solid var(--clavex-border)' }}>
          {/* Activate panel (pending campaigns) */}
          {campaign.status === 'pending' && (
            <div style={{ padding: '14px 20px', background: '#fffbeb', borderBottom: '0.5px solid #fde68a', display: 'flex', alignItems: 'center', gap: 12 }}>
              <AlertCircle size={16} style={{ color: '#b45309', flexShrink: 0 }} />
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: 13, color: '#92400e', fontWeight: 600, margin: 0 }}>Campaign pending — enter reviewer user ID to activate</p>
              </div>
              <input
                style={{ ...inp, width: 240 }}
                placeholder="Reviewer UUID"
                value={reviewerId}
                onChange={e => setReviewerId(e.target.value)}
              />
              <button
                style={btn('primary')}
                onClick={() => {
                  if (!reviewerId.trim()) { toast.error('Reviewer ID required'); return }
                  activate.mutate(reviewerId.trim())
                }}
                disabled={activate.isPending}
              >
                {activate.isPending ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                Activate
              </button>
            </div>
          )}

          {/* Progress bar */}
          {campaign.total_items > 0 && (
            <div style={{ padding: '10px 20px', display: 'flex', alignItems: 'center', gap: 12, borderBottom: '0.5px solid var(--clavex-border)' }}>
              <div style={{ flex: 1, height: 6, background: '#f1f5f9', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: 'var(--clavex-primary)', borderRadius: 3, transition: 'width .3s' }} />
              </div>
              <div style={{ display: 'flex', gap: 14, fontSize: 11, flexShrink: 0 }}>
                <span style={{ color: '#166534' }}>✓ {campaign.confirmed_items} confirmed</span>
                <span style={{ color: '#991b1b' }}>✗ {campaign.deprecated_items} deprecated</span>
                <span style={{ color: 'var(--clavex-ink-muted)' }}>⋯ {campaign.pending_items} pending</span>
              </div>
            </div>
          )}

          {/* Items table */}
          {itemsLoading && (
            <p style={{ padding: '20px', fontSize: 13, color: 'var(--clavex-ink-muted)' }}>Loading items…</p>
          )}
          {!itemsLoading && items.length === 0 && (
            <p style={{ padding: '20px', fontSize: 13, color: 'var(--clavex-ink-muted)' }}>
              No review items yet.{campaign.status === 'pending' ? ' Activate the campaign to generate items.' : ''}
            </p>
          )}
          {items.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ background: 'var(--clavex-surface)' }}>
                  {['Entity', 'ID', 'Decision', ''].map(h => (
                    <th key={h} style={{ padding: '8px 16px', textAlign: 'left', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--clavex-ink-muted)', borderBottom: '0.5px solid var(--clavex-border)' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map(item => (
                  <ItemRow key={item.id} item={item} orgId={orgId} />
                ))}
              </tbody>
            </table>
          )}

          {/* Cancel */}
          {(campaign.status === 'pending' || campaign.status === 'active') && (
            <div style={{ padding: '12px 20px', borderTop: '0.5px solid var(--clavex-border)', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                style={{ ...btn('ghost'), color: '#ef4444', borderColor: '#fecaca' }}
                onClick={() => { if (confirm('Cancel this campaign?')) cancel.mutate() }}
                disabled={cancel.isPending}
              >
                {cancel.isPending ? <Loader2 size={14} className="animate-spin" /> : <Ban size={14} />}
                Cancel Campaign
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Create form ───────────────────────────────────────────────────────────────

function CreateForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    name: '',
    description: '',
    entity_type: 'client' as EntityType,
    frequency_days: 90,
    starts_at: '',
    ends_at: '',
    reviewer_id: '',
    auto_disable: true,
  })
  const [saving, setSaving] = useState(false)

  const set = (k: keyof typeof form, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  const create = async () => {
    if (!form.name.trim()) { toast.error('Name is required'); return }
    if (!form.ends_at)    { toast.error('End date is required'); return }
    if (!form.reviewer_id.trim()) { toast.error('Reviewer ID is required'); return }
    setSaving(true)
    try {
      await api.post(`/organizations/${orgId}/entity-review-campaigns`, {
        ...form,
        name: form.name.trim(),
        description: form.description.trim() || undefined,
        starts_at: form.starts_at ? new Date(form.starts_at).toISOString() : undefined,
        ends_at: new Date(form.ends_at).toISOString(),
      })
      toast.success('Campaign created')
      qc.invalidateQueries({ queryKey: ['entity-review-campaigns', orgId] })
      onDone()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg ?? 'Create failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ ...card, borderColor: 'var(--clavex-primary)' }} className="space-y-4">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--clavex-ink)' }}>New Entity Review Campaign</span>
        <button style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--clavex-ink-muted)' }} onClick={onDone}>
          <X size={16} />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label style={lbl}>Campaign Name</label>
          <input style={inp} value={form.name} onChange={e => set('name', e.target.value)} placeholder="e.g. Q2 Client Audit" />
        </div>
        <div>
          <label style={lbl}>Entity Type</label>
          <select style={{ ...inp, cursor: 'pointer' }} value={form.entity_type} onChange={e => set('entity_type', e.target.value as EntityType)}>
            <option value="client">OIDC Clients</option>
            <option value="group">Groups</option>
            <option value="role">Roles</option>
          </select>
        </div>
        <div>
          <label style={lbl}>Reviewer User ID</label>
          <input style={inp} value={form.reviewer_id} onChange={e => set('reviewer_id', e.target.value)} placeholder="UUID of reviewer user" />
        </div>
        <div>
          <label style={lbl}>Recurrence (days, 0 = one-off)</label>
          <input style={inp} type="number" min={0} value={form.frequency_days} onChange={e => set('frequency_days', Number(e.target.value))} />
        </div>
        <div>
          <label style={lbl}>Starts At (optional)</label>
          <input style={inp} type="datetime-local" value={form.starts_at} onChange={e => set('starts_at', e.target.value)} />
        </div>
        <div>
          <label style={lbl}>Ends At *</label>
          <input style={inp} type="datetime-local" value={form.ends_at} onChange={e => set('ends_at', e.target.value)} />
        </div>
        <div style={{ gridColumn: 'span 2' }}>
          <label style={lbl}>Description</label>
          <input style={inp} value={form.description} onChange={e => set('description', e.target.value)} placeholder="Optional description" />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <input type="checkbox" id="auto-disable" checked={form.auto_disable} onChange={e => set('auto_disable', e.target.checked)} style={{ accentColor: 'var(--clavex-primary)', width: 14, height: 14 }} />
          <label htmlFor="auto-disable" style={{ fontSize: 13, color: 'var(--clavex-ink)', cursor: 'pointer' }}>Auto-disable deprecated entities on campaign end</label>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button style={btn('ghost')} onClick={onDone}>Cancel</button>
        <button style={btn('primary')} onClick={create} disabled={saving}>
          {saving ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
          Create Campaign
        </button>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function EntityReviewPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [filter, setFilter] = useState<CampaignStatus | 'all'>('all')

  const { data: campaigns = [], isLoading } = useQuery<Campaign[]>({
    queryKey: ['entity-review-campaigns', orgId],
    queryFn: () =>
      api.get(`/organizations/${orgId}/entity-review-campaigns`)
        .then(r => toArr<Campaign>(r.data)),
    enabled: !!orgId,
  })

  if (!orgId) return null

  const visible = filter === 'all' ? campaigns : campaigns.filter(c => c.status === filter)
  const counts = {
    active:    campaigns.filter(c => c.status === 'active').length,
    pending:   campaigns.filter(c => c.status === 'pending').length,
    completed: campaigns.filter(c => c.status === 'completed').length,
    cancelled: campaigns.filter(c => c.status === 'cancelled').length,
  }

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 28 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <ClipboardList size={20} style={{ color: 'var(--clavex-primary)' }} />
            <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--clavex-ink)', margin: 0 }}>
              Entity Review Campaigns
            </h1>
          </div>
          <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', margin: 0, lineHeight: 1.6, maxWidth: 560 }}>
            Periodic Object Lifecycle Management reviews for OIDC clients, groups, and roles.
            Reviewers confirm or deprecate stale entities on a scheduled cadence.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button style={btn('ghost')} onClick={() => qc.invalidateQueries({ queryKey: ['entity-review-campaigns', orgId] })}>
            <RefreshCw size={13} />
          </button>
          <button style={btn('primary')} onClick={() => setCreating(true)} disabled={creating}>
            <Plus size={13} /> New Campaign
          </button>
        </div>
      </div>

      {creating && (
        <div style={{ marginBottom: 20 }}>
          <CreateForm orgId={orgId} onDone={() => setCreating(false)} />
        </div>
      )}

      {/* Summary tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 20 }}>
        {(['all', 'active', 'pending', 'completed'] as const).map(s => (
          <div
            key={s}
            style={{
              ...card,
              padding: '12px 16px',
              cursor: 'pointer',
              borderColor: filter === s ? 'var(--clavex-primary)' : 'var(--clavex-border)',
              background: filter === s ? '#f0fdf4' : 'white',
            }}
            onClick={() => setFilter(s)}
          >
            <p style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--clavex-ink-muted)', marginBottom: 4 }}>{s}</p>
            <p style={{ fontSize: 22, fontWeight: 700, color: 'var(--clavex-ink)', margin: 0 }}>
              {s === 'all' ? campaigns.length : counts[s as CampaignStatus]}
            </p>
          </div>
        ))}
      </div>

      {isLoading && <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)' }}>Loading…</p>}

      {!isLoading && visible.length === 0 && !creating && (
        <div style={{ ...card, textAlign: 'center', padding: '48px 24px', borderStyle: 'dashed' }}>
          <ClipboardList size={36} style={{ color: 'var(--clavex-ink-muted)', margin: '0 auto 12px' }} />
          <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 8 }}>No campaigns</p>
          <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', marginBottom: 20 }}>
            Create a campaign to start reviewing stale OIDC clients, groups, or roles.
          </p>
          <button style={btn('primary')} onClick={() => setCreating(true)}>
            <Plus size={14} /> New Campaign
          </button>
        </div>
      )}

      <div className="space-y-3">
        {visible.map(c => (
          <CampaignCard key={c.id} campaign={c} orgId={orgId} />
        ))}
      </div>
    </div>
  )
}
