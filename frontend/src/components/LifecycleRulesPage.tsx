import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import { Plus, Trash2, Pencil, Zap, X, ChevronDown, ChevronUp, ToggleLeft, ToggleRight } from 'lucide-react'
import { Button, PageHeader, Card, EmptyState, Spinner } from '@/components/ui'

// ── Types ─────────────────────────────────────────────────────────────────────

type Trigger = 'joiner' | 'mover' | 'leaver'

interface Condition {
  field: string
  op: string
  value?: string
}

interface Action {
  type: string
  role_name?: string
  group_name?: string
  notification_type?: string
}

interface LifecycleRule {
  id: string
  name: string
  description?: string
  trigger: Trigger
  priority: number
  conditions: Condition[]
  actions: Action[]
  is_active: boolean
  created_at: string
  updated_at: string
}

interface RuleFormData {
  name: string
  description: string
  trigger: Trigger
  priority: number
  conditions: Condition[]
  actions: Action[]
  is_active: boolean
}

// ── Constants ─────────────────────────────────────────────────────────────────

const TRIGGER_LABELS: Record<Trigger, string> = {
  joiner: 'Joiner',
  mover:  'Mover',
  leaver: 'Leaver',
}

const TRIGGER_COLORS: Record<Trigger, string> = {
  joiner: 'bg-emerald-100 text-emerald-700',
  mover:  'bg-blue-100 text-blue-700',
  leaver: 'bg-red-100 text-red-700',
}

const CONDITION_OPS = ['eq', 'neq', 'contains', 'starts_with', 'ends_with', 'exists', 'not_exists']
const BINARY_OPS = new Set(['eq', 'neq', 'contains', 'starts_with', 'ends_with'])

const ACTION_TYPES = [
  { value: 'assign_role',        label: 'Assign Role',        field: 'role_name'  },
  { value: 'remove_role',        label: 'Remove Role',        field: 'role_name'  },
  { value: 'add_to_group',       label: 'Add to Group',       field: 'group_name' },
  { value: 'remove_from_group',  label: 'Remove from Group',  field: 'group_name' },
  { value: 'revoke_sessions',    label: 'Revoke Sessions',    field: null         },
  { value: 'send_notification',  label: 'Send Notification',  field: 'notification_type' },
]

// ── Small helpers ─────────────────────────────────────────────────────────────

function TriggerBadge({ trigger }: { trigger: Trigger }) {
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${TRIGGER_COLORS[trigger]}`}>
      {TRIGGER_LABELS[trigger]}
    </span>
  )
}

function EmptyCondition(): Condition {
  return { field: 'department', op: 'eq', value: '' }
}
function EmptyAction(): Action {
  return { type: 'assign_role', role_name: '' }
}

// ── Condition editor ──────────────────────────────────────────────────────────

function ConditionRow({
  cond,
  onChange,
  onRemove,
}: {
  cond: Condition
  onChange: (c: Condition) => void
  onRemove: () => void
}) {
  const needsValue = BINARY_OPS.has(cond.op)
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <input
        className="border border-gray-300 rounded px-2 py-1 text-sm w-36 focus:outline-none focus:border-indigo-400"
        placeholder="field (e.g. department)"
        value={cond.field}
        onChange={(e) => onChange({ ...cond, field: e.target.value })}
      />
      <select
        className="border border-gray-300 rounded px-2 py-1 text-sm focus:outline-none focus:border-indigo-400"
        value={cond.op}
        onChange={(e) => onChange({ ...cond, op: e.target.value, value: '' })}
      >
        {CONDITION_OPS.map((op) => <option key={op} value={op}>{op}</option>)}
      </select>
      {needsValue && (
        <input
          className="border border-gray-300 rounded px-2 py-1 text-sm w-36 focus:outline-none focus:border-indigo-400"
          placeholder="value"
          value={cond.value ?? ''}
          onChange={(e) => onChange({ ...cond, value: e.target.value })}
        />
      )}
      <button onClick={onRemove} className="text-gray-400 hover:text-red-500">
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}

// ── Action editor ─────────────────────────────────────────────────────────────

function ActionRow({
  action,
  onChange,
  onRemove,
}: {
  action: Action
  onChange: (a: Action) => void
  onRemove: () => void
}) {
  const meta = ACTION_TYPES.find((t) => t.value === action.type)
  const fieldKey = meta?.field as keyof Action | null | undefined

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <select
        className="border border-gray-300 rounded px-2 py-1 text-sm focus:outline-none focus:border-indigo-400"
        value={action.type}
        onChange={(e) => onChange({ type: e.target.value })}
      >
        {ACTION_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
      </select>
      {fieldKey && (
        <input
          className="border border-gray-300 rounded px-2 py-1 text-sm w-44 focus:outline-none focus:border-indigo-400"
          placeholder={fieldKey.replace('_', ' ')}
          value={(action[fieldKey] as string) ?? ''}
          onChange={(e) => onChange({ ...action, [fieldKey]: e.target.value })}
        />
      )}
      <button onClick={onRemove} className="text-gray-400 hover:text-red-500">
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}

// ── Rule form (create / edit modal) ──────────────────────────────────────────

function RuleModal({
  orgId,
  rule,
  onClose,
}: {
  orgId: string
  rule?: LifecycleRule
  onClose: () => void
}) {
  const qc = useQueryClient()
  const isEdit = !!rule

  const [form, setForm] = useState<RuleFormData>({
    name:        rule?.name        ?? '',
    description: rule?.description ?? '',
    trigger:     rule?.trigger     ?? 'joiner',
    priority:    rule?.priority    ?? 10,
    conditions:  rule?.conditions  ?? [],
    actions:     rule?.actions     ?? [],
    is_active:   rule?.is_active   ?? true,
  })

  const save = useMutation({
    mutationFn: (data: RuleFormData) =>
      isEdit
        ? api.put(`/organizations/${orgId}/lifecycle-rules/${rule!.id}`, data)
        : api.post(`/organizations/${orgId}/lifecycle-rules`, data),
    onSuccess: () => {
      toast.success(isEdit ? 'Rule updated' : 'Rule created')
      qc.invalidateQueries({ queryKey: ['lifecycle-rules', orgId] })
      onClose()
    },
    onError: () => toast.error('Save failed'),
  })

  const addCondition = () => setForm((f) => ({ ...f, conditions: [...f.conditions, EmptyCondition()] }))
  const addAction    = () => setForm((f) => ({ ...f, actions: [...f.actions, EmptyAction()] }))

  const updateCondition = (i: number, c: Condition) =>
    setForm((f) => { const arr = [...f.conditions]; arr[i] = c; return { ...f, conditions: arr } })
  const removeCondition = (i: number) =>
    setForm((f) => ({ ...f, conditions: f.conditions.filter((_, idx) => idx !== i) }))
  const updateAction = (i: number, a: Action) =>
    setForm((f) => { const arr = [...f.actions]; arr[i] = a; return { ...f, actions: arr } })
  const removeAction = (i: number) =>
    setForm((f) => ({ ...f, actions: f.actions.filter((_, idx) => idx !== i) }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b">
          <h3 className="text-base font-semibold text-gray-900">
            {isEdit ? 'Edit Lifecycle Rule' : 'New Lifecycle Rule'}
          </h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X className="h-5 w-5" /></button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-5">
          {/* Name */}
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Name *</label>
            <input
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"
              placeholder="e.g. Assign Engineering role on Joiner"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Description</label>
            <textarea
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400 resize-none"
              rows={2}
              placeholder="Optional description"
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </div>

          {/* Trigger + Priority */}
          <div className="flex gap-4">
            <div className="flex-1">
              <label className="block text-xs font-semibold text-gray-600 mb-1">Trigger *</label>
              <select
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"
                value={form.trigger}
                onChange={(e) => setForm((f) => ({ ...f, trigger: e.target.value as Trigger }))}
              >
                <option value="joiner">Joiner (user created/provisioned)</option>
                <option value="mover">Mover (user attributes changed)</option>
                <option value="leaver">Leaver (user deactivated/deleted)</option>
              </select>
            </div>
            <div className="w-28">
              <label className="block text-xs font-semibold text-gray-600 mb-1">Priority</label>
              <input
                type="number"
                min={1}
                max={999}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"
                value={form.priority}
                onChange={(e) => setForm((f) => ({ ...f, priority: parseInt(e.target.value, 10) || 10 }))}
              />
            </div>
          </div>

          {/* Conditions */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-semibold text-gray-600">Conditions <span className="text-gray-400 font-normal">(all must match; empty = always run)</span></label>
              <button
                onClick={addCondition}
                style={{ color: 'var(--clavex-primary)' }}
              className="text-xs font-medium flex items-center gap-1 hover:opacity-75"
              >
                <Plus className="h-3.5 w-3.5" /> Add
              </button>
            </div>
            <div className="space-y-2">
              {form.conditions.map((c, i) => (
                <ConditionRow key={i} cond={c} onChange={(v) => updateCondition(i, v)} onRemove={() => removeCondition(i)} />
              ))}
              {form.conditions.length === 0 && (
                <p className="text-xs text-gray-400 italic">No conditions — rule will always execute on trigger</p>
              )}
            </div>
          </div>

          {/* Actions */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-semibold text-gray-600">Actions *</label>
              <button
                onClick={addAction}
                style={{ color: 'var(--clavex-primary)' }}
              className="text-xs font-medium flex items-center gap-1 hover:opacity-75"
              >
                <Plus className="h-3.5 w-3.5" /> Add
              </button>
            </div>
            <div className="space-y-2">
              {form.actions.map((a, i) => (
                <ActionRow key={i} action={a} onChange={(v) => updateAction(i, v)} onRemove={() => removeAction(i)} />
              ))}
              {form.actions.length === 0 && (
                <p className="text-xs text-red-400 italic">Add at least one action</p>
              )}
            </div>
          </div>

          {/* Active toggle */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setForm((f) => ({ ...f, is_active: !f.is_active }))}
              style={{ color: form.is_active ? 'var(--clavex-primary)' : 'var(--clavex-neutral)' }}
            >
              {form.is_active ? <ToggleRight className="h-6 w-6" /> : <ToggleLeft className="h-6 w-6" />}
            </button>
            <span className="text-sm text-gray-700">{form.is_active ? 'Active' : 'Inactive'}</span>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-3 px-6 py-4 border-t bg-gray-50 rounded-b-xl">
          <Button variant="secondary" size="sm" onClick={onClose}>Cancel</Button>
          <Button
            size="sm"
            loading={save.isPending}
            onClick={() => {
              if (!form.name.trim()) { toast.error('Name is required'); return }
              if (form.actions.length === 0) { toast.error('Add at least one action'); return }
              save.mutate(form)
            }}
          >
            {isEdit ? 'Save Changes' : 'Create Rule'}
          </Button>
        </div>
      </div>
    </div>
  )
}

// ── Rule row (expandable) ─────────────────────────────────────────────────────

function RuleRow({
  rule,
  orgId,
  onEdit,
}: {
  rule: LifecycleRule
  orgId: string
  onEdit: (r: LifecycleRule) => void
}) {
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)

  const del = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/lifecycle-rules/${rule.id}`),
    onSuccess: () => {
      toast.success('Rule deleted')
      qc.invalidateQueries({ queryKey: ['lifecycle-rules', orgId] })
    },
    onError: () => toast.error('Delete failed'),
  })

  return (
    <div className="border border-gray-200 rounded-xl overflow-hidden">
      <div
        className="flex items-center gap-3 px-4 py-3 bg-white hover:bg-gray-50 cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        {/* Active indicator */}
        <span
          className={`h-2 w-2 rounded-full flex-shrink-0 ${rule.is_active ? 'bg-emerald-400' : 'bg-gray-300'}`}
        />

        {/* Trigger badge */}
        <TriggerBadge trigger={rule.trigger} />

        {/* Name */}
        <span className="flex-1 text-sm font-medium text-gray-900 min-w-0 truncate">{rule.name}</span>

        {/* Priority */}
        <span className="text-xs text-gray-400 mr-2">priority {rule.priority}</span>

        {/* Actions count */}
        <span className="text-xs text-gray-400">
          {rule.conditions.length} cond · {rule.actions.length} action{rule.actions.length !== 1 ? 's' : ''}
        </span>

        {/* Controls */}
        <div className="flex items-center gap-1 ml-2" onClick={(e) => e.stopPropagation()}>
          <button
            onClick={() => onEdit(rule)}
            className="p-1.5 rounded hover:bg-gray-100 text-gray-500"
            style={{ color: undefined }}
            onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--clavex-primary)')}
            onMouseLeave={(e) => (e.currentTarget.style.color = '')}
            title="Edit"
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={() => { if (confirm(`Delete rule "${rule.name}"?`)) del.mutate() }}
            className="p-1.5 rounded hover:bg-red-50 text-gray-400 hover:text-red-600"
            title="Delete"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>

        {expanded ? <ChevronUp className="h-4 w-4 text-gray-400 flex-shrink-0" /> : <ChevronDown className="h-4 w-4 text-gray-400 flex-shrink-0" />}
      </div>

      {expanded && (
        <div className="px-4 py-3 border-t bg-gray-50 grid grid-cols-2 gap-4 text-sm">
          {/* Conditions */}
          <div>
            <p className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wide">Conditions</p>
            {rule.conditions.length === 0
              ? <p className="text-xs text-gray-400 italic">Always execute</p>
              : rule.conditions.map((c, i) => (
                  <div key={i} className="text-xs text-gray-700 font-mono bg-white border border-gray-200 rounded px-2 py-1 mb-1">
                    {c.field} <span style={{ color: 'var(--clavex-primary)' }}>{c.op}</span>{c.value ? ` "${c.value}"` : ''}
                  </div>
                ))
            }
          </div>
          {/* Actions */}
          <div>
            <p className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wide">Actions</p>
            {rule.actions.map((a, i) => {
              const meta = ACTION_TYPES.find((t) => t.value === a.type)
              const detail = a.role_name ?? a.group_name ?? a.notification_type ?? ''
              return (
                <div key={i} className="text-xs text-gray-700 font-mono bg-white border border-gray-200 rounded px-2 py-1 mb-1">
                  {meta?.label ?? a.type}{detail ? `: ${detail}` : ''}
                </div>
              )
            })}
          </div>
          {rule.description && (
            <div className="col-span-2 text-xs text-gray-500">{rule.description}</div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function LifecycleRulesPage({ orgId }: { orgId: string }) {
  const [modal, setModal] = useState<{ open: boolean; rule?: LifecycleRule }>({ open: false })

  const { data: rules = [], isLoading } = useQuery<LifecycleRule[]>({
    queryKey: ['lifecycle-rules', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/lifecycle-rules`).then((r) => toArr(r.data)),
  })

  const byTrigger = (t: Trigger) => rules.filter((r) => r.trigger === t)

  return (
    <div>
      <PageHeader
        title="Lifecycle Rules"
        subtitle="Automate role/group assignments and notifications on Joiner, Mover, and Leaver events."
        action={
          <Button onClick={() => setModal({ open: true })}>
            <Plus className="h-4 w-4" /> New Rule
          </Button>
        }
      />

      {/* Stats strip */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {(['joiner', 'mover', 'leaver'] as Trigger[]).map((t) => (
          <Card key={t} className="p-4">
            <div className="flex items-center justify-between mb-1">
              <TriggerBadge trigger={t} />
              <span className="text-lg font-bold" style={{ color: 'var(--clavex-ink)' }}>{byTrigger(t).length}</span>
            </div>
            <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>
              {byTrigger(t).filter((r) => r.is_active).length} active
            </p>
          </Card>
        ))}
      </div>

      {/* Rule list */}
      {isLoading ? (
        <Spinner />
      ) : rules.length === 0 ? (
        <Card>
          <EmptyState icon={Zap} title="No lifecycle rules yet" message="Create a rule to automatically manage roles and groups when users join, move, or leave." />
        </Card>
      ) : (
        <div className="space-y-3">
          {(['joiner', 'mover', 'leaver'] as Trigger[]).map((t) => {
            const group = byTrigger(t)
            if (group.length === 0) return null
            return (
              <div key={t}>
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 px-1">
                  {TRIGGER_LABELS[t]} ({group.length})
                </p>
                <div className="space-y-2">
                  {group
                    .sort((a, b) => a.priority - b.priority)
                    .map((rule) => (
                      <RuleRow
                        key={rule.id}
                        rule={rule}
                        orgId={orgId}
                        onEdit={(r) => setModal({ open: true, rule: r })}
                      />
                    ))}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Modal */}
      {modal.open && (
        <RuleModal
          orgId={orgId}
          rule={modal.rule}
          onClose={() => setModal({ open: false })}
        />
      )}
    </div>
  )
}
