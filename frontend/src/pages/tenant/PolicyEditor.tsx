import { useEffect, useState, useCallback, useRef } from 'react'
import { useAuthStore } from '@/stores/auth'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import {
  Plus, Trash2, Play, CheckCircle, XCircle, AlertCircle,
  GripVertical, ChevronDown, ChevronUp, Save, RefreshCw,
  Shield, Globe, Clock, Wifi, Smartphone, Eye, Layers, X,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

type Action = 'allow' | 'deny' | 'require_mfa' | 'step_up'

interface Condition {
  id: string // client-only, for React keys
  field: string
  operator: string
  value: string
}

interface PolicyRule {
  id?: string
  name: string
  priority: number
  enabled: boolean
  action: Action
  conditions: Record<string, unknown>
  _localConditions?: Condition[] // builder state, not sent to API
}

interface SimResult {
  outcome: { action: string; reason?: string }
  mfa_required: boolean
  trace: Array<{ rule_name: string; matched: boolean; action: string; priority: number }>
}

// ── Condition field registry ──────────────────────────────────────────────────

const FIELDS = [
  { key: 'ip_cidr',    label: 'IP / CIDR Range',    icon: Wifi,        ops: ['in_cidr', 'not_in_cidr'],            placeholder: '10.0.0.0/8, 192.168.1.1' },
  { key: 'country',    label: 'Country (ISO 3166)',  icon: Globe,       ops: ['in', 'not_in'],                      placeholder: 'IT, DE, FR' },
  { key: 'hour_utc',   label: 'Hour of day (UTC)',   icon: Clock,       ops: ['between', 'not_between'],            placeholder: '9:23 (start:end)' },
  { key: 'mfa',        label: 'MFA completed',       icon: Shield,      ops: ['is_true', 'is_false'],               placeholder: '' },
  { key: 'device',     label: 'Device trust',        icon: Smartphone,  ops: ['trusted', 'untrusted'],              placeholder: '' },
  { key: 'user_group', label: 'User group',          icon: Eye,         ops: ['in', 'not_in'],                      placeholder: 'admins, finance' },
  { key: 'acr',        label: 'ACR (assurance level)',icon: Shield,     ops: ['eq', 'gte'],                         placeholder: 'urn:mace:incommon:iap:silver' },
] as const

const ACTIONS: { value: Action; label: string; color: string }[] = [
  { value: 'allow',       label: 'Allow',       color: 'var(--clavex-primary)' },
  { value: 'deny',        label: 'Deny',         color: '#f87171' },
  { value: 'require_mfa', label: 'Require MFA',  color: '#fbbf24' },
  { value: 'step_up',     label: 'Step-up MFA',  color: '#a78bfa' },
]

// ── Vertical policy templates ────────────────────────────────────────────────

const EU_COUNTRIES = 'AT, BE, BG, CY, CZ, DE, DK, EE, ES, FI, FR, GR, HR, HU, IE, IT, LT, LU, LV, MT, NL, PL, PT, RO, SE, SI, SK'

interface ConditionSpec { field: string; operator: string; value: string }
interface RuleSpec {
  name: string; priority: number; action: Action; enabled: boolean
  note?: string; conditions: ConditionSpec[]
}
interface VerticalTemplate {
  id: string; name: string; emoji: string; description: string
  tags: string[]; color: string; rules: RuleSpec[]
}

const VERTICAL_TEMPLATES: VerticalTemplate[] = [
  {
    id: 'healthcare',
    name: 'Healthcare',
    emoji: '🏥',
    description: 'GDPR Art. 9 & NIS2-compliant baseline for EHR / medical record systems: MFA L2+ mandatory, EU-only access, restricted clinical hours.',
    tags: ['GDPR Art. 9', 'NIS2', 'EHR'],
    color: '#3b82f6',
    rules: [
      {
        name: 'Block non-EU access',
        priority: 5, action: 'deny', enabled: true,
        note: 'Deny any session originating outside the European Union (GDPR data-residency requirement).',
        conditions: [{ field: 'country', operator: 'not_in', value: EU_COUNTRIES }],
      },
      {
        name: 'Require MFA (L2+) for all sessions',
        priority: 10, action: 'require_mfa', enabled: true,
        note: 'Enforce step-up authentication before granting access to patient data.',
        conditions: [{ field: 'mfa', operator: 'is_false', value: '' }],
      },
      {
        name: 'Restrict to clinical hours (06:00–22:00 UTC)',
        priority: 20, action: 'deny', enabled: true,
        note: 'Block access outside core clinical hours. Adjust the range for your timezone.',
        conditions: [{ field: 'hour_utc', operator: 'not_between', value: '6:22' }],
      },
    ],
  },
  {
    id: 'banking',
    name: 'Banking / Fintech',
    emoji: '🏦',
    description: 'FAPI 2.0 & PSD2 SCA baseline: mandatory MFA, step-up for finance/payments/trading groups, restricted operating hours.',
    tags: ['FAPI 2.0', 'PSD2 SCA', 'EBA RTS'],
    color: '#8b5cf6',
    rules: [
      {
        name: 'Require MFA for all banking sessions',
        priority: 10, action: 'require_mfa', enabled: true,
        note: 'PSD2 SCA: strong customer authentication required for every session.',
        conditions: [{ field: 'mfa', operator: 'is_false', value: '' }],
      },
      {
        name: 'Step-up for finance / payments / trading',
        priority: 5, action: 'step_up', enabled: true,
        note: 'Trigger step-up for users in privileged financial groups (proxy for high-value transaction threshold).',
        conditions: [{ field: 'user_group', operator: 'in', value: 'finance, payments, trading' }],
      },
      {
        name: 'Block access outside banking hours (06:00–22:00 UTC)',
        priority: 20, action: 'deny', enabled: true,
        note: 'Reduce attack surface by blocking requests outside core operating hours.',
        conditions: [{ field: 'hour_utc', operator: 'not_between', value: '6:22' }],
      },
    ],
  },
  {
    id: 'italian-pa',
    name: 'Italian PA',
    emoji: '🇮🇹',
    description: 'CAF / AgID compliance: SPID L2 assurance required, Italian-IP gating for internal portals, eIDAS-compatible ACR enforcement.',
    tags: ['SPID L2', 'CAF / AgID', 'eIDAS'],
    color: '#10b981',
    rules: [
      {
        name: 'Block access from non-Italian IPs',
        priority: 5, action: 'deny', enabled: true,
        note: 'Restrict internal PA portals to Italian IP space. Disable this rule for citizen-facing services.',
        conditions: [{ field: 'country', operator: 'not_in', value: 'IT' }],
      },
      {
        name: 'Require SPID L2 assurance (ACR)',
        priority: 10, action: 'require_mfa', enabled: true,
        note: 'AgID mandates SPID L2 (ACR ≥ https://www.spid.gov.it/SpidL2) for PA digital services.',
        conditions: [{ field: 'acr', operator: 'gte', value: 'https://www.spid.gov.it/SpidL2' }],
      },
      {
        name: 'Restrict to office hours (08:00–18:00 CET / 07:00–17:00 UTC)',
        priority: 20, action: 'deny', enabled: true,
        note: 'Italian civil-service hours. Switch to 6:16 during CEST (summer, UTC+2).',
        conditions: [{ field: 'hour_utc', operator: 'not_between', value: '7:17' }],
      },
    ],
  },
]

function buildRulesFromTemplate(specs: RuleSpec[]): PolicyRule[] {
  return specs.map((spec) => ({
    name: spec.name,
    priority: spec.priority,
    action: spec.action,
    enabled: spec.enabled,
    conditions: {},
    _localConditions: spec.conditions.map((c) => ({ id: uid(), ...c })),
  }))
}

function TemplatesModal({ onLoad, onClose }: { onLoad: (rules: PolicyRule[]) => void; onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.45)', backdropFilter: 'blur(4px)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-5xl max-h-[90vh] overflow-y-auto rounded-2xl"
        style={{ background: 'white', boxShadow: '0 25px 60px rgba(0,0,0,0.25)' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
          <div>
            <h2 className="text-lg font-bold" style={{ color: 'var(--clavex-ink)' }}>Policy Templates by Vertical</h2>
            <p className="text-sm mt-0.5" style={{ color: 'var(--clavex-ink-subtle)' }}>
              Choose an industry baseline — rules are added in draft state and never saved until you click Deploy / Save on each one.
            </p>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-gray-50" style={{ color: 'var(--clavex-neutral)' }}>
            <X size={18} />
          </button>
        </div>

        {/* Vertical cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 p-6">
          {VERTICAL_TEMPLATES.map((tmpl) => (
            <div
              key={tmpl.id}
              className="rounded-xl flex flex-col"
              style={{ border: `1.5px solid ${tmpl.color}30`, background: `${tmpl.color}06` }}
            >
              {/* Card header */}
              <div className="px-5 pt-5 pb-4">
                <div className="flex items-center gap-3 mb-3">
                  <span className="text-3xl">{tmpl.emoji}</span>
                  <div>
                    <h3 className="font-bold text-base" style={{ color: 'var(--clavex-ink)' }}>{tmpl.name}</h3>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {tmpl.tags.map((tag) => (
                        <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold"
                          style={{ background: `${tmpl.color}20`, color: tmpl.color }}>
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
                <p className="text-xs leading-relaxed" style={{ color: 'var(--clavex-ink-subtle)' }}>{tmpl.description}</p>
              </div>

              {/* Rules preview */}
              <div className="px-5 pb-4 flex-1 space-y-2">
                {tmpl.rules.map((rule, i) => {
                  const actionDef = ACTIONS.find((a) => a.value === rule.action)
                  return (
                    <div key={i} className="rounded-lg px-3 py-2" style={{ background: 'white', border: '0.5px solid var(--clavex-border)' }}>
                      <div className="flex items-start gap-2">
                        <span className="text-xs font-semibold flex-1" style={{ color: 'var(--clavex-ink)' }}>{rule.name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold flex-shrink-0"
                          style={{ background: `${actionDef?.color}22`, color: actionDef?.color }}>
                          {actionDef?.label}
                        </span>
                      </div>
                      {rule.note && (
                        <p className="text-[11px] mt-1 leading-snug" style={{ color: 'var(--clavex-neutral)' }}>{rule.note}</p>
                      )}
                    </div>
                  )
                })}
              </div>

              {/* Load button */}
              <div className="px-5 pb-5">
                <button
                  onClick={() => { onLoad(buildRulesFromTemplate(tmpl.rules)); onClose() }}
                  className="w-full py-2.5 rounded-lg text-sm font-semibold transition-opacity hover:opacity-90"
                  style={{ background: tmpl.color, color: 'white' }}
                >
                  Add {tmpl.rules.length} rules to editor
                </button>
              </div>
            </div>
          ))}
        </div>

        <p className="text-xs text-center pb-6" style={{ color: 'var(--clavex-neutral)' }}>
          Rules are added in <strong>draft state</strong> — none are persisted until you click Deploy / Save on each one.
        </p>
      </div>
    </div>
  )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function uid() { return Math.random().toString(36).slice(2) }

function conditionsToAPI(conds: Condition[]): Record<string, unknown> {
  // Build the conditions object that the backend policy engine understands.
  // Multiple conditions on the same field are combined with AND.
  const out: Record<string, unknown> = {}
  for (const c of conds) {
    if (!c.field || !c.operator) continue
    const vals = c.value.split(',').map((s) => s.trim()).filter(Boolean)
    switch (c.operator) {
      case 'in':
      case 'not_in':
        out[c.field] = { [c.operator === 'in' ? '$in' : '$nin']: vals }
        break
      case 'in_cidr':
        out['ip_cidr'] = { $in: vals }
        break
      case 'not_in_cidr':
        out['ip_cidr'] = { $nin: vals }
        break
      case 'between': {
        const [start, end] = c.value.split(':')
        out[c.field] = { $gte: parseInt(start ?? '0'), $lte: parseInt(end ?? '23') }
        break
      }
      case 'not_between': {
        const [s2, e2] = c.value.split(':')
        out[c.field] = { $lt: parseInt(s2 ?? '0'), $gt: parseInt(e2 ?? '23') }
        break
      }
      case 'is_true':
        out[c.field] = true
        break
      case 'is_false':
        out[c.field] = false
        break
      case 'trusted':
        out['device_trusted'] = true
        break
      case 'untrusted':
        out['device_trusted'] = false
        break
      case 'eq':
        out[c.field] = c.value
        break
      case 'gte':
        out[c.field] = { $gte: c.value }
        break
    }
  }
  return out
}

function apiToConditions(conds: Record<string, unknown>): Condition[] {
  const out: Condition[] = []
  for (const [key, val] of Object.entries(conds)) {
    if (val === true) {
      out.push({ id: uid(), field: key === 'device_trusted' ? 'device' : key, operator: key === 'device_trusted' ? 'trusted' : 'is_true', value: '' })
    } else if (val === false) {
      out.push({ id: uid(), field: key === 'device_trusted' ? 'device' : key, operator: key === 'device_trusted' ? 'untrusted' : 'is_false', value: '' })
    } else if (val && typeof val === 'object') {
      const v = val as Record<string, unknown>
      if ('$in' in v) out.push({ id: uid(), field: key, operator: key === 'ip_cidr' ? 'in_cidr' : 'in', value: (v['$in'] as string[]).join(', ') })
      else if ('$nin' in v) out.push({ id: uid(), field: key, operator: key === 'ip_cidr' ? 'not_in_cidr' : 'not_in', value: (v['$nin'] as string[]).join(', ') })
      else if ('$gte' in v && '$lte' in v) out.push({ id: uid(), field: key, operator: 'between', value: `${v['$gte']}:${v['$lte']}` })
      else if ('$gte' in v) out.push({ id: uid(), field: key, operator: 'gte', value: String(v['$gte']) })
    } else if (typeof val === 'string') {
      out.push({ id: uid(), field: key, operator: 'eq', value: val })
    }
  }
  return out.length ? out : [{ id: uid(), field: '', operator: '', value: '' }]
}

// ── Styles ────────────────────────────────────────────────────────────────────

const card: React.CSSProperties = { background: 'white', border: '0.5px solid var(--clavex-border)', borderRadius: 12, padding: '20px 24px' }
const inp: React.CSSProperties = { background: 'white', color: 'var(--clavex-ink)', border: '0.5px solid var(--clavex-border-subtle)', borderRadius: 8, padding: '6px 10px', fontSize: 13, outline: 'none', width: '100%' }
const sel: React.CSSProperties = { ...inp, cursor: 'pointer' }

// ── Sub-components ────────────────────────────────────────────────────────────

function ConditionRow({ cond, onChange, onRemove }: {
  cond: Condition
  onChange: (c: Condition) => void
  onRemove: () => void
}) {
  const fieldDef = FIELDS.find((f) => f.key === cond.field)
  const ops = fieldDef?.ops ?? []
  const needsValue = !['is_true', 'is_false', 'trusted', 'untrusted'].includes(cond.operator)

  return (
    <div className="flex items-center gap-2">
      <select style={sel} value={cond.field} onChange={(e) => onChange({ ...cond, field: e.target.value, operator: '', value: '' })}>
        <option value="">— pick field —</option>
        {FIELDS.map((f) => <option key={f.key} value={f.key}>{f.label}</option>)}
      </select>
      <select style={{ ...sel, width: 160, flexShrink: 0 }} value={cond.operator} onChange={(e) => onChange({ ...cond, operator: e.target.value, value: '' })}>
        <option value="">— operator —</option>
        {ops.map((op) => <option key={op} value={op}>{op.replace(/_/g, ' ')}</option>)}
      </select>
      {needsValue && (
        <input
          style={{ ...inp, flexShrink: 0, width: 220 }}
          value={cond.value}
          placeholder={fieldDef?.placeholder ?? 'value'}
          onChange={(e) => onChange({ ...cond, value: e.target.value })}
        />
      )}
      <button onClick={onRemove} className="p-1 rounded hover:bg-red-50 flex-shrink-0" style={{ color: '#f87171' }}>
        <Trash2 size={14} />
      </button>
    </div>
  )
}

function RuleCard({ rule, onUpdate, onDelete, onSimulate }: {
  rule: PolicyRule
  onUpdate: (r: PolicyRule) => void
  onDelete: () => void
  onSimulate: () => void
}) {
  const [open, setOpen] = useState(true)
  const actionDef = ACTIONS.find((a) => a.value === rule.action)

  const addCond = () => {
    const conds = rule._localConditions ?? []
    onUpdate({ ...rule, _localConditions: [...conds, { id: uid(), field: '', operator: '', value: '' }] })
  }

  const updateCond = (idx: number, c: Condition) => {
    const conds = [...(rule._localConditions ?? [])]
    conds[idx] = c
    onUpdate({ ...rule, _localConditions: conds })
  }

  const removeCond = (idx: number) => {
    const conds = (rule._localConditions ?? []).filter((_, i) => i !== idx)
    onUpdate({ ...rule, _localConditions: conds })
  }

  return (
    <div style={{ ...card, padding: 0, overflow: 'hidden' }}>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3" style={{ borderBottom: open ? '0.5px solid var(--clavex-border)' : 'none', background: rule.enabled ? 'white' : 'rgba(0,0,0,0.02)' }}>
        <GripVertical size={14} style={{ color: 'var(--clavex-neutral)', flexShrink: 0 }} />
        <input
          style={{ ...inp, flex: 1, fontWeight: 600, border: 'none', padding: '2px 0', background: 'transparent' }}
          value={rule.name}
          onChange={(e) => onUpdate({ ...rule, name: e.target.value })}
          placeholder="Rule name…"
        />
        <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{ background: `${actionDef?.color}22`, color: actionDef?.color }}>
          {actionDef?.label ?? rule.action}
        </span>
        <span className="text-xs" style={{ color: 'var(--clavex-neutral)', whiteSpace: 'nowrap' }}>
          Priority {rule.priority}
        </span>
        <button
          onClick={() => onUpdate({ ...rule, enabled: !rule.enabled })}
          className="text-xs px-2 py-0.5 rounded-full"
          style={{ background: rule.enabled ? 'rgba(93,202,165,0.12)' : 'rgba(0,0,0,0.05)', color: rule.enabled ? 'var(--clavex-primary)' : 'var(--clavex-neutral)' }}
        >
          {rule.enabled ? 'ON' : 'OFF'}
        </button>
        <button onClick={onSimulate} className="p-1 rounded hover:bg-green-50" style={{ color: 'var(--clavex-primary)' }} title="Preview">
          <Play size={14} />
        </button>
        <button onClick={onDelete} className="p-1 rounded hover:bg-red-50" style={{ color: '#f87171' }} title="Delete rule">
          <Trash2 size={14} />
        </button>
        <button onClick={() => setOpen((o) => !o)} className="p-1 rounded" style={{ color: 'var(--clavex-neutral)' }}>
          {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Body */}
      {open && (
        <div className="px-4 py-4 space-y-4">
          {/* Action + Priority row */}
          <div className="flex gap-3">
            <div style={{ flex: 1 }}>
              <p className="text-xs font-semibold mb-1.5 uppercase tracking-wide" style={{ color: 'var(--clavex-ink-muted)' }}>Action</p>
              <select style={sel} value={rule.action} onChange={(e) => onUpdate({ ...rule, action: e.target.value as Action })}>
                {ACTIONS.map((a) => <option key={a.value} value={a.value}>{a.label}</option>)}
              </select>
            </div>
            <div style={{ width: 120 }}>
              <p className="text-xs font-semibold mb-1.5 uppercase tracking-wide" style={{ color: 'var(--clavex-ink-muted)' }}>Priority</p>
              <input style={inp} type="number" min={1} max={9999} value={rule.priority}
                onChange={(e) => onUpdate({ ...rule, priority: parseInt(e.target.value) || 100 })} />
            </div>
          </div>

          {/* Conditions */}
          <div>
            <p className="text-xs font-semibold mb-2 uppercase tracking-wide" style={{ color: 'var(--clavex-ink-muted)' }}>
              Conditions <span style={{ color: 'var(--clavex-neutral)', fontWeight: 400 }}>(ALL must match — leave empty = always matches)</span>
            </p>
            <div className="space-y-2">
              {(rule._localConditions ?? []).map((cond, i) => (
                <ConditionRow key={cond.id} cond={cond} onChange={(c) => updateCond(i, c)} onRemove={() => removeCond(i)} />
              ))}
            </div>
            <button onClick={addCond} className="mt-2 flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg"
              style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }}>
              <Plus size={12} /> Add condition
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Simulate panel ────────────────────────────────────────────────────────────

function SimPanel({ orgId }: { orgId: string; rules?: PolicyRule[] }) {
  const [form, setForm] = useState({ user_id: '', ip_address: '', country: '', request_time: '' })
  const [result, setResult] = useState<SimResult | null>(null)
  const [loading, setLoading] = useState(false)
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null)

  const run = useCallback(async (f: typeof form) => {
    setLoading(true)
    try {
      const body: Record<string, unknown> = {}
      Object.entries(f).forEach(([k, v]) => { if (v) body[k] = v })
      const res = await api.post(`/organizations/${orgId}/auth-policies/simulate`, body)
      setResult(res.data)
    } catch {
      setResult(null)
    } finally {
      setLoading(false)
    }
  }, [orgId])

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const next = { ...form, [k]: e.target.value }
    setForm(next)
    if (debounce.current) clearTimeout(debounce.current)
    debounce.current = setTimeout(() => run(next), 500)
  }

  const outcome = result?.outcome
  const outcomeColor = outcome?.action === 'allow' ? 'var(--clavex-primary)' : outcome?.action === 'deny' ? '#f87171' : '#fbbf24'
  const OutcomeIcon = outcome?.action === 'allow' ? CheckCircle : outcome?.action === 'deny' ? XCircle : AlertCircle

  return (
    <div style={card}>
      <h3 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: 'var(--clavex-ink)' }}>
        <Play size={14} style={{ color: 'var(--clavex-primary)' }} /> Live Preview
        {loading && <RefreshCw size={12} className="animate-spin ml-auto" style={{ color: 'var(--clavex-neutral)' }} />}
      </h3>
      <div className="space-y-2 mb-4">
        {[
          { k: 'user_id' as const, label: 'User ID' },
          { k: 'ip_address' as const, label: 'IP address' },
          { k: 'country' as const, label: 'Country (IT, DE…)' },
          { k: 'request_time' as const, label: 'Request time (ISO 8601)' },
        ].map(({ k, label }) => (
          <div key={k}>
            <p className="text-[11px] font-medium mb-1 uppercase tracking-wide" style={{ color: 'var(--clavex-ink-muted)' }}>{label}</p>
            <input style={inp} value={form[k]} onChange={set(k)} placeholder="leave empty = any" />
          </div>
        ))}
      </div>
      {result && outcome && (
        <div className="rounded-lg p-3" style={{ background: `${outcomeColor}14`, border: `1px solid ${outcomeColor}40` }}>
          <div className="flex items-center gap-2 mb-2">
            <OutcomeIcon size={16} style={{ color: outcomeColor }} />
            <span className="font-bold text-sm capitalize" style={{ color: outcomeColor }}>{outcome.action.replace('_', ' ')}</span>
          </div>
          {result.trace.map((t, i) => (
            <div key={i} className="flex items-center gap-2 text-xs py-0.5">
              <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: t.matched ? outcomeColor : 'var(--clavex-border)' }} />
              <span style={{ color: t.matched ? 'var(--clavex-ink)' : 'var(--clavex-neutral)' }}>{t.rule_name}</span>
              {t.matched && <span className="ml-auto font-medium" style={{ color: outcomeColor }}>→ {t.action}</span>}
            </div>
          ))}
        </div>
      )}
      {!result && !loading && (
        <p className="text-xs text-center py-4" style={{ color: 'var(--clavex-neutral)' }}>
          Fill in the fields above — result appears automatically
        </p>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function PolicyEditorPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const [rules, setRules] = useState<PolicyRule[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState<string | null>(null)
  const [showTemplates, setShowTemplates] = useState(false)

  const load = useCallback(async () => {
    if (!orgId) return
    setLoading(true)
    try {
      const res = await api.get(`/organizations/${orgId}/auth-policies`)
      const rows = toArr<PolicyRule>(res.data)
      setRules(rows.map((r) => ({
        ...r,
        _localConditions: apiToConditions(r.conditions ?? {}),
      })))
    } catch {
      toast.error('Failed to load policies')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { load() }, [load])

  const addRule = () => {
    setRules((rs) => [...rs, {
      name: 'New rule',
      priority: 100,
      enabled: true,
      action: 'allow',
      conditions: {},
      _localConditions: [{ id: uid(), field: '', operator: '', value: '' }],
    }])
  }

  const updateRule = (idx: number, r: PolicyRule) => {
    setRules((rs) => rs.map((x, i) => i === idx ? r : x))
  }

  const deleteRule = async (idx: number) => {
    const rule = rules[idx]
    if (rule.id) {
      try {
        await api.delete(`/organizations/${orgId}/auth-policies/${rule.id}`)
        toast.success('Rule deleted')
      } catch {
        toast.error('Delete failed')
        return
      }
    }
    setRules((rs) => rs.filter((_, i) => i !== idx))
  }

  const saveRule = async (idx: number) => {
    const rule = rules[idx]
    if (!orgId) return
    setSaving(rule.id ?? `new-${idx}`)
    try {
      const payload = {
        name: rule.name,
        priority: rule.priority,
        enabled: rule.enabled,
        action: rule.action,
        conditions: conditionsToAPI(rule._localConditions ?? []),
      }
      if (rule.id) {
        const res = await api.put(`/organizations/${orgId}/auth-policies/${rule.id}`, payload)
        setRules((rs) => rs.map((r, i) => i === idx ? { ...res.data, _localConditions: rule._localConditions } : r))
        toast.success('Rule updated')
      } else {
        const res = await api.post(`/organizations/${orgId}/auth-policies`, payload)
        setRules((rs) => rs.map((r, i) => i === idx ? { ...res.data, _localConditions: rule._localConditions } : r))
        toast.success('Rule created')
      }
    } catch {
      toast.error('Save failed')
    } finally {
      setSaving(null)
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center py-24">
      <RefreshCw size={24} className="animate-spin" style={{ color: 'var(--clavex-primary)' }} />
    </div>
  )

  return (
    <div>
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>Clavex Shield</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
            Visual condition builder for auth-flow rules — evaluated before every login
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowTemplates(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold"
            style={{ background: 'white', color: 'var(--clavex-ink)', border: '0.5px solid var(--clavex-border)' }}
          >
            <Layers size={14} /> From template
          </button>
          <button onClick={addRule} className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold"
            style={{ background: 'var(--clavex-primary)', color: 'white' }}>
            <Plus size={14} /> New rule
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Rules list — 2/3 width */}
        <div className="xl:col-span-2 space-y-4">
          {rules.length === 0 && (
            <div className="text-center py-16" style={card}>
              <Shield size={32} className="mx-auto mb-3" style={{ color: 'var(--clavex-border)' }} />
              <p className="font-semibold" style={{ color: 'var(--clavex-ink)' }}>No rules yet</p>
              <p className="text-sm mt-1" style={{ color: 'var(--clavex-neutral)' }}>Click "New rule" to add your first policy.</p>
            </div>
          )}
          {rules.map((rule, idx) => (
            <div key={rule.id ?? `new-${idx}`} className="relative">
              <RuleCard
                rule={rule}
                onUpdate={(r) => updateRule(idx, r)}
                onDelete={() => deleteRule(idx)}
                onSimulate={() => {/* focus simulate panel */}}
              />
              <div className="flex justify-end mt-2">
                <button
                  onClick={() => saveRule(idx)}
                  disabled={saving === (rule.id ?? `new-${idx}`)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold"
                  style={{ background: 'var(--clavex-primary)', color: 'white' }}
                >
                  {saving === (rule.id ?? `new-${idx}`)
                    ? <RefreshCw size={12} className="animate-spin" />
                    : <Save size={12} />}
                  {rule.id ? 'Save' : 'Deploy'}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Live preview — 1/3 width */}
        <div className="xl:col-span-1">
          {orgId && <SimPanel orgId={orgId} rules={rules} />}
        </div>
      </div>

      {showTemplates && (
        <TemplatesModal
          onLoad={(newRules) => {
            setRules((rs) => [...rs, ...newRules])
            toast.success(`${newRules.length} draft rules added — review and save each one`)
          }}
          onClose={() => setShowTemplates(false)}
        />
      )}
    </div>
  )
}
