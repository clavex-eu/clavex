import { useEffect, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { ShieldCheck, ShieldX, Trash2, Plus, Network } from 'lucide-react'

// ── API types ────────────────────────────────────────────────────────────────

interface IPRule {
  id: string
  org_id: string
  type: 'allow' | 'deny'
  cidr: string
  notes: string
  created_by: string | null
  created_at: string
}

// ── Styles ───────────────────────────────────────────────────────────────────

const card = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
} as const

const badge = (type: 'allow' | 'deny') => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 4,
  borderRadius: 6,
  padding: '2px 8px',
  fontSize: 12,
  fontWeight: 600,
  background: type === 'allow' ? '#16a34a18' : '#dc262618',
  color: type === 'allow' ? '#16a34a' : '#dc2626',
} as const)

// ── Component ────────────────────────────────────────────────────────────────

export default function IPRules() {
  const { orgId } = useAuthStore()
  const [rules, setRules] = useState<IPRule[]>([])
  const [loading, setLoading] = useState(true)

  // New-rule form state
  const [formType, setFormType] = useState<'allow' | 'deny'>('deny')
  const [formCIDR, setFormCIDR] = useState('')
  const [formNotes, setFormNotes] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const load = useCallback(async () => {
    if (!orgId) return
    try {
      const { data } = await api.get<IPRule[]>(`/organizations/${orgId}/ip-rules`)
      setRules(data ?? [])
    } catch {
      toast.error('Failed to load IP rules')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { load() }, [load])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!orgId) return
    setSubmitting(true)
    try {
      await api.post(`/organizations/${orgId}/ip-rules`, {
        type: formType,
        cidr: formCIDR.trim(),
        notes: formNotes.trim(),
      })
      toast.success('Rule created')
      setFormCIDR('')
      setFormNotes('')
      load()
    } catch (err: any) {
      toast.error(err?.response?.data?.message ?? 'Failed to create rule')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (ruleId: string) => {
    if (!orgId) return
    if (!window.confirm('Delete this IP rule?')) return
    try {
      await api.delete(`/organizations/${orgId}/ip-rules/${ruleId}`)
      toast.success('Rule deleted')
      setRules(prev => prev.filter(r => r.id !== ruleId))
    } catch {
      toast.error('Failed to delete rule')
    }
  }

  const allows = rules.filter(r => r.type === 'allow')
  const denies = rules.filter(r => r.type === 'deny')

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Network className="w-6 h-6" style={{ color: 'var(--clavex-primary)' }} />
          <div>
            <h1 className="text-xl font-semibold">IP Rules</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Deny or allow specific CIDR ranges before authentication policies run.
              Deny rules are checked first and always take precedence.
            </p>
          </div>
        </div>
      </div>

      {/* Add rule form */}
      <div style={card}>
        <h2 className="text-sm font-semibold mb-4">Add Rule</h2>
        <form onSubmit={handleCreate} className="flex flex-wrap gap-3 items-end">
          {/* Type selector */}
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500 font-medium">Type</label>
            <select
              value={formType}
              onChange={e => setFormType(e.target.value as 'allow' | 'deny')}
              className="border rounded px-3 py-2 text-sm"
              style={{ minWidth: 90 }}
            >
              <option value="deny">Deny</option>
              <option value="allow">Allow</option>
            </select>
          </div>

          {/* CIDR */}
          <div className="flex flex-col gap-1 flex-1" style={{ minWidth: 200 }}>
            <label className="text-xs text-gray-500 font-medium">CIDR</label>
            <input
              type="text"
              value={formCIDR}
              onChange={e => setFormCIDR(e.target.value)}
              placeholder="e.g. 10.0.0.0/8 or 203.0.113.5/32"
              required
              className="border rounded px-3 py-2 text-sm"
            />
          </div>

          {/* Notes */}
          <div className="flex flex-col gap-1 flex-1" style={{ minWidth: 200 }}>
            <label className="text-xs text-gray-500 font-medium">Notes (optional)</label>
            <input
              type="text"
              value={formNotes}
              onChange={e => setFormNotes(e.target.value)}
              placeholder="e.g. Corporate VPN"
              className="border rounded px-3 py-2 text-sm"
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="flex items-center gap-2 rounded px-4 py-2 text-sm font-medium text-white"
            style={{ background: 'var(--clavex-primary)', opacity: submitting ? 0.6 : 1 }}
          >
            <Plus className="w-4 h-4" />
            Add
          </button>
        </form>
      </div>

      {/* Rules list */}
      {loading ? (
        <p className="text-sm text-gray-400">Loading…</p>
      ) : rules.length === 0 ? (
        <div style={card} className="text-center text-sm text-gray-400 py-8">
          No IP rules configured. All IPs are permitted by default.
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          {/* Deny rules */}
          {denies.length > 0 && (
            <div style={card}>
              <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <ShieldX className="w-4 h-4 text-red-500" />
                Deny Rules
                <span className="text-xs font-normal text-gray-400">({denies.length})</span>
              </h2>
              <RuleTable rules={denies} onDelete={handleDelete} />
            </div>
          )}

          {/* Allow rules */}
          {allows.length > 0 && (
            <div style={card}>
              <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-green-600" />
                Allow Rules
                <span className="text-xs font-normal text-gray-400">({allows.length})</span>
              </h2>
              <p className="text-xs text-gray-400 mb-3">
                IPs matching allow rules bypass the policy engine (Shield, geo-blocking, etc.).
              </p>
              <RuleTable rules={allows} onDelete={handleDelete} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Sub-components ───────────────────────────────────────────────────────────

function RuleTable({ rules, onDelete }: { rules: IPRule[]; onDelete: (id: string) => void }) {
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-xs text-gray-400 border-b">
          <th className="text-left pb-2 font-medium">CIDR</th>
          <th className="text-left pb-2 font-medium">Type</th>
          <th className="text-left pb-2 font-medium">Notes</th>
          <th className="text-left pb-2 font-medium">Added</th>
          <th className="pb-2" />
        </tr>
      </thead>
      <tbody>
        {rules.map(rule => (
          <tr key={rule.id} className="border-b last:border-0">
            <td className="py-2 font-mono text-xs">{rule.cidr}</td>
            <td className="py-2">
              <span style={badge(rule.type)}>
                {rule.type === 'allow' ? <ShieldCheck className="w-3 h-3" /> : <ShieldX className="w-3 h-3" />}
                {rule.type}
              </span>
            </td>
            <td className="py-2 text-gray-500">{rule.notes || '—'}</td>
            <td className="py-2 text-gray-400">{new Date(rule.created_at).toLocaleDateString()}</td>
            <td className="py-2 text-right">
              <button
                onClick={() => onDelete(rule.id)}
                className="p-1 rounded hover:bg-red-50 text-gray-400 hover:text-red-500 transition-colors"
                title="Delete rule"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
