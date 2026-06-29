import { useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  Sparkles, Key, FileText, Shield, Search, Users,
  Cpu, ScrollText, RefreshCw, CheckCircle, Copy,
  ChevronDown, ChevronUp, Eye, EyeOff,
} from 'lucide-react'
import { PageHeader } from '@/components/ui'

// ── Shared styles ─────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}
const lbl: React.CSSProperties = {
  display: 'block', fontSize: 11, fontWeight: 700,
  letterSpacing: '0.08em', textTransform: 'uppercase',
  color: 'var(--clavex-ink-muted)', marginBottom: 6,
}
const inp: React.CSSProperties = {
  width: '100%', fontSize: 13, padding: '8px 12px',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 8, outline: 'none', boxSizing: 'border-box',
  color: 'var(--clavex-ink)', background: 'white',
}
const textarea: React.CSSProperties = {
  ...inp, minHeight: 120, resize: 'vertical', fontFamily: 'inherit',
}
const btn = (loading = false): React.CSSProperties => ({
  display: 'inline-flex', alignItems: 'center', gap: 6,
  padding: '8px 18px', fontSize: 13, fontWeight: 600,
  borderRadius: 8, border: 'none', cursor: loading ? 'not-allowed' : 'pointer',
  background: 'var(--clavex-primary)', color: 'white', opacity: loading ? 0.7 : 1,
})
const pre: React.CSSProperties = {
  background: '#f8fafc', border: '0.5px solid var(--clavex-border)',
  borderRadius: 8, padding: '12px 16px', fontSize: 12,
  fontFamily: 'monospace', overflowX: 'auto', whiteSpace: 'pre-wrap',
  maxHeight: 400, overflowY: 'auto',
  color: 'var(--clavex-ink)',
}

// ── Types ─────────────────────────────────────────────────────────────────────

type AiFeature = 'policy' | 'fga' | 'anomaly' | 'audit' | 'access_review' | 'lifecycle' | 'dpia'

interface Feature {
  id: AiFeature
  label: string
  icon: React.ElementType
  description: string
  placeholder: string
}

const FEATURES: Feature[] = [
  {
    id: 'policy',
    label: 'Policy Generator',
    icon: Shield,
    description: 'Describe your access control requirements in plain text — get a structured auth-flow policy JSON ready to save.',
    placeholder: 'E.g. "Block logins from Russia and China. Require MFA for all admin users outside office hours (8am–6pm UTC)."',
  },
  {
    id: 'fga',
    label: 'FGA Model Generator',
    icon: Cpu,
    description: 'Describe your permission model in plain language — get an OpenFGA 1.1 authorization model JSON.',
    placeholder: 'E.g. "A document system: owners can read/write, editors can write, viewers can only read. Teams inherit from org membership."',
  },
  {
    id: 'anomaly',
    label: 'Anomaly Explainer',
    icon: Sparkles,
    description: 'Paste risk signals from a login event — get a NIS2-ready natural language explanation and suggested action.',
    placeholder: '{"risk_score": 85, "country": "RU", "new_country": true, "user_email": "alice@example.com", "is_tor": false}',
  },
  {
    id: 'audit',
    label: 'Audit Log Query',
    icon: Search,
    description: 'Ask in plain language — the AI translates to structured filters and returns matching audit events.',
    placeholder: 'E.g. "Show all failed logins in the last 24 hours" or "Which admin created the most users this week?"',
  },
  {
    id: 'access_review',
    label: 'Access Review Suggestions',
    icon: Users,
    description: 'Enter a campaign ID — the AI pre-fills keep/revoke decisions for each pending (user, role) pair.',
    placeholder: 'Campaign UUID, e.g. 01924a3e-...',
  },
  {
    id: 'lifecycle',
    label: 'Lifecycle Rule Generator',
    icon: FileText,
    description: 'Describe a JML automation in plain text — get a structured lifecycle rule JSON ready to save.',
    placeholder: 'E.g. "When a new user joins Engineering, assign them the Developer role and add them to the Dev-Tools group."',
  },
  {
    id: 'dpia',
    label: 'DPIA Generator (GDPR Art.35)',
    icon: ScrollText,
    description: 'Describe a data processing activity — the AI drafts a complete GDPR Article 35 DPIA.',
    placeholder: 'E.g. "We process employee biometric data (facial recognition) for time-and-attendance tracking. Data stored 3 years, shared with payroll provider."',
  },
]

// ── API key config card ───────────────────────────────────────────────────────

function AIKeyConfig({ orgId, configured, onSaved }: {
  orgId: string; configured: boolean; onSaved: () => void
}) {
  const [key, setKey] = useState('')
  const [show, setShow] = useState(false)
  const [saving, setSaving] = useState(false)

  const save = async () => {
    if (!key.trim() && !configured) {
      toast.error('Enter an API key to configure AI features')
      return
    }
    setSaving(true)
    try {
      await api.put(`/organizations/${orgId}/ai/config`, {
        anthropic_api_key: key.trim() || null,
      })
      toast.success(key.trim() ? 'API key saved' : 'API key cleared')
      setKey('')
      onSaved()
    } catch {
      toast.error('Failed to save API key')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ ...card, display: 'flex', alignItems: 'flex-start', gap: 16 }}>
      <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
        style={{ background: configured ? '#f0fdf4' : '#faf5ff' }}>
        <Key className="w-5 h-5" style={{ color: configured ? '#16a34a' : 'var(--clavex-primary)' }} />
      </div>
      <div className="flex-1">
        <div className="flex items-center gap-2 mb-1">
          <p className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>
            Anthropic API Key
          </p>
          {configured && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
              style={{ background: '#f0fdf4', color: '#16a34a', border: '0.5px solid #bbf7d0' }}>
              Configured
            </span>
          )}
        </div>
        <p className="text-xs mb-3" style={{ color: 'var(--clavex-neutral)' }}>
          Used for all AI features below. Stored securely per-org. Get your key at{' '}
          <a href="https://console.anthropic.com" target="_blank" rel="noopener noreferrer"
            style={{ color: 'var(--clavex-primary)' }}>console.anthropic.com</a>.
        </p>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input
              style={{ ...inp, paddingRight: 36 }}
              type={show ? 'text' : 'password'}
              placeholder={configured ? '•••••••• (key already set — enter new to replace)' : 'sk-ant-...'}
              value={key}
              onChange={e => setKey(e.target.value)}
            />
            <button type="button" onClick={() => setShow(s => !s)}
              className="absolute right-2 top-1/2 -translate-y-1/2"
              style={{ color: 'var(--clavex-neutral)' }}>
              {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            </button>
          </div>
          <button onClick={save} disabled={saving} style={btn(saving)}>
            {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
            Save
          </button>
          {configured && (
            <button onClick={() => { setKey(''); save() }}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '8px 18px', fontSize: 13, fontWeight: 600, borderRadius: 8, border: 'none', cursor: 'pointer', background: '#ef4444', color: 'white' }}
              title="Clear API key">
              Clear
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Feature card ──────────────────────────────────────────────────────────────

function FeatureCard({ feature, orgId, enabled }: { feature: Feature; orgId: string; enabled: boolean }) {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<string | null>(null)

  const Icon = feature.icon

  const run = useCallback(async () => {
    if (!input.trim()) {
      toast.error('Enter a description or input')
      return
    }
    setLoading(true)
    setResult(null)
    try {
      let endpoint: string
      let body: Record<string, unknown>

      switch (feature.id) {
        case 'policy':
          endpoint = `/organizations/${orgId}/ai/suggest-policy`
          body = { description: input }
          break
        case 'fga':
          endpoint = `/organizations/${orgId}/ai/suggest-fga-model`
          body = { description: input }
          break
        case 'anomaly': {
          let signals: Record<string, unknown>
          try {
            signals = JSON.parse(input)
          } catch {
            signals = { raw_input: input }
          }
          endpoint = `/organizations/${orgId}/ai/explain-anomaly`
          body = { signals }
          break
        }
        case 'audit':
          endpoint = `/organizations/${orgId}/ai/nl-audit-query`
          body = { query: input }
          break
        case 'access_review':
          endpoint = `/organizations/${orgId}/ai/suggest-access-review`
          body = { campaign_id: input.trim() }
          break
        case 'lifecycle':
          endpoint = `/organizations/${orgId}/ai/suggest-lifecycle-rule`
          body = { description: input }
          break
        case 'dpia':
          endpoint = `/organizations/${orgId}/ai/suggest-dpia`
          body = { description: input }
          break
      }

      const res = await api.post(endpoint!, body)
      setResult(JSON.stringify(res.data, null, 2))
    } catch (e: unknown) {
      const err = e as { response?: { data?: { message?: string } } }
      const msg = err?.response?.data?.message ?? 'Request failed'
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }, [feature.id, input, orgId])

  const copy = () => {
    if (result) {
      navigator.clipboard.writeText(result).then(() => toast.success('Copied!'))
    }
  }

  return (
    <div style={card}>
      <div className="flex items-start gap-3">
        <div className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0"
          style={{ background: '#faf5ff' }}>
          <Icon className="w-4.5 h-4.5" style={{ color: 'var(--clavex-primary)' }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>
              {feature.label}
            </p>
            <button onClick={() => setOpen(o => !o)} className="p-1 rounded"
              style={{ color: 'var(--clavex-neutral)' }}>
              {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>
            {feature.description}
          </p>
        </div>
      </div>

      {open && (
        <div className="mt-4 space-y-3">
          {!enabled && (
            <div className="text-xs rounded-lg px-3 py-2"
              style={{ background: '#fef3c7', color: '#92400e', border: '0.5px solid #fcd34d' }}>
              ⚠️ Configure your Anthropic API key above to enable AI features.
            </div>
          )}
          <div>
            <label style={lbl}>Input</label>
            <textarea
              style={textarea}
              placeholder={feature.placeholder}
              value={input}
              onChange={e => setInput(e.target.value)}
              disabled={!enabled}
            />
          </div>
          <button onClick={run} disabled={loading || !enabled} style={btn(loading)}>
            {loading
              ? <><RefreshCw className="w-4 h-4 animate-spin" /> Running…</>
              : <><Sparkles className="w-4 h-4" /> Generate</>
            }
          </button>

          {result && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <label style={lbl}>Result</label>
                <button onClick={copy} className="p-1 rounded hover:bg-gray-50"
                  style={{ color: 'var(--clavex-neutral)' }}>
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
              <pre style={pre}>{result}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AIAssistant() {
  const orgId = useAuthStore(s => s.orgId)
  const [configured, setConfigured] = useState(false)
  const [checking, setChecking] = useState(true)

  const checkConfig = useCallback(async () => {
    if (!orgId) return
    setChecking(true)
    try {
      const res = await api.get<{ configured: boolean }>(`/organizations/${orgId}/ai/config`)
      setConfigured(res.data.configured)
    } catch {
      setConfigured(false)
    } finally {
      setChecking(false)
    }
  }, [orgId])

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useState(() => { checkConfig() })

  if (!orgId) return null

  return (
    <div className="space-y-5">
      <PageHeader
        title="AI Assistant"
        subtitle="Powered by Claude Opus 4.7 · API key stored per-org · Never shared with end-users"
      />

      {/* API key config */}
      {!checking && (
        <AIKeyConfig
          orgId={orgId}
          configured={configured}
          onSaved={checkConfig}
        />
      )}

      {/* Feature cards */}
      <div className="grid grid-cols-1 gap-4">
        {FEATURES.map(f => (
          <FeatureCard
            key={f.id}
            feature={f}
            orgId={orgId}
            enabled={configured}
          />
        ))}
      </div>

      {/* Footer note */}
      <div className="text-xs text-center pb-4" style={{ color: 'var(--clavex-neutral)' }}>
        AI responses are suggestions — always review before saving.
        The <code>ai_decision</code> login flow step also uses this API key.
      </div>
    </div>
  )
}
