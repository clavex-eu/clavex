import { useEffect, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  GraduationCap, Award, Star, RefreshCw, Plus, Send, QrCode,
  Zap, ChevronDown, ChevronUp, CheckCircle, Copy, Webhook, Eye, EyeOff, Sparkles, BarChart2,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { PageHeader, Button } from '@/components/ui'

// ── Types ──────────────────────────────────────────────────────────────────────

interface SchemaField {
  name: string
  label: string
  type: 'string' | 'date' | 'number' | 'url'
  mandatory: boolean
}

interface VCConfig {
  id: string
  vct: string
  display_name: string
  description?: string
  category: 'training' | 'qualification' | 'badge' | 'identity'
  schema_fields: SchemaField[]
  ttl_seconds: number
  pre_issuance_webhook_url?: string
}

interface Offer {
  id: string
  vct: string
  status: 'pending' | 'used' | 'expired'
  expires_at: string
  created_at: string
  credential_offer_uri?: string
}

// ── Styles ─────────────────────────────────────────────────────────────────────

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

// ── Category meta ──────────────────────────────────────────────────────────────

const categoryMeta = {
  training:      { icon: GraduationCap, color: '#2563eb', bg: '#eff6ff', label: 'Training Certificate' },
  qualification: { icon: Award,         color: '#7c3aed', bg: '#f5f3ff', label: 'Professional Qualification' },
  badge:         { icon: Star,          color: '#d97706', bg: '#fffbeb', label: 'Competency Badge' },
  identity:      { icon: CheckCircle,   color: '#16a34a', bg: '#f0fdf4', label: 'Identity' },
}

function categoryIcon(cat: string) {
  const m = categoryMeta[cat as keyof typeof categoryMeta] ?? categoryMeta.identity
  const Icon = m.icon
  return <Icon className="w-4 h-4 flex-shrink-0" style={{ color: m.color }} />
}

// ── Issue modal ────────────────────────────────────────────────────────────────

function IssueModal({
  config, orgId, onCreated, onClose,
}: {
  config: VCConfig
  orgId: string
  onCreated: (offer: Offer & { credential_offer_uri: string }) => void
  onClose: () => void
}) {
  const [userId, setUserId] = useState('')
  const [txCode, setTxCode] = useState('')
  const [ttl, setTtl] = useState('60')
  const [fields, setFields] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(false)

  const meta = categoryMeta[config.category as keyof typeof categoryMeta] ?? categoryMeta.identity

  const setField = (name: string, val: string) => setFields((f) => ({ ...f, [name]: val }))

  const submit = async () => {
    // Validate mandatory fields.
    for (const f of config.schema_fields) {
      if (f.mandatory && !fields[f.name]?.trim()) {
        toast.error(`"${f.label}" is required`)
        return
      }
    }
    setLoading(true)
    try {
      const payload: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(fields)) {
        if (v.trim()) payload[k] = v.trim()
      }
      const body: Record<string, unknown> = {
        vct: config.vct,
        ttl_minutes: parseInt(ttl) || 60,
        payload,
      }
      if (userId.trim()) body.user_id = userId.trim()
      if (txCode.trim()) body.tx_code = txCode.trim()
      const res = await api.post(`/organizations/${orgId}/oid4vci/offers`, body)
      onCreated(res.data)
    } catch {
      toast.error('Failed to create credential offer')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto py-8"
      style={{ background: 'rgba(0,0,0,0.55)' }}>
      <div className="rounded-xl w-full max-w-xl mx-4 my-auto" style={{ background: 'white', border: '0.5px solid var(--clavex-border)' }}>
        {/* Header */}
        <div className="px-6 py-4 border-b flex items-center gap-3" style={{ borderColor: 'var(--clavex-border)' }}>
          <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: meta.bg }}>
            {categoryIcon(config.category)}
          </div>
          <div>
            <h3 className="text-base font-semibold" style={{ color: 'var(--clavex-ink)' }}>
              Issue {config.display_name}
            </h3>
            <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>
              {config.description}
            </p>
          </div>
        </div>

        <div className="px-6 py-5 space-y-4 max-h-[60vh] overflow-y-auto">
          {/* Credential-specific fields */}
          {config.schema_fields.map((f) => (
            <div key={f.name}>
              <label style={lbl}>
                {f.label}
                {f.mandatory && <span style={{ color: '#ef4444' }}> *</span>}
              </label>
              <input
                style={inp}
                type={f.type === 'date' ? 'date' : f.type === 'number' ? 'number' : f.type === 'url' ? 'url' : 'text'}
                value={fields[f.name] ?? ''}
                onChange={(e) => setField(f.name, e.target.value)}
                placeholder={f.label}
              />
            </div>
          ))}

          <div className="border-t pt-4" style={{ borderColor: 'var(--clavex-border)' }}>
            <div className="space-y-3">
              <div>
                <label style={lbl}>Linked user ID <span style={{ color: 'var(--clavex-neutral)', fontWeight: 400, textTransform: 'none' }}>(optional)</span></label>
                <input style={inp} value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="UUID of the recipient" />
              </div>
              <div>
                <label style={lbl}>PIN (tx_code) <span style={{ color: 'var(--clavex-neutral)', fontWeight: 400, textTransform: 'none' }}>(optional extra security)</span></label>
                <input style={inp} value={txCode} onChange={(e) => setTxCode(e.target.value)} placeholder="e.g. 1234 — share separately with recipient" />
              </div>
              <div>
                <label style={lbl}>Expires in (minutes)</label>
                <input style={{ ...inp, width: 80 }} type="number" min={1} max={10080} value={ttl} onChange={(e) => setTtl(e.target.value)} />
              </div>
            </div>
          </div>
        </div>

        <div className="px-6 py-4 border-t flex justify-end gap-3" style={{ borderColor: 'var(--clavex-border)' }}>
          <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg"
            style={{ color: 'var(--clavex-ink-subtle)' }}>Cancel</button>
          <button onClick={submit} disabled={loading}
            className="px-4 py-2 text-sm font-semibold rounded-lg flex items-center gap-2"
            style={{ background: meta.color, color: 'white', opacity: loading ? 0.7 : 1 }}>
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            Issue credential
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Credential type card ────────────────────────────────────────────────────────

function CredentialTypeCard({
  config, orgId, onOffersChange,
}: {
  config: VCConfig
  orgId: string
  onOffersChange: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [issuing, setIssuing] = useState(false)
  const [result, setResult] = useState<(Offer & { credential_offer_uri: string }) | null>(null)
  const [hookURL, setHookURL] = useState(config.pre_issuance_webhook_url ?? '')
  const [hookSecret, setHookSecret] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const [hookSaving, setHookSaving] = useState(false)
  const meta = categoryMeta[config.category as keyof typeof categoryMeta] ?? categoryMeta.identity

  const saveHook = async () => {
    setHookSaving(true)
    try {
      await api.patch(`/organizations/${orgId}/oid4vci/configs/${config.id}`, {
        pre_issuance_webhook_url: hookURL.trim() || null,
        pre_issuance_webhook_secret: hookSecret.trim() || null,
      })
      toast.success(hookURL.trim() ? 'Hook configured' : 'Hook cleared')
      setHookSecret('')
    } catch {
      toast.error('Failed to save hook config')
    } finally {
      setHookSaving(false)
    }
  }

  const hookConfigured = !!(config.pre_issuance_webhook_url || hookURL.trim())

  const copyURI = () => {
    if (result?.credential_offer_uri) {
      navigator.clipboard.writeText(result.credential_offer_uri).then(() => toast.success('Copied!'))
    }
  }

  return (
    <div style={card}>
      {/* Card header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: meta.bg }}>
            {categoryIcon(config.category)}
          </div>
          <div>
            <p className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>
              {config.display_name}
            </p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>
              {meta.label} · {Math.round(config.ttl_seconds / (365 * 24 * 3600))} yr validity
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={() => setIssuing(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg"
            style={{ background: meta.color, color: 'white' }}>
            <Send className="w-3.5 h-3.5" />
            Issue
          </button>
          <button
            onClick={() => setExpanded((e) => !e)}
            className="p-1.5 rounded-lg hover:bg-gray-50"
            style={{ color: 'var(--clavex-neutral)' }}>
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Schema fields preview */}
      {expanded && (
        <div className="mt-4 pt-4 border-t space-y-1" style={{ borderColor: 'var(--clavex-border)' }}>
          <p className="text-xs font-semibold mb-2" style={{ color: 'var(--clavex-ink-muted)' }}>
            Claim fields ({config.schema_fields.length})
          </p>
          {config.schema_fields.map((f) => (
            <div key={f.name} className="flex items-center justify-between text-xs">
              <span style={{ color: 'var(--clavex-ink)' }}>{f.label}</span>
              <div className="flex items-center gap-2">
                <span className="rounded px-1.5 py-0.5" style={{ background: '#f1f5f9', color: '#64748b' }}>
                  {f.type}
                </span>
                {f.mandatory && (
                  <span className="rounded px-1.5 py-0.5" style={{ background: '#fef2f2', color: '#ef4444' }}>
                    required
                  </span>
                )}
              </div>
            </div>
          ))}
          <p className="text-[11px] mt-2 break-all" style={{ color: 'var(--clavex-neutral)' }}>
            VCT: <code>{config.vct}</code>
          </p>

          {/* Pre-issuance webhook config */}
          <div className="mt-4 pt-4 border-t" style={{ borderColor: 'var(--clavex-border)' }}>
            <div className="flex items-center gap-2 mb-2">
              <Webhook className="w-3.5 h-3.5" style={{ color: hookConfigured ? '#16a34a' : 'var(--clavex-neutral)' }} />
              <p className="text-xs font-semibold" style={{ color: 'var(--clavex-ink-muted)' }}>
                Pre-issuance webhook
              </p>
              {hookConfigured && (
                <span className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
                  style={{ background: '#f0fdf4', color: '#16a34a', border: '0.5px solid #bbf7d0' }}>
                  Active
                </span>
              )}
            </div>
            <p className="text-[11px] mb-3" style={{ color: 'var(--clavex-neutral)' }}>
              Clavex calls this endpoint before issuing the credential. The hook can approve/deny
              and enrich the payload on-demand (e.g. LMS completion, qualification lookup).
            </p>
            <div className="space-y-2">
              <div>
                <label style={lbl}>Webhook URL</label>
                <input
                  style={inp}
                  type="url"
                  placeholder="https://lms.university.eu/clavex/verify"
                  value={hookURL}
                  onChange={(e) => setHookURL(e.target.value)}
                />
              </div>
              <div>
                <label style={lbl}>Signing secret <span style={{ color: 'var(--clavex-neutral)', fontWeight: 400, textTransform: 'none' }}>(HMAC-SHA256 — leave blank to keep existing)</span></label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <input
                      style={{ ...inp, paddingRight: 36 }}
                      type={showSecret ? 'text' : 'password'}
                      placeholder={config.pre_issuance_webhook_url ? '••••••••  (unchanged)' : 'Optional'}
                      value={hookSecret}
                      onChange={(e) => setHookSecret(e.target.value)}
                    />
                    <button
                      type="button"
                      onClick={() => setShowSecret((s) => !s)}
                      className="absolute right-2 top-1/2 -translate-y-1/2"
                      style={{ color: 'var(--clavex-neutral)' }}>
                      {showSecret ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>
              <div className="flex gap-2 pt-1">
                <button
                  onClick={saveHook}
                  disabled={hookSaving}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg"
                  style={{ background: 'var(--clavex-primary)', color: 'white', opacity: hookSaving ? 0.7 : 1 }}>
                  {hookSaving ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Webhook className="w-3 h-3" />}
                  Save hook
                </button>
                {(config.pre_issuance_webhook_url || hookURL.trim()) && (
                  <button
                    onClick={() => { setHookURL(''); setHookSecret(''); saveHook() }}
                    className="px-3 py-1.5 text-xs rounded-lg"
                    style={{ color: '#ef4444', border: '0.5px solid #fecaca' }}>
                    Clear hook
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Offer result */}
      {result && (
        <div className="mt-4 pt-4 border-t" style={{ borderColor: 'var(--clavex-border)' }}>
          <p className="text-xs font-semibold mb-2 flex items-center gap-1.5" style={{ color: '#16a34a' }}>
            <CheckCircle className="w-3.5 h-3.5" /> Offer created — share the link with the recipient
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-[11px] break-all rounded px-3 py-2 truncate"
              style={{ background: '#f8fafc', color: 'var(--clavex-ink)', border: '0.5px solid var(--clavex-border)' }}>
              {result.credential_offer_uri}
            </code>
            <button onClick={copyURI} className="p-2 rounded-lg hover:bg-gray-50 flex-shrink-0"
              style={{ border: '0.5px solid var(--clavex-border)' }}>
              <Copy className="w-4 h-4" style={{ color: 'var(--clavex-neutral)' }} />
            </button>
          </div>
          <button onClick={() => { setResult(null); onOffersChange() }}
            className="text-xs mt-2" style={{ color: 'var(--clavex-neutral)' }}>
            Dismiss
          </button>
        </div>
      )}

      {issuing && (
        <IssueModal
          config={config}
          orgId={orgId}
          onCreated={(o) => { setResult(o); setIssuing(false); onOffersChange() }}
          onClose={() => setIssuing(false)}
        />
      )}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function VerifiedCredentials() {
  const orgId   = useAuthStore((s) => s.orgId)
  const orgSlug = useAuthStore((s) => s.orgSlug)
  const navigate = useNavigate()
  const [configs, setConfigs] = useState<VCConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [seeding, setSeeding] = useState(false)

  const loadCatalog = useCallback(async () => {
    if (!orgId) return
    try {
      const res = await api.get<VCConfig[]>(`/organizations/${orgId}/oid4vci/catalog`)
      setConfigs(res.data ?? [])
    } catch {
      // Catalog may be empty on first load.
    }
  }, [orgId])

  const loadRecentOffers = useCallback(async () => {
    if (!orgId) return
    try {
      const res = await api.get<Offer[]>(`/organizations/${orgId}/oid4vci/issued`)
      void res // available for future use
    } catch {
      // ignore
    }
  }, [orgId])

  const load = useCallback(async () => {
    setLoading(true)
    await Promise.all([loadCatalog(), loadRecentOffers()])
    setLoading(false)
  }, [loadCatalog, loadRecentOffers])

  useEffect(() => { load() }, [load])

  const seedCatalog = async () => {
    if (!orgId) return
    setSeeding(true)
    try {
      const res = await api.post(`/organizations/${orgId}/oid4vci/catalog/seed`, {})
      const data = res.data as { seeded: number; skipped: number; configs: VCConfig[] }
      setConfigs(data.configs ?? [])
      if (data.seeded > 0) {
        toast.success(`Seeded ${data.seeded} credential type${data.seeded > 1 ? 's' : ''}`)
      } else {
        toast.success('Catalog up-to-date')
      }
    } catch {
      toast.error('Failed to seed catalog')
    } finally {
      setSeeding(false)
    }
  }

  if (loading)
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-6 h-6 rounded-full" style={{ border: '2px solid var(--clavex-200)', borderTopColor: 'var(--clavex-primary)' }} />
      </div>
    )

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title="Clavex Verified"
        subtitle="Issue verifiable credentials for training, qualifications and competency badges via OID4VCI / eIDAS 2.0"
        action={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={load}>
              <RefreshCw className="h-4 w-4" /> Refresh
            </Button>
            <Button variant="secondary" size="sm" onClick={() => navigate(`/admin/${orgSlug}/credential-analytics`)}>
              <BarChart2 className="h-4 w-4" /> Analytics
            </Button>
            <Button variant="secondary" size="sm" onClick={() => navigate(`/admin/${orgSlug}/credential-schema-generator`)}>
              <Sparkles className="h-4 w-4" /> AI Schema
            </Button>
            <Button size="sm" loading={seeding} onClick={seedCatalog}>
              {!seeding && <Zap className="w-4 h-4" />}
              {configs.length === 0 ? 'Enable Clavex Verified' : 'Sync catalog'}
            </Button>
          </div>
        }
      />

      {/* Empty state */}
      {configs.length === 0 && (
        <div style={{ ...card, textAlign: 'center', padding: '48px 24px' }}>
          <Award className="w-10 h-10 mx-auto mb-3" style={{ color: 'var(--clavex-primary)', opacity: 0.4 }} />
          <p className="text-sm font-medium" style={{ color: 'var(--clavex-ink)' }}>
            No Verified credential types configured
          </p>
          <p className="text-xs mt-1 mb-4" style={{ color: 'var(--clavex-neutral)' }}>
            Click <strong>Enable Clavex Verified</strong> to seed the standard catalog:<br />
            Training Completion · Professional Qualification · Competency Badge
          </p>
          <button
            onClick={seedCatalog}
            disabled={seeding}
            className="inline-flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-semibold"
            style={{ background: 'var(--clavex-primary)', color: 'white' }}>
            <Zap className="w-4 h-4" />
            Enable Clavex Verified
          </button>
        </div>
      )}

      {/* Credential type cards */}
      {configs.length > 0 && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {configs.map((cfg) => (
            <CredentialTypeCard
              key={cfg.id}
              config={cfg}
              orgId={orgId!}
              onOffersChange={loadRecentOffers}
            />
          ))}
        </div>
      )}

      {/* How it works */}
      {configs.length > 0 && (
        <div style={card}>
          <p className="text-xs font-semibold mb-3" style={{ color: 'var(--clavex-ink-muted)' }}>
            HOW IT WORKS
          </p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-4 text-xs" style={{ color: 'var(--clavex-neutral)' }}>
            {[
              { icon: Send,        n: '1', label: 'Admin issues credential', desc: 'Fill in the claim fields and click Issue' },
              { icon: QrCode,      n: '2', label: 'Share the deep-link', desc: 'Send openid-credential-offer:// link via email/SMS/QR' },
              { icon: GraduationCap, n: '3', label: 'Holder accepts in wallet', desc: 'IT-Wallet, EUDIW or any OID4VCI wallet' },
              { icon: CheckCircle, n: '4', label: 'Verifier checks via OID4VP', desc: 'Employer / authority scans the holder\'s SD-JWT-VC' },
            ].map((s) => {
              const StepIcon = s.icon
              return (
                <div key={s.n} className="flex items-start gap-2">
                  <div className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 text-[10px] font-bold"
                    style={{ background: 'var(--clavex-50)', color: 'var(--clavex-700)' }}>{s.n}</div>
                  <div>
                    <p className="font-medium" style={{ color: 'var(--clavex-ink)' }}>{s.label}</p>
                    <p className="mt-0.5">{s.desc}</p>
                  </div>
                  <StepIcon className="hidden" />
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
