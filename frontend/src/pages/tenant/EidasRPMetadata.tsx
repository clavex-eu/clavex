import { useState } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  Download, Shield, FileJson, Info, ChevronDown, ChevronUp,
  Loader2, CheckCircle,
} from 'lucide-react'

// ── Data categories ───────────────────────────────────────────────────────────

const DATA_CATEGORY_OPTIONS = [
  { value: 'identity',          label: 'Identity (name, birth date)' },
  { value: 'tax_id',            label: 'Tax ID / Codice Fiscale' },
  { value: 'email',             label: 'Email address' },
  { value: 'phone',             label: 'Phone number' },
  { value: 'address',           label: 'Residential address' },
  { value: 'nationality',       label: 'Nationality / citizenship' },
  { value: 'driving_licence',   label: 'Driving licence (mDL)' },
  { value: 'health_insurance',  label: 'Health insurance (EHIC)' },
  { value: 'employment',        label: 'Employment status' },
  { value: 'biometric',         label: 'Biometric data (portrait)' },
]

// ── Component ─────────────────────────────────────────────────────────────────

export default function EidasRPMetadata() {
  const orgId   = useAuthStore(s => s.orgId)
  const orgSlug = useAuthStore(s => s.orgSlug)

  const [purpose, setPurpose]               = useState('')
  const [categories, setCategories]         = useState<string[]>(['identity', 'email'])
  const [retentionYears, setRetentionYears] = useState(1)
  const [contactEmail, setContactEmail]     = useState('')
  const [loading, setLoading]               = useState(false)
  const [previewData, setPreviewData]       = useState<object | null>(null)
  const [showPreview, setShowPreview]       = useState(false)

  // ── Helpers ───────────────────────────────────────────────────────────────

  function toggleCategory(value: string) {
    setCategories(prev =>
      prev.includes(value) ? prev.filter(c => c !== value) : [...prev, value]
    )
  }

  // ── Generate & Download ───────────────────────────────────────────────────

  async function handleGenerate() {
    if (!purpose.trim()) {
      toast.error('Purpose is required')
      return
    }
    if (categories.length === 0) {
      toast.error('Select at least one data category')
      return
    }

    setLoading(true)
    try {
      const params = new URLSearchParams({
        purpose:          purpose.trim(),
        data_categories:  categories.join(','),
        retention_years:  String(retentionYears),
        contact_email:    contactEmail.trim(),
      })

      const response = await api.get(
        `/organizations/${orgId}/eidas-rp-metadata?${params}`,
        { responseType: 'blob' }
      )

      // Parse blob to show preview
      const text = await (response.data as Blob).text()
      const json = JSON.parse(text)
      setPreviewData(json)
      setShowPreview(true)

      // Trigger download
      const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
      const a   = document.createElement('a')
      a.href     = url
      a.download = `${orgSlug}-eidas-rp-metadata.json`
      a.click()
      URL.revokeObjectURL(url)

      toast.success('eIDAS RP metadata downloaded')
    } catch {
      toast.error('Failed to generate metadata')
    } finally {
      setLoading(false)
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-10 h-10 rounded-lg"
          style={{ background: 'rgba(93,202,165,0.12)' }}>
          <Shield size={20} style={{ color: 'var(--clavex-accent)' }} />
        </div>
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--clavex-ink)' }}>
            eIDAS 2.0 Relying Party Metadata
          </h1>
          <p className="text-sm" style={{ color: 'var(--clavex-muted)' }}>
            Generate and download the signed entity configuration for Trust Anchor registration (AgID / eIDAS node).
          </p>
        </div>
      </div>

      {/* Info banner */}
      <div className="rounded-lg p-4 flex gap-3 text-sm"
        style={{ background: 'rgba(93,202,165,0.06)', border: '1px solid rgba(93,202,165,0.2)' }}>
        <Info size={16} className="flex-shrink-0 mt-0.5" style={{ color: 'var(--clavex-accent)' }} />
        <span style={{ color: 'var(--clavex-muted)' }}>
          The generated JSON bundle contains an <strong>entity_configuration JWT</strong> signed with this
          organisation's RS256 key, conforming to <strong>OpenID Federation 1.0</strong> and the
          eIDAS 2.0 Relying Party profile. Submit it to the AgID national registry at{' '}
          <a
            href="https://registry.servizicie.interno.gov.it/federation/enrollment"
            target="_blank" rel="noreferrer"
            style={{ color: 'var(--clavex-accent)', textDecoration: 'underline' }}
          >
            registry.servizicie.interno.gov.it
          </a>.
        </span>
      </div>

      {/* Wizard form */}
      <div className="rounded-xl p-6 space-y-5"
        style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>

        {/* Purpose */}
        <div>
          <label className="block text-sm font-medium mb-1" style={{ color: 'var(--clavex-ink)' }}>
            Data Processing Purpose <span style={{ color: '#ef4444' }}>*</span>
          </label>
          <textarea
            rows={3}
            value={purpose}
            onChange={e => setPurpose(e.target.value)}
            placeholder="Describe the purpose for which the user's identity data is requested, e.g. 'Authentication and age verification for access to regulated financial services'"
            className="w-full rounded-lg px-3 py-2 text-sm resize-none"
            style={{
              background: 'var(--clavex-surface)',
              border: '1px solid var(--clavex-border)',
              color: 'var(--clavex-ink)',
              outline: 'none',
            }}
          />
        </div>

        {/* Data categories */}
        <div>
          <label className="block text-sm font-medium mb-2" style={{ color: 'var(--clavex-ink)' }}>
            Data Categories Requested <span style={{ color: '#ef4444' }}>*</span>
          </label>
          <div className="grid grid-cols-2 gap-2">
            {DATA_CATEGORY_OPTIONS.map(opt => {
              const checked = categories.includes(opt.value)
              return (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => toggleCategory(opt.value)}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-left transition-colors"
                  style={{
                    background: checked ? 'rgba(93,202,165,0.15)' : 'var(--clavex-surface)',
                    border: `1px solid ${checked ? 'rgba(93,202,165,0.5)' : 'var(--clavex-border)'}`,
                    color: checked ? 'var(--clavex-accent)' : 'var(--clavex-muted)',
                    cursor: 'pointer',
                  }}
                >
                  {checked
                    ? <CheckCircle size={14} style={{ color: 'var(--clavex-accent)', flexShrink: 0 }} />
                    : <div style={{ width: 14, height: 14, borderRadius: 7, border: '1.5px solid var(--clavex-border)', flexShrink: 0 }} />
                  }
                  {opt.label}
                </button>
              )
            })}
          </div>
        </div>

        {/* Retention years */}
        <div>
          <label className="block text-sm font-medium mb-1" style={{ color: 'var(--clavex-ink)' }}>
            Data Retention Period (years)
          </label>
          <input
            type="number"
            min={1}
            max={30}
            value={retentionYears}
            onChange={e => setRetentionYears(Number(e.target.value))}
            className="w-32 rounded-lg px-3 py-2 text-sm"
            style={{
              background: 'var(--clavex-surface)',
              border: '1px solid var(--clavex-border)',
              color: 'var(--clavex-ink)',
              outline: 'none',
            }}
          />
        </div>

        {/* Contact email */}
        <div>
          <label className="block text-sm font-medium mb-1" style={{ color: 'var(--clavex-ink)' }}>
            DPO / Contact Email
          </label>
          <input
            type="email"
            value={contactEmail}
            onChange={e => setContactEmail(e.target.value)}
            placeholder="dpo@example.com"
            className="w-full rounded-lg px-3 py-2 text-sm"
            style={{
              background: 'var(--clavex-surface)',
              border: '1px solid var(--clavex-border)',
              color: 'var(--clavex-ink)',
              outline: 'none',
            }}
          />
        </div>

        {/* Submit */}
        <button
          type="button"
          onClick={handleGenerate}
          disabled={loading}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-opacity"
          style={{
            background: 'var(--clavex-accent)',
            color: '#0d1f1a',
            opacity: loading ? 0.6 : 1,
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          {loading
            ? <><Loader2 size={15} className="animate-spin" /> Generating…</>
            : <><Download size={15} /> Generate &amp; Download</>
          }
        </button>
      </div>

      {/* Preview */}
      {previewData && (
        <div className="rounded-xl overflow-hidden"
          style={{ border: '1px solid var(--clavex-border)' }}>
          <button
            type="button"
            onClick={() => setShowPreview(v => !v)}
            className="w-full flex items-center justify-between px-5 py-3 text-sm font-medium"
            style={{ background: 'var(--clavex-card)', color: 'var(--clavex-ink)', cursor: 'pointer' }}
          >
            <span className="flex items-center gap-2">
              <FileJson size={15} style={{ color: 'var(--clavex-accent)' }} />
              Metadata Preview
            </span>
            {showPreview ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
          </button>

          {showPreview && (
            <pre
              className="text-xs overflow-auto p-4"
              style={{
                background: 'var(--clavex-surface)',
                color: 'var(--clavex-muted)',
                maxHeight: 400,
              }}
            >
              {JSON.stringify(previewData, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}
