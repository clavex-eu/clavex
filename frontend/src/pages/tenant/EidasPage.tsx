import { useState, useEffect } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Globe, Shield, CheckCircle, XCircle, Download, RefreshCw, Settings, Save } from 'lucide-react'

interface EidasConfig {
  id?: string
  entity_id: string
  eidas_node_url: string
  acs_url: string
  idp_cert_pem: string
  sp_cert_pem?: string
  requested_loa: string
  org_name: string
  org_display_name: string
  org_url: string
  contact_email: string
  is_active: boolean
}

const LOA_OPTIONS = [
  { value: 'http://eidas.europa.eu/LoA/low',         label: 'Low',         desc: 'username/password or equivalent' },
  { value: 'http://eidas.europa.eu/LoA/substantial', label: 'Substantial', desc: 'two-factor or equivalent' },
  { value: 'http://eidas.europa.eu/LoA/high',        label: 'High',        desc: 'hardware token or biometric' },
]

const EU_COUNTRIES = [
  'Austria','Belgium','Bulgaria','Croatia','Cyprus','Czechia','Denmark',
  'Estonia','Finland','France','Germany','Greece','Hungary','Ireland',
  'Italy','Latvia','Lithuania','Luxembourg','Malta','Netherlands','Poland',
  'Portugal','Romania','Slovakia','Slovenia','Spain','Sweden',
]

const card: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: 24,
}

const label: React.CSSProperties = {
  display: 'block',
  fontSize: 12,
  fontWeight: 600,
  color: 'var(--clavex-ink-subtle)',
  marginBottom: 4,
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
}

const input: React.CSSProperties = {
  background: 'white',
  color: 'var(--clavex-ink)',
  border: '0.5px solid var(--clavex-border-subtle)',
  borderRadius: 8,
  padding: '8px 12px',
  fontSize: 13,
  width: '100%',
  outline: 'none',
}

const textarea: React.CSSProperties = {
  ...input,
  fontFamily: 'monospace',
  fontSize: 11,
  minHeight: 100,
  resize: 'vertical',
}

export default function EidasPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const [cfg, setCfg] = useState<EidasConfig>({
    entity_id: '',
    eidas_node_url: '',
    acs_url: '',
    idp_cert_pem: '',
    requested_loa: 'http://eidas.europa.eu/LoA/substantial',
    org_name: '',
    org_display_name: '',
    org_url: '',
    contact_email: '',
    is_active: true,
  })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [configured, setConfigured] = useState(false)

  useEffect(() => {
    if (!orgId) return
    api.get(`/organizations/${orgId}/eidas`)
      .then(r => {
        setCfg(r.data)
        setConfigured(true)
      })
      .catch(err => {
        if (err.response?.status !== 404) {
          toast.error('Failed to load eIDAS config')
        }
      })
      .finally(() => setLoading(false))
  }, [orgId])

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!orgId) return
    setSaving(true)
    try {
      const r = await api.put(`/organizations/${orgId}/eidas`, cfg)
      setCfg(r.data)
      setConfigured(true)
      toast.success('eIDAS configuration saved')
    } catch {
      toast.error('Failed to save eIDAS configuration')
    } finally {
      setSaving(false)
    }
  }

  const downloadMetadata = async () => {
    if (!orgId) return
    try {
      const r = await api.get(`/organizations/${orgId}/eidas/metadata`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([r.data], { type: 'application/xml' }))
      const a = document.createElement('a')
      a.href = url
      a.download = 'sp-metadata.xml'
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      toast.error('Failed to download metadata')
    }
  }

  const field = (key: keyof EidasConfig, lbl: string, placeholder?: string) => (
    <div>
      <label style={label}>{lbl}</label>
      <input
        style={input}
        value={cfg[key] as string || ''}
        onChange={e => setCfg(p => ({ ...p, [key]: e.target.value }))}
        placeholder={placeholder}
      />
    </div>
  )

  if (loading) return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}>
      <RefreshCw size={22} style={{ animation: 'spin 1s linear infinite', opacity: 0.4 }} />
    </div>
  )

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, marginBottom: 28 }}>
        <div style={{
          width: 48, height: 48, borderRadius: 12,
          background: 'linear-gradient(135deg, #003399 0%, #FFCC00 100%)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
        }}>
          <Globe size={22} color="#fff" />
        </div>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: 'var(--clavex-ink)' }}>
            eIDAS Node Integration
          </h1>
          <p style={{ margin: '4px 0 0', fontSize: 13, color: 'var(--clavex-ink-subtle)' }}>
            One SAML integration → 27 EU member states. Accepts all notified national eIDs via
            the European eIDAS infrastructure.
          </p>
        </div>
        {configured && (
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <span style={{
              background: cfg.is_active ? 'rgba(93,202,165,0.12)' : 'rgba(239,68,68,0.12)',
              color: cfg.is_active ? 'var(--clavex-primary)' : '#f87171',
              padding: '4px 10px', borderRadius: 20, fontSize: 12, fontWeight: 600,
            }}>
              {cfg.is_active ? <><CheckCircle size={11} style={{ marginRight: 4 }} />Active</> : <><XCircle size={11} style={{ marginRight: 4 }} />Inactive</>}
            </span>
          </div>
        )}
      </div>

      {/* Country coverage pill cloud */}
      <div style={{ ...card, marginBottom: 20 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-neutral)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Coverage — {EU_COUNTRIES.length} EU Member States
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {EU_COUNTRIES.map(c => (
            <span key={c} style={{
              background: 'rgba(93,202,165,0.08)',
              border: '1px solid rgba(93,202,165,0.15)',
              color: 'var(--clavex-ink)',
              padding: '3px 10px',
              borderRadius: 20,
              fontSize: 11,
            }}>{c}</span>
          ))}
        </div>
      </div>

      {/* Config form */}
      <form onSubmit={handleSave}>
        <div style={{ ...card, marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 18 }}>
            <Settings size={15} style={{ color: 'var(--clavex-primary)' }} />
            <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--clavex-ink)' }}>SP Configuration</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            {field('entity_id', 'Entity ID (SP Metadata URL)', 'https://auth.example.com/acme/eidas/metadata')}
            {field('eidas_node_url', 'eIDAS Node SSO URL', 'https://eidas.agid.gov.it/EidasNode/ServiceProvider')}
            {field('acs_url', 'Assertion Consumer Service URL', 'https://auth.example.com/acme/eidas/callback')}
            <div>
              <label style={label}>Requested Level of Assurance</label>
              <select
                style={{ ...input, cursor: 'pointer' }}
                value={cfg.requested_loa}
                onChange={e => setCfg(p => ({ ...p, requested_loa: e.target.value }))}
              >
                {LOA_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label} — {o.desc}</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <div style={{ ...card, marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 14 }}>
            Organization Details <span style={{ fontSize: 11, fontWeight: 400, color: 'var(--clavex-neutral)' }}>(embedded in SP metadata)</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            {field('org_name', 'Organization Name', 'Acme Corp')}
            {field('org_display_name', 'Display Name', 'Acme Corp (IT)')}
            {field('org_url', 'Organization URL', 'https://www.example.com')}
            {field('contact_email', 'Technical Contact Email', 'security@example.com')}
          </div>
        </div>

        <div style={{ ...card, marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 4 }}>
            eIDAS Node Certificate (IdP)
          </div>
          <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginBottom: 12 }}>
            The signing certificate of the national eIDAS Connector/Node. Provided by the node operator
            (e.g. AgID for Italy). Used to verify SAML response signatures.
          </p>
          <textarea
            style={textarea}
            value={cfg.idp_cert_pem}
            onChange={e => setCfg(p => ({ ...p, idp_cert_pem: e.target.value }))}
            placeholder="-----BEGIN CERTIFICATE-----&#10;MIIBkTCB...&#10;-----END CERTIFICATE-----"
          />
        </div>

        <div style={{ ...card, marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 4 }}>
            SP Signing Certificate
          </div>
          <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginBottom: 12 }}>
            Leave blank to auto-generate a 2048-bit RSA self-signed certificate on first save.
            Submit the downloaded SP metadata to the eIDAS node operator for registration.
          </p>
          <textarea
            style={{ ...textarea, minHeight: 70 }}
            value={cfg.sp_cert_pem || ''}
            readOnly
            placeholder="Auto-generated on save (RSA 2048)"
          />
        </div>

        <div style={{ ...card, marginBottom: 20, display: 'flex', alignItems: 'center', gap: 12 }}>
          <Shield size={15} style={{ color: cfg.is_active ? 'var(--clavex-primary)' : '#f87171' }} />
          <span style={{ fontSize: 13, color: 'var(--clavex-ink)' }}>Enable eIDAS SSO for this organization</span>
          <label style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
            <div style={{
              width: 40, height: 22, borderRadius: 11,
              background: cfg.is_active ? 'var(--clavex-primary)' : 'rgba(232,244,240,0.15)',
              position: 'relative', transition: 'background 0.2s',
            }}>
              <div style={{
                position: 'absolute',
                top: 3, left: cfg.is_active ? 21 : 3,
                width: 16, height: 16, borderRadius: '50%',
                background: '#fff', transition: 'left 0.2s',
              }} />
            </div>
            <input
              type="checkbox"
              style={{ display: 'none' }}
              checked={cfg.is_active}
              onChange={e => setCfg(p => ({ ...p, is_active: e.target.checked }))}
            />
          </label>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button
            type="submit"
            disabled={saving}
            style={{
              background: 'var(--clavex-primary)',
              color: 'white',
              border: 'none',
              borderRadius: 8,
              padding: '10px 20px',
              fontSize: 13,
              fontWeight: 600,
              cursor: saving ? 'not-allowed' : 'pointer',
              opacity: saving ? 0.7 : 1,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <Save size={14} />
            {saving ? 'Saving…' : 'Save Configuration'}
          </button>
          {configured && (
            <button
              type="button"
              onClick={downloadMetadata}
              style={{
                background: 'rgba(93,202,165,0.1)',
                color: 'var(--clavex-primary)',
                border: '1px solid rgba(93,202,165,0.25)',
                borderRadius: 8,
                padding: '10px 20px',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <Download size={14} />
              Download SP Metadata XML
            </button>
          )}
        </div>
      </form>

      {/* Onboarding guide */}
      <div style={{ ...card, marginTop: 24, borderColor: 'rgba(255,204,0,0.2)' }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: '#fbbf24', marginBottom: 10 }}>
          Onboarding Steps
        </div>
        <ol style={{ margin: 0, paddingLeft: 18, color: 'var(--clavex-ink-muted)', fontSize: 12, lineHeight: 2 }}>
          <li>Configure the SP fields above and save (a signing certificate is auto-generated).</li>
          <li>Download the SP Metadata XML and submit it to your national eIDAS node operator (e.g. AgID for Italy).</li>
          <li>Obtain the eIDAS node's IdP certificate PEM from the operator and paste it above.</li>
          <li>The operator registers your SP and provides the production SSO URL — update <em>eIDAS Node SSO URL</em>.</li>
          <li>Add an "eIDAS" button to your login page pointing to{' '}
            <code style={{ background: 'rgba(255,255,255,0.05)', padding: '1px 4px', borderRadius: 3 }}>
              /:org_slug/eidas/sso?login_session_id=…
            </code>
          </li>
        </ol>
      </div>
    </div>
  )
}
