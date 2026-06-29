import { useEffect, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import {
  Plus, RefreshCw, QrCode, Send, Clock, CheckCircle,
  XCircle, AlertCircle, Smartphone, Mail, Copy, Eye, Settings, Trash2
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface VCIConfig {
  id: string
  vct: string
  display_name?: string
  source_idp_type?: string | null
  claims_mapping?: Record<string, string>
  credential_format?: string
}

interface Offer {
  id: string
  vct: string
  user_id?: string
  status: 'pending' | 'used' | 'expired'
  expires_at: string
  created_at: string
  credential_offer_uri?: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function relTime(ts: string) {
  const diff = (new Date(ts).getTime() - Date.now()) / 1000
  if (diff < 0) return 'Expired'
  if (diff < 60) return `${Math.round(diff)}s`
  if (diff < 3600) return `${Math.round(diff / 60)}m`
  return `${Math.round(diff / 3600)}h`
}

function StatusBadge({ status }: { status: Offer['status'] }) {
  const styles: Record<string, { color: string; bg: string; icon: typeof CheckCircle; label: string }> = {
    pending:  { color: 'var(--clavex-primary)', bg: 'rgba(93,202,165,0.12)', icon: Clock,        label: 'Pending'  },
    used:     { color: '#a78bfa',               bg: 'rgba(167,139,250,0.12)', icon: CheckCircle,  label: 'Used'     },
    expired:  { color: '#f87171',               bg: 'rgba(239,68,68,0.1)',   icon: XCircle,      label: 'Expired'  },
  }
  const s = styles[status] ?? styles.pending
  const Icon = s.icon
  return (
    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium"
      style={{ background: s.bg, color: s.color }}>
      <Icon size={10} /> {s.label}
    </span>
  )
}

// ── Styles ────────────────────────────────────────────────────────────────────

const card: React.CSSProperties = { background: 'white', border: '0.5px solid var(--clavex-border)', borderRadius: 12, padding: '20px 24px' }
const inp: React.CSSProperties = { background: 'white', color: 'var(--clavex-ink)', border: '0.5px solid var(--clavex-border-subtle)', borderRadius: 8, padding: '7px 11px', fontSize: 13, outline: 'none', width: '100%' }
const sel: React.CSSProperties = { ...inp, cursor: 'pointer' }
const lbl: React.CSSProperties = { display: 'block', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--clavex-ink-muted)', marginBottom: 4 }

// ── Create offer modal ────────────────────────────────────────────────────────

interface CreateResult { offer_id: string; credential_offer_uri: string; expires_at: string }

function CreateOfferModal({ configs, orgId, onCreated, onClose }: {
  configs: VCIConfig[]
  orgId: string
  onCreated: (r: CreateResult) => void
  onClose: () => void
}) {
  const [vct, setVct] = useState(configs[0]?.vct ?? '')
  const [userId, setUserId] = useState('')
  const [txCode, setTxCode] = useState('')
  const [ttl, setTtl] = useState('15')
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    if (!vct) { toast.error('Select a credential type'); return }
    setLoading(true)
    try {
      const body: Record<string, unknown> = { vct, ttl_mins: parseInt(ttl) || 15 }
      if (userId.trim()) body.user_id = userId.trim()
      if (txCode.trim()) body.tx_code = txCode.trim()
      const res = await api.post(`/organizations/${orgId}/oid4vci/offers`, body)
      onCreated(res.data)
    } catch {
      toast.error('Failed to create offer')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.55)' }}>
      <div className="rounded-xl w-full max-w-lg" style={{ background: 'white', border: '0.5px solid var(--clavex-border)' }}>
        <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--clavex-border)' }}>
          <h3 className="text-base font-semibold" style={{ color: 'var(--clavex-ink)' }}>New credential offer</h3>
          <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>Create a pre-authorized code offer for a citizen / user</p>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label style={lbl}>Credential type (VCT) <span style={{ color: '#f87171' }}>*</span></label>
            <select style={sel} value={vct} onChange={(e) => setVct(e.target.value)}>
              {configs.map((c) => <option key={c.id} value={c.vct}>{c.display_name ?? c.vct}</option>)}
            </select>
          </div>
          <div>
            <label style={lbl}>Linked user ID <span style={{ color: 'var(--clavex-neutral)', fontWeight: 400, textTransform: 'none' }}>(optional — enables auto-fill of send recipient)</span></label>
            <input style={inp} value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="UUID of the user receiving the credential" />
          </div>
          <div>
            <label style={lbl}>Transaction code (PIN) <span style={{ color: 'var(--clavex-neutral)', fontWeight: 400, textTransform: 'none' }}>(optional — extra security factor)</span></label>
            <input style={inp} value={txCode} onChange={(e) => setTxCode(e.target.value)} placeholder="e.g. 1234" />
            <p className="text-[11px] mt-1" style={{ color: 'var(--clavex-neutral)' }}>Send this PIN separately to the user — they must enter it in their wallet.</p>
          </div>
          <div>
            <label style={lbl}>Expires in (minutes)</label>
            <input style={{ ...inp, width: 80 }} type="number" min={1} max={1440} value={ttl} onChange={(e) => setTtl(e.target.value)} />
          </div>
        </div>
        <div className="px-6 py-4 border-t flex justify-end gap-3" style={{ borderColor: 'var(--clavex-border)' }}>
          <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg" style={{ color: 'var(--clavex-ink-subtle)' }}>Cancel</button>
          <button onClick={submit} disabled={loading}
            className="px-4 py-2 text-sm font-semibold rounded-lg flex items-center gap-2"
            style={{ background: 'var(--clavex-primary)', color: 'white' }}>
            {loading ? <RefreshCw size={14} className="animate-spin" /> : <Plus size={14} />}
            Create offer
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Edit config modal ─────────────────────────────────────────────────────────

const IDP_OPTIONS = [
  { value: '',              label: 'None (manual / webhook)' },
  { value: 'spid',         label: 'SPID (Italy)' },
  { value: 'cie',          label: 'CIE 3.0 (Italy)' },
  { value: 'itsme',        label: 'itsme (Belgium/NL)' },
  { value: 'franceconnect', label: 'FranceConnect' },
  { value: 'bundid',       label: 'BundID (Germany)' },
  { value: 'digid',        label: 'DigiD (Netherlands)' },
]

const SPID_PRESETS: Record<string, string> = {
  given_name:   'metadata.spid_name',
  family_name:  'metadata.spid_family_name',
  tax_id_code:  'metadata.spid_fiscal_number',
  birth_date:   'metadata.spid_date_of_birth',
  birth_place:  'metadata.spid_place_of_birth',
  email:        'metadata.spid_email',
}

const CIE_PRESETS: Record<string, string> = {
  given_name:   'metadata.cie_name',
  family_name:  'metadata.cie_family_name',
  tax_id_code:  'metadata.cie_fiscal_number',
  birth_date:   'metadata.cie_date_of_birth',
}

function EditConfigModal({ config, orgId, onSaved, onClose }: {
  config: VCIConfig
  orgId: string
  onSaved: () => void
  onClose: () => void
}) {
  const [idpType, setIdpType] = useState(config.source_idp_type ?? '')
  const [pairs, setPairs] = useState<{ k: string; v: string }[]>(() =>
    Object.entries(config.claims_mapping ?? {}).map(([k, v]) => ({ k, v }))
  )
  const [loading, setLoading] = useState(false)

  const applyPreset = (type: string) => {
    const presets = type === 'spid' ? SPID_PRESETS : type === 'cie' ? CIE_PRESETS : null
    if (presets) setPairs(Object.entries(presets).map(([k, v]) => ({ k, v })))
  }

  const handleIdpChange = (val: string) => {
    setIdpType(val)
    if (pairs.length === 0) applyPreset(val)
  }

  const save = async () => {
    setLoading(true)
    const mapping = Object.fromEntries(pairs.filter(p => p.k.trim()).map(p => [p.k.trim(), p.v.trim()]))
    try {
      await api.patch(`/organizations/${orgId}/oid4vci/configs/${config.id}`, {
        source_idp_type: idpType || null,
        claims_mapping: mapping,
      })
      toast.success('Configuration saved')
      onSaved()
      onClose()
    } catch {
      toast.error('Failed to save configuration')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.55)' }}>
      <div className="rounded-xl w-full max-w-xl max-h-[90vh] flex flex-col" style={{ background: 'white', border: '0.5px solid var(--clavex-border)' }}>
        <div className="px-6 py-4 border-b flex-shrink-0" style={{ borderColor: 'var(--clavex-border)' }}>
          <h3 className="text-base font-semibold" style={{ color: 'var(--clavex-ink)' }}>Configure credential type</h3>
          <p className="text-xs mt-0.5 font-mono" style={{ color: 'var(--clavex-neutral)' }}>{config.vct}</p>
        </div>
        <div className="px-6 py-5 space-y-5 overflow-y-auto">
          {/* IdP source */}
          <div>
            <label style={lbl}>Identity provider source</label>
            <select style={sel} value={idpType} onChange={e => handleIdpChange(e.target.value)}>
              {IDP_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
            {idpType && (
              <p className="text-[11px] mt-1.5" style={{ color: 'var(--clavex-neutral)' }}>
                After login via {IDP_OPTIONS.find(o => o.value === idpType)?.label}, Clavex will automatically create an offer for this credential type using the verified IdP claims.
              </p>
            )}
          </div>

          {/* Claims mapping */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label style={{ ...lbl, marginBottom: 0 }}>Claims mapping</label>
              <div className="flex gap-2">
                {idpType && (
                  <button onClick={() => applyPreset(idpType)} className="text-[11px] px-2 py-1 rounded"
                    style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }}>
                    Apply {idpType.toUpperCase()} preset
                  </button>
                )}
                <button onClick={() => setPairs(p => [...p, { k: '', v: '' }])} className="text-[11px] px-2 py-1 rounded"
                  style={{ background: 'rgba(0,0,0,0.04)', color: 'var(--clavex-ink-subtle)' }}>
                  + Add field
                </button>
              </div>
            </div>
            <p className="text-[11px] mb-3" style={{ color: 'var(--clavex-neutral)' }}>
              Map credential field names to source attribute paths (e.g. <code className="bg-gray-100 px-1 rounded">metadata.spid_name</code>).
            </p>
            {pairs.length === 0 ? (
              <p className="text-[12px] py-3 text-center" style={{ color: 'var(--clavex-border)' }}>No mappings — credential will be issued with empty claims unless a webhook injects data.</p>
            ) : (
              <div className="space-y-2">
                {pairs.map((p, i) => (
                  <div key={i} className="flex gap-2 items-center">
                    <input style={{ ...inp, flex: 1 }} placeholder="field name" value={p.k}
                      onChange={e => setPairs(ps => ps.map((x, j) => j === i ? { ...x, k: e.target.value } : x))} />
                    <span style={{ color: 'var(--clavex-neutral)', fontSize: 12 }}>→</span>
                    <input style={{ ...inp, flex: 2 }} placeholder="metadata.spid_name" value={p.v}
                      onChange={e => setPairs(ps => ps.map((x, j) => j === i ? { ...x, v: e.target.value } : x))} />
                    <button onClick={() => setPairs(ps => ps.filter((_, j) => j !== i))}
                      className="p-1.5 rounded" style={{ color: '#f87171' }}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="px-6 py-4 border-t flex justify-end gap-3 flex-shrink-0" style={{ borderColor: 'var(--clavex-border)' }}>
          <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg" style={{ color: 'var(--clavex-ink-subtle)' }}>Cancel</button>
          <button onClick={save} disabled={loading}
            className="px-4 py-2 text-sm font-semibold rounded-lg flex items-center gap-2"
            style={{ background: 'var(--clavex-primary)', color: 'white' }}>
            {loading ? <RefreshCw size={14} className="animate-spin" /> : <CheckCircle size={14} />}
            Save
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Send offer modal ──────────────────────────────────────────────────────────

function SendOfferModal({ offerId, orgId, onClose }: { offerId: string; orgId: string; onClose: () => void }) {
  const [channel, setChannel] = useState<'sms' | 'email'>('email')
  const [to, setTo] = useState('')
  const [loading, setLoading] = useState(false)
  const [sent, setSent] = useState(false)

  const submit = async () => {
    setLoading(true)
    try {
      await api.post(`/organizations/${orgId}/oid4vci/offers/${offerId}/send`, { channel, to: to || undefined })
      setSent(true)
      toast.success(`Offer sent via ${channel}`)
    } catch {
      toast.error('Send failed — check your SMS/email gateway configuration')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.55)' }}>
      <div className="rounded-xl w-full max-w-md" style={{ background: 'white', border: '0.5px solid var(--clavex-border)' }}>
        <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--clavex-border)' }}>
          <h3 className="text-base font-semibold" style={{ color: 'var(--clavex-ink)' }}>Send offer to citizen</h3>
          <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>Deliver the deep link via SMS or email — citizen taps to open wallet</p>
        </div>
        {sent ? (
          <div className="px-6 py-10 text-center">
            <CheckCircle size={36} className="mx-auto mb-3" style={{ color: 'var(--clavex-primary)' }} />
            <p className="font-semibold" style={{ color: 'var(--clavex-ink)' }}>Offer sent successfully</p>
            <p className="text-sm mt-1" style={{ color: 'var(--clavex-neutral)' }}>The citizen will receive the deep link and can open their wallet by tapping it.</p>
            <button onClick={onClose} className="mt-4 px-4 py-2 rounded-lg text-sm font-semibold"
              style={{ background: 'var(--clavex-primary)', color: 'white' }}>Close</button>
          </div>
        ) : (
          <>
            <div className="px-6 py-5 space-y-4">
              <div>
                <label style={lbl}>Channel</label>
                <div className="grid grid-cols-2 gap-2">
                  {(['email', 'sms'] as const).map((ch) => (
                    <button key={ch} onClick={() => setChannel(ch)}
                      className="flex items-center gap-2 rounded-lg px-3 py-3"
                      style={{ background: channel === ch ? 'rgba(93,202,165,0.12)' : 'rgba(0,0,0,0.02)', border: `0.5px solid ${channel === ch ? 'var(--clavex-primary)' : 'var(--clavex-border-subtle)'}` }}>
                      {ch === 'email' ? <Mail size={16} style={{ color: channel === ch ? 'var(--clavex-primary)' : 'var(--clavex-neutral)' }} /> : <Smartphone size={16} style={{ color: channel === ch ? 'var(--clavex-primary)' : 'var(--clavex-neutral)' }} />}
                      <span className="text-sm font-medium capitalize" style={{ color: 'var(--clavex-ink)' }}>{ch === 'sms' ? 'SMS' : 'Email'}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label style={lbl}>
                  {channel === 'sms' ? 'Phone number' : 'Email address'}
                  <span className="ml-1 font-normal lowercase" style={{ letterSpacing: 0 }}>
                    (leave empty to use linked user's {channel === 'sms' ? 'phone' : 'email'})
                  </span>
                </label>
                <input style={inp} value={to} onChange={(e) => setTo(e.target.value)}
                  placeholder={channel === 'sms' ? '+39333xxxxxxx' : 'citizen@example.com'} />
              </div>
              {channel === 'sms' && (
                <div className="rounded-lg px-3 py-2.5" style={{ background: 'rgba(251,191,36,0.08)', border: '0.5px solid rgba(251,191,36,0.3)' }}>
                  <p className="text-xs" style={{ color: '#b45309' }}>
                    SMS requires a configured Twilio/SNS/Vonage gateway in <strong>Settings → SMS</strong>.
                  </p>
                </div>
              )}
            </div>
            <div className="px-6 py-4 border-t flex justify-end gap-3" style={{ borderColor: 'var(--clavex-border)' }}>
              <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg" style={{ color: 'var(--clavex-ink-subtle)' }}>Cancel</button>
              <button onClick={submit} disabled={loading}
                className="px-4 py-2 text-sm font-semibold rounded-lg flex items-center gap-2"
                style={{ background: 'var(--clavex-primary)', color: 'white' }}>
                {loading ? <RefreshCw size={14} className="animate-spin" /> : <Send size={14} />}
                Send offer
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ── QR Modal ──────────────────────────────────────────────────────────────────

function QRModal({ offerId, orgId, onClose }: { offerId: string; orgId: string; onClose: () => void }) {
  const [qrSrc, setQrSrc] = useState<string | null>(null)
  const [qrError, setQrError] = useState(false)

  useEffect(() => {
    const apiUrl = import.meta.env.VITE_API_URL ?? ''
    const url = `${apiUrl}/api/v1/organizations/${orgId}/oid4vci/offers/${offerId}/qr?size=320`
    fetch(url, { credentials: 'include' })
      .then((r) => {
        if (!r.ok) throw new Error(`${r.status}`)
        return r.blob()
      })
      .then((blob) => setQrSrc(URL.createObjectURL(blob)))
      .catch(() => setQrError(true))
    return () => { if (qrSrc) URL.revokeObjectURL(qrSrc) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [offerId, orgId])
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.55)' }}>
      <div className="rounded-xl p-6 flex flex-col items-center gap-4" style={{ background: 'white', border: '0.5px solid var(--clavex-border)', maxWidth: 380 }}>
        <h3 className="text-base font-semibold" style={{ color: 'var(--clavex-ink)' }}>Scan QR to open wallet</h3>
        {qrError ? (
          <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--clavex-danger, #ef4444)' }}>
            <AlertCircle size={18} /> Failed to load QR code
          </div>
        ) : qrSrc ? (
          <img src={qrSrc} alt="Credential offer QR code" style={{ width: 280, height: 280, borderRadius: 8 }} />
        ) : (
          <div style={{ width: 280, height: 280, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRadius: 8, background: '#f5f5f5' }}>
            <RefreshCw size={28} className="animate-spin" style={{ color: 'var(--clavex-neutral)' }} />
          </div>
        )}
        <p className="text-xs text-center" style={{ color: 'var(--clavex-neutral)' }}>
          The wallet app will start the pre-authorized code flow automatically after scanning.
        </p>
        <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm font-semibold"
          style={{ background: 'var(--clavex-primary)', color: 'white' }}>Close</button>
      </div>
    </div>
  )
}

// ── Offer row ─────────────────────────────────────────────────────────────────

function OfferRow({ offer, orgId, onRefresh }: {
  offer: Offer; orgId: string; onRefresh: () => void
}) {
  const [sendOpen, setSendOpen] = useState(false)
  const [qrOpen, setQrOpen] = useState(false)
  const isPending = offer.status === 'pending' && new Date(offer.expires_at) > new Date()
  const expiresIn = relTime(offer.expires_at)

  const copyURI = () => {
    if (offer.credential_offer_uri) {
      navigator.clipboard.writeText(offer.credential_offer_uri)
      toast.success('Deep link copied')
    }
  }

  return (
    <>
      <tr style={{ borderBottom: '0.5px solid var(--clavex-border-subtle)' }}>
        <td className="py-3 pr-4">
          <p className="text-xs font-mono truncate max-w-[200px]" style={{ color: 'var(--clavex-ink)' }}>{offer.id}</p>
        </td>
        <td className="py-3 pr-4">
          <span className="text-xs font-medium px-1.5 py-0.5 rounded" style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }}>
              {offer.vct.split('/').slice(-1)[0] ?? offer.vct}
          </span>
        </td>
        <td className="py-3 pr-4"><StatusBadge status={offer.status} /></td>
        <td className="py-3 pr-4 text-xs" style={{ color: offer.status === 'pending' ? 'var(--clavex-ink)' : 'var(--clavex-neutral)', whiteSpace: 'nowrap' }}>
          {isPending ? `Expires in ${expiresIn}` : offer.status === 'expired' ? 'Expired' : 'Used'}
        </td>
        <td className="py-3">
          <div className="flex items-center gap-1.5">
            {isPending && (
              <>
                <button onClick={() => setSendOpen(true)} className="flex items-center gap-1 px-2 py-1 rounded text-xs"
                  style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }} title="Send via SMS/email">
                  <Send size={10} /> Send
                </button>
                <button onClick={() => setQrOpen(true)} className="flex items-center gap-1 px-2 py-1 rounded text-xs"
                  style={{ background: 'rgba(0,0,0,0.04)', color: 'var(--clavex-ink-subtle)' }} title="Show QR code">
                  <QrCode size={10} /> QR
                </button>
                {offer.credential_offer_uri && (
                  <button onClick={copyURI} className="p-1 rounded" style={{ color: 'var(--clavex-neutral)' }} title="Copy deep link">
                    <Copy size={12} />
                  </button>
                )}
              </>
            )}
          </div>
        </td>
      </tr>
      {sendOpen && <SendOfferModal offerId={offer.id} orgId={orgId} onClose={() => { setSendOpen(false); onRefresh() }} />}
      {qrOpen && <QRModal offerId={offer.id} orgId={orgId} onClose={() => setQrOpen(false)} />}
    </>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CredentialOffersPage() {
  const { orgId } = useAuthStore()
  const [configs, setConfigs] = useState<VCIConfig[]>([])
  const [offers, setOffers] = useState<Offer[]>([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [newOffer, setNewOffer] = useState<CreateResult | null>(null)
  const [seeding, setSeeding] = useState<string | null>(null)
  const [editingConfig, setEditingConfig] = useState<VCIConfig | null>(null)

  const load = useCallback(async () => {
    if (!orgId) return
    setLoading(true)
    try {
      const [cfgRes, offersRes] = await Promise.all([
        api.get(`/organizations/${orgId}/oid4vci/configs`),
        api.get(`/organizations/${orgId}/oid4vci/offers`),
      ])
      setConfigs(toArr<VCIConfig>(cfgRes.data))
      setOffers(toArr<Offer>(offersRes.data))
    } catch {
      toast.error('Failed to load offers')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { load() }, [load])

  const seedPreset = async (preset: 'seed-mdl' | 'seed-it-wallet') => {
    if (!orgId) return
    setSeeding(preset)
    try {
      await api.post(`/organizations/${orgId}/oid4vci/catalog/${preset}`, {})
      toast.success('Credential type configured')
      await load()
    } catch {
      toast.error('Failed to configure credential type')
    } finally {
      setSeeding(null)
    }
  }

  const handleCreated = (r: CreateResult) => {
    setCreating(false)
    setNewOffer(r)
    load()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>Clavex Wallet</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
            OID4VCI pre-authorized code offers · issue digital credentials via QR or deep link
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} disabled={loading} className="p-2 rounded-lg"
            style={{ background: 'rgba(0,0,0,0.04)', color: 'var(--clavex-neutral)' }}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
          <button onClick={() => setCreating(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold"
            style={{ background: 'var(--clavex-primary)', color: 'white' }}>
            <Plus size={14} /> New offer
          </button>
        </div>
      </div>

      {/* New offer result banner */}
      {newOffer && (
        <div className="rounded-xl p-4" style={{ background: 'rgba(93,202,165,0.1)', border: '0.5px solid rgba(93,202,165,0.4)' }}>
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle size={16} style={{ color: 'var(--clavex-primary)' }} />
            <p className="font-semibold text-sm" style={{ color: 'var(--clavex-ink)' }}>Offer created — now send it to the citizen</p>
          </div>
          <p className="text-xs font-mono truncate" style={{ color: 'var(--clavex-neutral)' }}>{newOffer.credential_offer_uri}</p>
          <div className="flex gap-2 mt-3">
            <button onClick={() => { navigator.clipboard.writeText(newOffer.credential_offer_uri); toast.success('Copied') }}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded text-xs"
              style={{ background: 'white', color: 'var(--clavex-ink)' }}>
              <Copy size={11} /> Copy link
            </button>
            <button onClick={() => { setNewOffer(null) }} className="ml-auto text-xs" style={{ color: 'var(--clavex-neutral)' }}>
              Dismiss
            </button>
          </div>
        </div>
      )}

      {configs.length === 0 && !loading ? (
        <div style={card}>
          <div className="flex items-center gap-2 mb-4">
            <AlertCircle size={16} style={{ color: 'var(--clavex-border)' }} />
            <p className="font-semibold text-sm" style={{ color: 'var(--clavex-ink)' }}>No identity credential types configured</p>
          </div>
          <p className="text-sm mb-5" style={{ color: 'var(--clavex-neutral)' }}>
            Set up one-click presets for eIDAS 2.0 identity credentials issued via OID4VCI.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <button
              onClick={() => seedPreset('seed-mdl')}
              disabled={seeding !== null}
              className="flex items-start gap-3 p-4 rounded-xl text-left transition-colors"
              style={{ background: 'rgba(93,202,165,0.06)', border: '0.5px solid rgba(93,202,165,0.25)' }}>
              <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
                style={{ background: 'rgba(93,202,165,0.15)' }}>
                {seeding === 'seed-mdl' ? <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--clavex-primary)' }} /> : <QrCode size={16} style={{ color: 'var(--clavex-primary)' }} />}
              </div>
              <div>
                <p className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>Mobile Driving Licence (mDL)</p>
                <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>ISO 18013-5 · org.iso.18013.5.1.mDL</p>
              </div>
            </button>
            <button
              onClick={() => seedPreset('seed-it-wallet')}
              disabled={seeding !== null}
              className="flex items-start gap-3 p-4 rounded-xl text-left transition-colors"
              style={{ background: 'rgba(245,200,66,0.05)', border: '0.5px solid rgba(245,200,66,0.25)' }}>
              <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
                style={{ background: 'rgba(245,200,66,0.12)' }}>
                {seeding === 'seed-it-wallet' ? <RefreshCw size={16} className="animate-spin" style={{ color: '#b45309' }} /> : <AlertCircle size={16} style={{ color: '#b45309' }} />}
              </div>
              <div>
                <p className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>EU PID / IT-Wallet</p>
                <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>EUDIW · eu.europa.ec.eudi.pid.1 · SPID auto-offer</p>
              </div>
            </button>
          </div>
        </div>
      ) : (
        <>
        {/* Credential type cards */}
        <div style={card}>
          <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--clavex-ink)' }}>
            <QrCode size={13} className="inline mr-1.5" style={{ color: 'var(--clavex-primary)' }} />
            Credential types
          </h2>
          <div className="space-y-2">
            {configs.map(cfg => (
              <div key={cfg.id} className="flex items-center justify-between rounded-lg px-4 py-3"
                style={{ background: 'rgba(0,0,0,0.02)', border: '0.5px solid var(--clavex-border-subtle)' }}>
                <div className="min-w-0">
                  <p className="text-sm font-medium truncate" style={{ color: 'var(--clavex-ink)' }}>{cfg.display_name ?? cfg.vct}</p>
                  <p className="text-[11px] font-mono truncate mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>{cfg.vct}</p>
                  <div className="flex gap-2 mt-1 flex-wrap">
                    {cfg.credential_format && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-medium" style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }}>{cfg.credential_format}</span>
                    )}
                    {cfg.source_idp_type ? (
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-medium" style={{ background: 'rgba(99,102,241,0.1)', color: '#6366f1' }}>
                        IdP: {cfg.source_idp_type.toUpperCase()}
                      </span>
                    ) : (
                      <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(0,0,0,0.04)', color: 'var(--clavex-neutral)' }}>no IdP</span>
                    )}
                    {cfg.claims_mapping && Object.keys(cfg.claims_mapping).length > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(0,0,0,0.04)', color: 'var(--clavex-neutral)' }}>
                        {Object.keys(cfg.claims_mapping).length} claims mapped
                      </span>
                    )}
                  </div>
                </div>
                <button onClick={() => setEditingConfig(cfg)}
                  className="ml-4 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium flex-shrink-0"
                  style={{ border: '0.5px solid var(--clavex-border)', color: 'var(--clavex-ink-subtle)' }}>
                  <Settings size={12} /> Configure
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Offer history */}
        <div style={card}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>
              <Eye size={13} className="inline mr-1.5" style={{ color: 'var(--clavex-primary)' }} />
              Offer history
            </h2>
          </div>
          {loading ? (
            <div className="flex justify-center py-8">
              <RefreshCw size={20} className="animate-spin" style={{ color: 'var(--clavex-primary)' }} />
            </div>
          ) : offers.length === 0 ? (
            <p className="text-center py-8 text-sm" style={{ color: 'var(--clavex-neutral)' }}>
              No offers yet — click "New offer" to create one.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                    {['Offer ID', 'Type', 'Status', 'Expiry', 'Actions'].map((h) => (
                      <th key={h} className="text-left pb-2 pr-4 text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--clavex-ink-muted)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {offers.slice(0, 30).map((offer) => (
                    <OfferRow key={offer.id} offer={offer} orgId={orgId!} onRefresh={load} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        </>
      )}

      {creating && orgId && (
        <CreateOfferModal configs={configs} orgId={orgId} onCreated={handleCreated} onClose={() => setCreating(false)} />
      )}
      {editingConfig && orgId && (
        <EditConfigModal config={editingConfig} orgId={orgId} onSaved={load} onClose={() => setEditingConfig(null)} />
      )}
    </div>
  )
}
