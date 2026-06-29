import { useEffect, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Shield, Smartphone, Globe, Wifi, Save, RefreshCw, Trash2, Plus, X, ChevronDown, ChevronUp, Info, Award, CheckCircle2, Fingerprint, KeyRound } from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface AttestationPolicy {
  enabled: boolean
  require_attestation: boolean
  allowed_formats: string[]
  allowed_aaguids: string[]
  allowed_transports: string[]
  require_mds_certification: boolean
  min_certification_level: string
  exclude_revoked_authenticators: boolean
}

// ── Constants ─────────────────────────────────────────────────────────────────

const FORMATS = [
  { value: 'packed',           label: 'Packed',            desc: 'Standard FIDO2 format (most common)' },
  { value: 'tpm',              label: 'TPM',               desc: 'Trusted Platform Module (Windows Hello, enterprise laptops)' },
  { value: 'android-key',      label: 'Android Key',       desc: 'Android hardware-backed keystore' },
  { value: 'android-safetynet',label: 'Android SafetyNet', desc: 'Android SafetyNet attestation' },
  { value: 'apple',            label: 'Apple',             desc: 'Apple Touch ID / Face ID / iCloud Keychain' },
  { value: 'fido-u2f',         label: 'FIDO U2F',          desc: 'Legacy FIDO U2F security keys' },
]

const TRANSPORTS = [
  { value: 'internal', label: 'Internal',   icon: Smartphone, desc: 'Platform authenticator (Touch ID, Face ID, Windows Hello)' },
  { value: 'hybrid',   label: 'Hybrid',     icon: Wifi,       desc: 'Cross-device (FIDO2 QR / caBLE)' },
  { value: 'usb',      label: 'USB',        icon: Wifi,       desc: 'USB security key' },
  { value: 'nfc',      label: 'NFC',        icon: Wifi,       desc: 'NFC security key' },
  { value: 'ble',      label: 'BLE',        icon: Wifi,       desc: 'Bluetooth security key' },
]

// Well-known AAGUIDs for quick pick
const KNOWN_AAGUIDS = [
  { aaguid: 'fbfc3007-154e-4ecc-8ade-601177b8b3f6', label: 'Apple Face ID',         icon: '🍎' },
  { aaguid: 'dd4ec289-e01d-41c9-bb89-70fa845d4bf2', label: 'Apple Touch ID / iCloud Keychain', icon: '🍎' },
  { aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', label: 'Google Password Manager', icon: '🔍' },
  { aaguid: 'adce0002-35bc-c60a-648b-0b25f1f05503', label: 'Chrome on Android',      icon: '🤖' },
  { aaguid: '9ddd1817-af5a-4672-a2b9-3e3dd95000a9', label: 'Windows Hello',           icon: '🪟' },
  { aaguid: '2fc0579f-8113-47ea-b116-bb5a8db9202a', label: 'YubiKey 5 FIDO2',        icon: '🔑' },
  { aaguid: 'b93fd961-f2e6-462f-b122-82002247de78', label: 'Android (Google cred.)', icon: '🤖' },
]

// ── Preview ───────────────────────────────────────────────────────────────────

interface PreviewDevice {
  aaguid: string
  description: string
  certification_level: string | null
  authenticator_type: string
}

interface PolicyPreview {
  min_cert_level: string
  exclude_revoked: boolean
  total: number
  devices: PreviewDevice[]
}

// ── Styles ────────────────────────────────────────────────────────────────────

const card: React.CSSProperties = { background: 'white', border: '0.5px solid var(--clavex-border)', borderRadius: 12, padding: '20px 24px' }
const inp: React.CSSProperties = { background: 'white', color: 'var(--clavex-ink)', border: '0.5px solid var(--clavex-border-subtle)', borderRadius: 8, padding: '7px 11px', fontSize: 13, outline: 'none' }
const lbl: React.CSSProperties = { display: 'block', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--clavex-ink-muted)', marginBottom: 6 }

// ── AAGUID Quick-pick dropdown ────────────────────────────────────────────────

function AAGUIDPicker({ onAdd }: { onAdd: (a: string) => void }) {
  const [open, setOpen] = useState(false)
  const [custom, setCustom] = useState('')

  return (
    <div className="relative">
      <button onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg"
        style={{ background: 'rgba(93,202,165,0.1)', color: 'var(--clavex-primary)' }}>
        <Plus size={12} /> Add device {open ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
      </button>
      {open && (
        <div className="absolute top-full mt-1 left-0 z-20 rounded-xl shadow-xl overflow-hidden"
          style={{ background: 'white', border: '0.5px solid var(--clavex-border)', width: 360 }}>
          <div className="p-3 space-y-1">
            <p className="text-[11px] font-semibold uppercase tracking-wide px-1 mb-2" style={{ color: 'var(--clavex-ink-muted)' }}>Known authenticators</p>
            {KNOWN_AAGUIDS.map((k) => (
              <button key={k.aaguid} onClick={() => { onAdd(k.aaguid); setOpen(false) }}
                className="w-full text-left flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-gray-50">
                <span className="text-base">{k.icon}</span>
                <div>
                  <p className="text-sm font-medium" style={{ color: 'var(--clavex-ink)' }}>{k.label}</p>
                  <p className="text-[10px] font-mono" style={{ color: 'var(--clavex-neutral)' }}>{k.aaguid}</p>
                </div>
              </button>
            ))}
          </div>
          <div className="border-t p-3" style={{ borderColor: 'var(--clavex-border)' }}>
            <p className="text-[11px] font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--clavex-ink-muted)' }}>Custom AAGUID</p>
            <div className="flex gap-2">
              <input style={{ ...inp, flex: 1, fontSize: 12 }} value={custom}
                onChange={(e) => setCustom(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
              <button onClick={() => { if (custom.trim()) { onAdd(custom.trim()); setCustom(''); setOpen(false) } }}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold"
                style={{ background: 'var(--clavex-primary)', color: 'white' }}>
                Add
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function PasskeyPolicyPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const [policy, setPolicy] = useState<AttestationPolicy>({
    enabled: false,
    require_attestation: false,
    allowed_formats: [],
    allowed_aaguids: [],
    allowed_transports: [],
    require_mds_certification: false,
    min_certification_level: '',
    exclude_revoked_authenticators: false,
  })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [preview, setPreview] = useState<PolicyPreview | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [showPreviewList, setShowPreviewList] = useState(false)

  const load = useCallback(async () => {
    if (!orgId) return
    setLoading(true)
    try {
      const res = await api.get(`/organizations/${orgId}/webauthn-policy`)
      setPolicy({
        enabled: res.data.enabled ?? false,
        require_attestation: res.data.require_attestation ?? false,
        allowed_formats: res.data.allowed_formats ?? [],
        allowed_aaguids: res.data.allowed_aaguids ?? [],
        allowed_transports: res.data.allowed_transports ?? [],
        require_mds_certification: res.data.require_mds_certification ?? false,
        min_certification_level: res.data.min_certification_level ?? '',
        exclude_revoked_authenticators: res.data.exclude_revoked_authenticators ?? false,
      })
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status
      if (status !== 404) toast.error('Failed to load passkey policy')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { load() }, [load])

  // Fetch preview whenever min_certification_level or exclude_revoked changes.
  useEffect(() => {
    if (!orgId || !policy.min_certification_level) {
      setPreview(null)
      return
    }
    let cancelled = false
    setPreviewLoading(true)
    const qs = new URLSearchParams({
      min_cert_level: policy.min_certification_level,
      exclude_revoked: policy.exclude_revoked_authenticators ? 'true' : 'false',
    })
    api.get(`/organizations/${orgId}/webauthn-policy/preview?${qs}`)
      .then((r) => { if (!cancelled) setPreview(r.data) })
      .catch(() => { /* silent — catalog may be empty */ })
      .finally(() => { if (!cancelled) setPreviewLoading(false) })
    return () => { cancelled = true }
  }, [orgId, policy.min_certification_level, policy.exclude_revoked_authenticators])

  const save = async () => {
    if (!orgId) return
    setSaving(true)
    try {
      await api.put(`/organizations/${orgId}/webauthn-policy`, policy)
      toast.success('Passkey policy saved')
    } catch {
      toast.error('Failed to save policy')
    } finally {
      setSaving(false)
    }
  }

  const removePolicy = async () => {
    if (!orgId) return
    try {
      await api.delete(`/organizations/${orgId}/webauthn-policy`)
      setPolicy({ enabled: false, require_attestation: false, allowed_formats: [], allowed_aaguids: [], allowed_transports: [], require_mds_certification: false, min_certification_level: '', exclude_revoked_authenticators: false })
      toast.success('Policy removed — all authenticators accepted')
    } catch {
      toast.error('Failed to remove policy')
    }
  }

  const toggleFormat = (f: string) => {
    setPolicy((p) => ({
      ...p,
      allowed_formats: p.allowed_formats.includes(f)
        ? p.allowed_formats.filter((x) => x !== f)
        : [...p.allowed_formats, f],
    }))
  }

  const toggleTransport = (t: string) => {
    setPolicy((p) => ({
      ...p,
      allowed_transports: p.allowed_transports.includes(t)
        ? p.allowed_transports.filter((x) => x !== t)
        : [...p.allowed_transports, t],
    }))
  }

  const addAAGUID = (a: string) => {
    if (!policy.allowed_aaguids.includes(a)) {
      setPolicy((p) => ({ ...p, allowed_aaguids: [...p.allowed_aaguids, a] }))
    }
  }

  const removeAAGUID = (a: string) => {
    setPolicy((p) => ({ ...p, allowed_aaguids: p.allowed_aaguids.filter((x) => x !== a) }))
  }

  if (loading) return (
    <div className="flex items-center justify-center py-24">
      <RefreshCw size={24} className="animate-spin" style={{ color: 'var(--clavex-primary)' }} />
    </div>
  )

  const isRestricted = policy.enabled && (
    policy.require_attestation ||
    policy.allowed_formats.length > 0 ||
    policy.allowed_aaguids.length > 0 ||
    policy.allowed_transports.length > 0 ||
    policy.require_mds_certification ||
    policy.min_certification_level !== '' ||
    policy.exclude_revoked_authenticators
  )

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>Clavex Keys</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
            Control which authenticators can be registered — BYOD enterprise zero-trust
          </p>
        </div>
        {isRestricted && (
          <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-semibold"
            style={{ background: 'rgba(93,202,165,0.15)', color: 'var(--clavex-primary)' }}>
            <Shield size={11} /> Policy active
          </span>
        )}
      </div>

      {/* Info */}
      <div className="rounded-xl px-4 py-3 flex items-start gap-3"
        style={{ background: 'rgba(93,202,165,0.08)', border: '0.5px solid rgba(93,202,165,0.25)' }}>
        <Info size={14} className="mt-0.5 flex-shrink-0" style={{ color: 'var(--clavex-primary)' }} />
        <p className="text-xs leading-relaxed" style={{ color: 'var(--clavex-ink-subtle)' }}>
          Attestation verification checks the hardware identity of the authenticator at enrollment time.
          This lets you enforce policies like <em>"only managed iPhones"</em> or <em>"only FIDO2-certified security keys"</em>.
          Credentials that fail the policy are rejected and never stored.
        </p>
      </div>

      {/* Master switch */}
      <div style={card}>
        <div className="flex items-center justify-between">
          <div>
            <p className="font-semibold" style={{ color: 'var(--clavex-ink)' }}>Enable attestation policy</p>
            <p className="text-sm mt-0.5" style={{ color: 'var(--clavex-ink-subtle)' }}>
              When off, all authenticators are accepted (no restrictions)
            </p>
          </div>
          <button
            onClick={() => setPolicy((p) => ({ ...p, enabled: !p.enabled }))}
            className="relative w-10 h-5 rounded-full transition-colors flex-shrink-0"
            style={{ background: policy.enabled ? 'var(--clavex-primary)' : 'var(--clavex-border)' }}>
            <span className="absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform"
              style={{ transform: policy.enabled ? 'translateX(20px)' : 'translateX(2px)' }} />
          </button>
        </div>
      </div>

      {policy.enabled && (
        <>
          {/* Require attestation */}
          <div style={card}>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-semibold" style={{ color: 'var(--clavex-ink)' }}>Require hardware attestation</p>
                <p className="text-sm mt-0.5" style={{ color: 'var(--clavex-ink-subtle)' }}>
                  Reject passkeys with no attestation statement (e.g. synced credentials without hardware proof)
                </p>
              </div>
              <button
                onClick={() => setPolicy((p) => ({ ...p, require_attestation: !p.require_attestation }))}
                className="relative w-10 h-5 rounded-full transition-colors flex-shrink-0"
                style={{ background: policy.require_attestation ? 'var(--clavex-primary)' : 'var(--clavex-border)' }}>
                <span className="absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform"
                  style={{ transform: policy.require_attestation ? 'translateX(20px)' : 'translateX(2px)' }} />
              </button>
            </div>
          </div>

          {/* Allowed transports */}
          <div style={card}>
            <label style={lbl}>
              <Wifi size={11} className="inline mr-1" style={{ color: 'var(--clavex-primary)' }} />
              Allowed transports
              <span className="ml-1 font-normal lowercase" style={{ letterSpacing: 0 }}>
                — empty = any transport accepted
              </span>
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mt-2">
              {TRANSPORTS.map((t) => {
                const checked = policy.allowed_transports.includes(t.value)
                return (
                  <button key={t.value} onClick={() => toggleTransport(t.value)}
                    className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-left"
                    style={{
                      background: checked ? 'rgba(93,202,165,0.12)' : 'rgba(0,0,0,0.02)',
                      border: `0.5px solid ${checked ? 'var(--clavex-primary)' : 'var(--clavex-border-subtle)'}`,
                    }}>
                    <span className="text-sm">{t.label === 'Internal' ? '📱' : t.label === 'Hybrid' ? '📷' : '🔑'}</span>
                    <div>
                      <p className="text-xs font-semibold" style={{ color: 'var(--clavex-ink)' }}>{t.label}</p>
                      <p className="text-[10px] leading-snug" style={{ color: 'var(--clavex-neutral)' }}>{t.desc}</p>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Allowed device models (AAGUIDs) */}
          <div style={card}>
            <div className="flex items-center justify-between mb-3">
              <label style={{ ...lbl, marginBottom: 0 }}>
                <Smartphone size={11} className="inline mr-1" style={{ color: 'var(--clavex-primary)' }} />
                Approved authenticator models
                <span className="ml-1 font-normal lowercase" style={{ letterSpacing: 0 }}>
                  — empty = any model
                </span>
              </label>
              <AAGUIDPicker onAdd={addAAGUID} />
            </div>
            {policy.allowed_aaguids.length === 0 ? (
              <p className="text-xs py-3 text-center" style={{ color: 'var(--clavex-neutral)' }}>
                No device model restrictions — click "Add device" to restrict by AAGUID
              </p>
            ) : (
              <div className="space-y-1.5">
                {policy.allowed_aaguids.map((a) => {
                  const known = KNOWN_AAGUIDS.find((k) => k.aaguid.toLowerCase() === a.toLowerCase())
                  return (
                    <div key={a} className="flex items-center gap-2 rounded-lg px-3 py-2"
                      style={{ background: 'rgba(93,202,165,0.07)', border: '0.5px solid rgba(93,202,165,0.2)' }}>
                      {known && <span className="text-sm">{known.icon}</span>}
                      <div className="flex-1 min-w-0">
                        {known && <p className="text-xs font-semibold" style={{ color: 'var(--clavex-ink)' }}>{known.label}</p>}
                        <p className="text-[11px] font-mono truncate" style={{ color: 'var(--clavex-neutral)' }}>{a}</p>
                      </div>
                      <button onClick={() => removeAAGUID(a)} className="p-1 rounded hover:bg-red-50" style={{ color: '#f87171' }}>
                        <X size={12} />
                      </button>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* FIDO MDS3 certification */}
          <div style={card}>
            <label style={lbl}>
              <Award size={11} className="inline mr-1" style={{ color: 'var(--clavex-primary)' }} />
              FIDO Alliance MDS3 certification
            </label>
            <p className="text-xs mb-3" style={{ color: 'var(--clavex-neutral)' }}>
              Enforce FIDO Alliance certification levels without maintaining a manual AAGUID list.
              Requires the MDS3 catalog to be synced — see <strong>TrustScore</strong> in the sidebar.
            </p>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>Require MDS3 certification</p>
                  <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>Reject authenticators not listed in the FIDO Alliance MDS3 catalog</p>
                </div>
                <button
                  onClick={() => setPolicy((p) => ({ ...p, require_mds_certification: !p.require_mds_certification }))}
                  className="relative w-10 h-5 rounded-full transition-colors flex-shrink-0"
                  style={{ background: policy.require_mds_certification ? 'var(--clavex-primary)' : 'var(--clavex-border)' }}>
                  <span className="absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform"
                    style={{ transform: policy.require_mds_certification ? 'translateX(20px)' : 'translateX(2px)' }} />
                </button>
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>Exclude revoked authenticators</p>
                  <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>Block authenticators flagged REVOKED, key compromised, or user verification bypass in MDS3</p>
                </div>
                <button
                  onClick={() => setPolicy((p) => ({ ...p, exclude_revoked_authenticators: !p.exclude_revoked_authenticators }))}
                  className="relative w-10 h-5 rounded-full transition-colors flex-shrink-0"
                  style={{ background: policy.exclude_revoked_authenticators ? 'var(--clavex-primary)' : 'var(--clavex-border)' }}>
                  <span className="absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform"
                    style={{ transform: policy.exclude_revoked_authenticators ? 'translateX(20px)' : 'translateX(2px)' }} />
                </button>
              </div>
              <div>
                <p className="text-sm font-semibold mb-1" style={{ color: 'var(--clavex-ink)' }}>Minimum certification level</p>
                <p className="text-xs mb-2" style={{ color: 'var(--clavex-ink-subtle)' }}>Only allow authenticators certified at or above this level (empty = no minimum)</p>
                <select
                  value={policy.min_certification_level}
                  onChange={(e) => setPolicy((p) => ({ ...p, min_certification_level: e.target.value }))}
                  style={{ ...inp, width: '100%' }}>
                  <option value="">No minimum (any level)</option>
                  <option value="L1">L1 — FIDO Functional Certification</option>
                  <option value="L1+">L1+ — FIDO Functional + Biometrics</option>
                  <option value="L2">L2 — Restricted Operating Environment</option>
                  <option value="L2+">L2+ — L2 + Biometrics</option>
                  <option value="L3">L3 — Hardware Security Module</option>
                  <option value="L3+">L3+ — L3 + Biometrics</option>
                </select>

                {/* MDS3 eligible device preview */}
                {policy.min_certification_level && (
                  <div style={{
                    marginTop: 12,
                    background: preview && preview.total > 0 ? 'rgba(93,202,165,0.06)' : 'rgba(0,0,0,0.02)',
                    border: `0.5px solid ${preview && preview.total > 0 ? 'rgba(93,202,165,0.3)' : 'var(--clavex-border-subtle)'}`,
                    borderRadius: 10, padding: '12px 14px',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {previewLoading
                          ? <RefreshCw size={13} className="animate-spin" style={{ color: 'var(--clavex-primary)' }} />
                          : <CheckCircle2 size={13} style={{ color: preview && preview.total > 0 ? 'var(--clavex-primary)' : 'var(--clavex-neutral)' }} />
                        }
                        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)' }}>
                          {previewLoading
                            ? 'Querying MDS3 catalog…'
                            : preview
                              ? `${preview.total} authenticator model${preview.total !== 1 ? 's' : ''} qualify at ${policy.min_certification_level}+`
                              : 'No matching devices in catalog'
                          }
                        </span>
                      </div>
                      {preview && preview.total > 0 && (
                        <button
                          onClick={() => setShowPreviewList((o) => !o)}
                          style={{ fontSize: 11, color: 'var(--clavex-700)', display: 'flex', alignItems: 'center', gap: 4 }}
                        >
                          {showPreviewList ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                          {showPreviewList ? 'Hide' : 'Show list'}
                        </button>
                      )}
                    </div>

                    {showPreviewList && preview && preview.devices.length > 0 && (
                      <div style={{ marginTop: 10, maxHeight: 200, overflowY: 'auto' }}>
                        {preview.devices.map((d) => (
                          <div key={d.aaguid} style={{
                            display: 'flex', alignItems: 'center', gap: 8,
                            padding: '5px 0', borderBottom: '0.5px solid var(--clavex-border)',
                          }}>
                            {d.authenticator_type === 'platform'
                              ? <Fingerprint size={12} style={{ color: 'var(--clavex-700)', flexShrink: 0 }} />
                              : <KeyRound size={12} style={{ color: 'var(--clavex-neutral)', flexShrink: 0 }} />}
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--clavex-ink)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {d.description}
                              </p>
                              <p style={{ fontSize: 10, color: 'var(--clavex-neutral)', fontFamily: 'monospace' }}>{d.aaguid}</p>
                            </div>
                            {d.certification_level && (
                              <span style={{
                                fontSize: 10, fontWeight: 700,
                                background: 'rgba(93,202,165,0.15)', color: 'var(--clavex-700)',
                                borderRadius: 4, padding: '1px 6px', flexShrink: 0,
                              }}>{d.certification_level}</span>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    {preview && preview.total === 0 && (
                      <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 6 }}>
                        The MDS3 catalog may not be synced yet — check <strong>TrustScore</strong> in the sidebar.
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Advanced: formats */}
          <div style={card}>
            <button onClick={() => setShowAdvanced((o) => !o)}
              className="flex items-center gap-2 w-full text-left"
              style={{ color: 'var(--clavex-ink)' }}>
              <Globe size={14} style={{ color: 'var(--clavex-primary)' }} />
              <span className="font-semibold text-sm">Advanced: attestation formats</span>
              {showAdvanced ? <ChevronUp size={14} className="ml-auto" /> : <ChevronDown size={14} className="ml-auto" />}
            </button>
            {showAdvanced && (
              <div className="mt-4">
                <p className="text-xs mb-3" style={{ color: 'var(--clavex-neutral)' }}>
                  Restrict to specific attestation statement formats. Empty = any format accepted.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {FORMATS.map((f) => {
                    const checked = policy.allowed_formats.includes(f.value)
                    return (
                      <label key={f.value} className="flex items-start gap-2.5 rounded-lg px-3 py-2.5 cursor-pointer"
                        style={{
                          background: checked ? 'rgba(93,202,165,0.1)' : 'rgba(0,0,0,0.02)',
                          border: `0.5px solid ${checked ? 'var(--clavex-primary)' : 'var(--clavex-border-subtle)'}`,
                        }}>
                        <input type="checkbox" checked={checked} onChange={() => toggleFormat(f.value)} className="mt-0.5 accent-green-400" />
                        <div>
                          <p className="text-xs font-semibold" style={{ color: 'var(--clavex-ink)' }}>{f.label}</p>
                          <p className="text-[10px]" style={{ color: 'var(--clavex-neutral)' }}>{f.desc}</p>
                        </div>
                      </label>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* Actions */}
      <div className="flex justify-between">
        <button onClick={removePolicy} className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm"
          style={{ color: '#f87171', background: 'rgba(239,68,68,0.06)' }}>
          <Trash2 size={13} /> Remove policy
        </button>
        <button onClick={save} disabled={saving}
          className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-semibold"
          style={{ background: 'var(--clavex-primary)', color: 'white' }}>
          {saving ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
          Save policy
        </button>
      </div>
    </div>
  )
}
