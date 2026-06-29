import { useState, useRef } from 'react'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Key, Download, Upload, Trash2, Lock, Unlock, Info, ArrowDownToLine,
  ArrowUpFromLine, CheckCircle2, AlertTriangle, Smartphone, Globe, Wifi,
  ShieldCheck, ShieldOff, RefreshCw, X,
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────

interface Passkey {
  id: string
  name: string
  credential_id: string
  aaguid: string
  transports: string[]
  sign_count: number
  is_imported: boolean
  created_at: string
  last_used_at: string | null
}

interface ImportResult {
  imported: number
  skipped: number
  errors: string[]
}

// ── AAGUID labels ─────────────────────────────────────────────────────

const AAGUID_LABELS: Record<string, { label: string; icon: string }> = {
  'fbfc3007-154e-4ecc-8ade-601177b8b3f6': { label: 'Apple Face ID',              icon: '🍎' },
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': { label: 'iCloud Keychain',            icon: '🍎' },
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': { label: 'Google Password Manager',    icon: '🔍' },
  'adce0002-35bc-c60a-648b-0b25f1f05503': { label: 'Chrome on Android',          icon: '🤖' },
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': { label: 'Windows Hello',              icon: '🪟' },
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': { label: 'YubiKey 5 FIDO2',            icon: '🔑' },
  '39a5647e-1853-446c-a1f6-a79bae9f5bc7': { label: '1Password',                  icon: '🔑' },
  'd821a7d4-e97c-4cb6-bd82-4237731fd4be': { label: 'Bitwarden',                  icon: '🔑' },
}

function aaguidLabel(aaguid: string) {
  return AAGUID_LABELS[aaguid]
    ?? { label: aaguid ? aaguid.slice(0, 8) + '…' : 'Unknown', icon: '🔐' }
}

function transportIcon(t: string) {
  switch (t) {
    case 'internal': return <Smartphone size={12} />
    case 'hybrid':   return <Wifi size={12} />
    default:         return <Globe size={12} />
  }
}

function relativeTime(iso: string | null) {
  if (!iso) return 'Never'
  const diff = Date.now() - new Date(iso).getTime()
  const days = Math.floor(diff / 86_400_000)
  if (days === 0) return 'Today'
  if (days === 1) return 'Yesterday'
  if (days < 30) return `${days}d ago`
  if (days < 365) return `${Math.floor(days / 30)}mo ago`
  return `${Math.floor(days / 365)}y ago`
}

// ── Styles ────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}

const inp: React.CSSProperties = {
  background: 'white',
  color: 'var(--clavex-ink)',
  border: '0.5px solid var(--clavex-border)',
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
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  color: 'var(--clavex-ink-muted)',
  marginBottom: 6,
}

const btn = (variant: 'primary' | 'ghost' | 'danger'): React.CSSProperties => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  padding: '7px 14px',
  borderRadius: 8,
  fontSize: 13,
  fontWeight: 500,
  cursor: 'pointer',
  border: variant === 'ghost' ? '0.5px solid var(--clavex-border)' : 'none',
  background: variant === 'primary' ? 'var(--clavex-accent)' : variant === 'danger' ? '#fee2e2' : 'white',
  color: variant === 'primary' ? 'white' : variant === 'danger' ? '#dc2626' : 'var(--clavex-ink)',
})

// ── PasskeyRow ────────────────────────────────────────────────────────

function PasskeyRow({ pk, onDelete }: { pk: Passkey; onDelete: (id: string) => void }) {
  const { label, icon } = aaguidLabel(pk.aaguid)
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '12px 16px',
        borderRadius: 10,
        border: '0.5px solid var(--clavex-border)',
        background: pk.is_imported ? 'rgba(251,191,36,0.04)' : 'white',
      }}
    >
      {/* Icon */}
      <span style={{ fontSize: 22, lineHeight: 1 }}>{icon}</span>

      {/* Info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
          <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--clavex-ink)' }}>{pk.name}</span>
          {pk.is_imported && (
            <span style={{
              fontSize: 10, fontWeight: 700, letterSpacing: '0.06em',
              background: '#fef3c7', color: '#92400e',
              borderRadius: 4, padding: '1px 6px',
            }}>IMPORTED</span>
          )}
        </div>
        <div style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>
          {label} &nbsp;·&nbsp; sign count {pk.sign_count}
          &nbsp;·&nbsp; last used {relativeTime(pk.last_used_at)}
        </div>
        {/* Transports */}
        {pk.transports?.length > 0 && (
          <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
            {pk.transports.map((t) => (
              <span key={t} style={{
                display: 'inline-flex', alignItems: 'center', gap: 3,
                fontSize: 11, background: '#f1f5f9', borderRadius: 4, padding: '1px 6px',
                color: 'var(--clavex-ink-muted)',
              }}>
                {transportIcon(t)} {t}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Created */}
      <div style={{ fontSize: 12, color: 'var(--clavex-ink-muted)', textAlign: 'right', whiteSpace: 'nowrap' }}>
        Added {relativeTime(pk.created_at)}
      </div>

      {/* Delete */}
      <button
        onClick={() => onDelete(pk.id)}
        style={{ ...btn('ghost'), padding: '5px 8px', color: '#dc2626', borderColor: 'transparent' }}
        title="Remove passkey"
      >
        <Trash2 size={15} />
      </button>
    </div>
  )
}

// ── Export panel ─────────────────────────────────────────────────────

function ExportPanel() {
  const [password, setPassword] = useState('')
  const [encrypted, setEncrypted] = useState(true)
  const [busy, setBusy] = useState(false)

  async function handleExport() {
    setBusy(true)
    try {
      const res = await api.post('/me/passkeys/export', {
        password: encrypted ? password : '',
        title: 'My Clavex passkeys',
      }, { responseType: 'json' })

      const json = JSON.stringify(res.data, null, 2)
      const blob = new Blob([json], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'clavex-passkeys.cxf.json'
      a.click()
      URL.revokeObjectURL(url)
      toast.success('Passkeys exported')
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message ?? 'Export failed'
      toast.error(msg)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={card}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <ArrowDownToLine size={18} color="var(--clavex-accent)" />
        <span style={{ fontWeight: 700, fontSize: 15 }}>Export passkeys</span>
      </div>

      <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', marginBottom: 16, lineHeight: 1.6 }}>
        Downloads your passkey registrations in the&nbsp;
        <strong>FIDO Alliance Credential Exchange Format (CXF)</strong>.
        Compatible with 1Password, Bitwarden, and iCloud Keychain when they support CXF import.
      </p>

      {/* Encryption toggle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <button
          onClick={() => setEncrypted(!encrypted)}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '5px 10px', borderRadius: 8, fontSize: 13,
            border: '0.5px solid var(--clavex-border)', background: encrypted ? '#f0fdf4' : 'white',
            cursor: 'pointer',
          }}
        >
          {encrypted ? <Lock size={14} color="#16a34a" /> : <Unlock size={14} />}
          {encrypted ? 'Encrypted (AES-256-GCM)' : 'Plain JSON'}
        </button>
        <span style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>
          {encrypted ? 'PBKDF2-SHA256, 600 000 iterations' : 'Not recommended for sensitive environments'}
        </span>
      </div>

      {encrypted && (
        <div style={{ marginBottom: 16 }}>
          <label style={lbl}>Export password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter a strong password…"
            style={inp}
            autoComplete="new-password"
          />
          <p style={{ fontSize: 11, color: 'var(--clavex-ink-muted)', marginTop: 4 }}>
            You will need this password to import the file. Store it securely.
          </p>
        </div>
      )}

      <button
        onClick={handleExport}
        disabled={busy || (encrypted && !password)}
        style={{ ...btn('primary'), opacity: busy || (encrypted && !password) ? 0.5 : 1 }}
      >
        {busy ? <RefreshCw size={14} className="animate-spin" /> : <Download size={14} />}
        {busy ? 'Exporting…' : 'Download .cxf.json'}
      </button>

      {/* Security note */}
      <div style={{
        marginTop: 16, padding: '10px 14px', borderRadius: 8,
        background: '#f0f9ff', border: '0.5px solid #bae6fd',
        display: 'flex', alignItems: 'flex-start', gap: 8,
      }}>
        <Info size={14} color="#0369a1" style={{ marginTop: 1, flexShrink: 0 }} />
        <p style={{ fontSize: 12, color: '#0369a1', lineHeight: 1.5, margin: 0 }}>
          <strong>Privacy note:</strong> this export contains your passkey public keys and metadata.
          Private keys never leave your authenticator hardware and are <em>not</em> included.
        </p>
      </div>
    </div>
  )
}

// ── Import panel ─────────────────────────────────────────────────────

function ImportPanel({ onSuccess }: { onSuccess: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [password, setPassword] = useState('')
  const [fileName, setFileName] = useState('')
  const [bundleContent, setBundleContent] = useState<object | null>(null)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<ImportResult | null>(null)

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = () => {
      try {
        const parsed = JSON.parse(reader.result as string)
        setBundleContent(parsed)
      } catch {
        toast.error('Invalid JSON file')
      }
    }
    reader.readAsText(file)
  }

  async function handleImport() {
    if (!bundleContent) return
    setBusy(true)
    setResult(null)
    try {
      const res = await api.post<ImportResult>('/me/passkeys/import', {
        password,
        bundle: bundleContent,
      })
      setResult(res.data)
      if (res.data.imported > 0) {
        toast.success(`Imported ${res.data.imported} passkey${res.data.imported > 1 ? 's' : ''}`)
        onSuccess()
      } else if (res.data.skipped > 0) {
        toast(`${res.data.skipped} passkey${res.data.skipped > 1 ? 's' : ''} already registered`, { icon: 'ℹ️' })
      }
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message ?? 'Import failed'
      toast.error(msg)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={card}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <ArrowUpFromLine size={18} color="var(--clavex-accent)" />
        <span style={{ fontWeight: 700, fontSize: 15 }}>Import passkeys</span>
      </div>

      <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', marginBottom: 16, lineHeight: 1.6 }}>
        Import a <strong>.cxf.json</strong> bundle exported from Clavex, 1Password, Bitwarden,
        or any FIDO Alliance CXF-compatible source.
      </p>

      {/* File picker */}
      <div style={{ marginBottom: 14 }}>
        <label style={lbl}>CXF bundle file</label>
        <div
          onClick={() => fileRef.current?.click()}
          style={{
            border: '1.5px dashed var(--clavex-border)',
            borderRadius: 10,
            padding: '20px',
            textAlign: 'center',
            cursor: 'pointer',
            background: bundleContent ? '#f0fdf4' : '#fafafa',
            transition: 'background 0.2s',
          }}
        >
          {bundleContent ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
              <CheckCircle2 size={18} color="#16a34a" />
              <span style={{ fontSize: 13, color: '#16a34a', fontWeight: 600 }}>{fileName}</span>
            </div>
          ) : (
            <div>
              <Upload size={24} color="var(--clavex-ink-muted)" style={{ margin: '0 auto 8px' }} />
              <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', margin: 0 }}>
                Click to select a .cxf.json file
              </p>
            </div>
          )}
        </div>
        <input ref={fileRef} type="file" accept=".json" style={{ display: 'none' }} onChange={handleFileChange} />
      </div>

      {/* Password (for encrypted bundles) */}
      <div style={{ marginBottom: 16 }}>
        <label style={lbl}>Password (if encrypted)</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Leave empty for plain CXF files"
          style={inp}
          autoComplete="current-password"
        />
      </div>

      <button
        onClick={handleImport}
        disabled={busy || !bundleContent}
        style={{ ...btn('primary'), opacity: busy || !bundleContent ? 0.5 : 1 }}
      >
        {busy ? <RefreshCw size={14} className="animate-spin" /> : <Upload size={14} />}
        {busy ? 'Importing…' : 'Import passkeys'}
      </button>

      {/* Result summary */}
      {result && (
        <div style={{ marginTop: 16 }}>
          <div style={{
            padding: '10px 14px', borderRadius: 8,
            background: result.imported > 0 ? '#f0fdf4' : '#fff7ed',
            border: `0.5px solid ${result.imported > 0 ? '#86efac' : '#fed7aa'}`,
          }}>
            <div style={{ display: 'flex', gap: 16, fontSize: 13 }}>
              <span><strong>{result.imported}</strong> imported</span>
              <span><strong>{result.skipped}</strong> skipped</span>
            </div>
          </div>
          {result.errors?.length > 0 && (
            <div style={{ marginTop: 8 }}>
              {result.errors.map((e, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'flex-start', gap: 6,
                  fontSize: 12, color: '#dc2626', marginBottom: 4,
                }}>
                  <AlertTriangle size={13} style={{ marginTop: 1, flexShrink: 0 }} />
                  {e}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Compatibility note */}
      <div style={{
        marginTop: 16, padding: '10px 14px', borderRadius: 8,
        background: '#fafafa', border: '0.5px solid var(--clavex-border)',
        display: 'flex', alignItems: 'flex-start', gap: 8,
      }}>
        <Info size={14} color="var(--clavex-ink-muted)" style={{ marginTop: 1, flexShrink: 0 }} />
        <div style={{ fontSize: 12, color: 'var(--clavex-ink-muted)', lineHeight: 1.5 }}>
          <strong>Compatibility:</strong> CXF import validates that credentials were registered
          for this relying party. Cross-origin imports will be rejected. Duplicate credentials
          are silently skipped.
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────

export default function PasskeyExchangePage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'list' | 'export' | 'import'>('list')

  const { data: passkeys = [], isLoading } = useQuery<Passkey[]>({
    queryKey: ['my-passkeys'],
    queryFn: () => api.get('/me/passkeys').then((r) => r.data),
  })

  const deleteMutation = useMutation({
    mutationFn: (credId: string) => api.delete(`/me/passkeys/${credId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['my-passkeys'] })
      toast.success('Passkey removed')
    },
    onError: () => toast.error('Failed to remove passkey'),
  })

  const tabs: { id: typeof tab; icon: React.ReactNode; label: string }[] = [
    { id: 'list',   icon: <Key size={14} />,              label: 'My passkeys' },
    { id: 'export', icon: <ArrowDownToLine size={14} />,  label: 'Export' },
    { id: 'import', icon: <ArrowUpFromLine size={14} />,  label: 'Import' },
  ]

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
          <ShieldCheck size={24} color="var(--clavex-accent)" />
          <h1 style={{ fontSize: 22, fontWeight: 800, color: 'var(--clavex-ink)', margin: 0 }}>
            Clavex Keys — Passkey Portability
          </h1>
        </div>
        <p style={{ fontSize: 14, color: 'var(--clavex-ink-muted)', margin: 0 }}>
          Manage, export and import passkeys using the&nbsp;
          <strong>FIDO Alliance Credential Exchange Format (CXF)</strong>.
          Move passkeys between 1Password, Bitwarden, and iCloud Keychain.
        </p>
      </div>

      {/* Stats bar */}
      {!isLoading && (
        <div style={{
          display: 'flex', gap: 12, marginBottom: 24,
          padding: '14px 18px',
          background: 'white',
          border: '0.5px solid var(--clavex-border)',
          borderRadius: 12,
        }}>
          <StatPill icon={<Key size={14} />} value={passkeys.length} label="total" />
          <StatPill
            icon={<ShieldCheck size={14} color="#16a34a" />}
            value={passkeys.filter((p) => !p.is_imported).length}
            label="ceremony-registered"
          />
          <StatPill
            icon={<ShieldOff size={14} color="#f59e0b" />}
            value={passkeys.filter((p) => p.is_imported).length}
            label="imported"
          />
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20 }}>
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '7px 14px', borderRadius: 8, fontSize: 13, fontWeight: 500,
              border: 'none', cursor: 'pointer',
              background: tab === t.id ? 'var(--clavex-accent)' : '#f1f5f9',
              color: tab === t.id ? 'white' : 'var(--clavex-ink)',
              transition: 'all 0.15s',
            }}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'list' && (
        <div style={card}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <span style={{ fontWeight: 700, fontSize: 15 }}>Registered passkeys</span>
            <span style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>
              {passkeys.length} passkey{passkeys.length !== 1 ? 's' : ''}
            </span>
          </div>

          {isLoading && (
            <div style={{ textAlign: 'center', padding: '32px', color: 'var(--clavex-ink-muted)' }}>
              <RefreshCw size={20} className="animate-spin" style={{ margin: '0 auto 8px' }} />
              Loading…
            </div>
          )}

          {!isLoading && passkeys.length === 0 && (
            <div style={{
              textAlign: 'center', padding: '40px 20px',
              border: '1.5px dashed var(--clavex-border)', borderRadius: 10,
            }}>
              <Key size={32} color="var(--clavex-ink-muted)" style={{ margin: '0 auto 12px' }} />
              <p style={{ fontSize: 14, color: 'var(--clavex-ink-muted)', margin: 0 }}>
                No passkeys registered yet.
              </p>
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {passkeys.map((pk) => (
              <PasskeyRow
                key={pk.id}
                pk={pk}
                onDelete={(id) => {
                  if (confirm('Remove this passkey? You will need to re-register it to use it again.')) {
                    deleteMutation.mutate(id)
                  }
                }}
              />
            ))}
          </div>

          {passkeys.length > 0 && (
            <div style={{
              marginTop: 20, padding: '10px 14px', borderRadius: 8,
              background: '#fffbeb', border: '0.5px solid #fde68a',
              display: 'flex', gap: 8, alignItems: 'flex-start',
            }}>
              <AlertTriangle size={14} color="#d97706" style={{ marginTop: 1, flexShrink: 0 }} />
              <p style={{ fontSize: 12, color: '#92400e', margin: 0, lineHeight: 1.5 }}>
                Removing a passkey from Clavex does <strong>not</strong> delete it from your password manager.
                You should also delete it there to prevent authentication attempts.
              </p>
            </div>
          )}
        </div>
      )}

      {tab === 'export' && <ExportPanel />}

      {tab === 'import' && (
        <ImportPanel onSuccess={() => qc.invalidateQueries({ queryKey: ['my-passkeys'] })} />
      )}

      {/* CXF spec reference */}
      <div style={{ marginTop: 24, display: 'flex', alignItems: 'center', gap: 8 }}>
        <X size={0} />
        <p style={{ fontSize: 11, color: 'var(--clavex-ink-muted)', margin: 0 }}>
          Implements draft-hodges-credential-exchange-format (FIDO Alliance, 2024) &mdash;
          AES-256-GCM encryption · PBKDF2-SHA256 · 600 000 iterations
        </p>
      </div>
    </div>
  )
}

// ── StatPill ──────────────────────────────────────────────────────────

function StatPill({ icon, value, label }: { icon: React.ReactNode; value: number; label: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      {icon}
      <span style={{ fontSize: 18, fontWeight: 800, color: 'var(--clavex-ink)' }}>{value}</span>
      <span style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>{label}</span>
    </div>
  )
}
