import { useEffect, useState, useCallback, useRef } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { RefreshCw, Search, ShieldCheck, AlertTriangle, CheckCircle, Clock, Database } from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface MDSEntry {
  aaguid: string
  description: string
  certification_level: string | null
  certificate_number: string | null
  certified_at: string | null
  status_reports: string[]
  authenticator_type: string
  refreshed_at: string
}

interface SyncStatus {
  last_synced_at: string | null
  entry_count: number
  last_no: number
  last_error: string | null
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const CERT_LEVEL_COLORS: Record<string, { bg: string; color: string }> = {
  'L3+': { bg: 'rgba(6,214,160,0.18)',   color: '#047857' },
  'L3':  { bg: 'rgba(6,214,160,0.13)',   color: '#059669' },
  'L2+': { bg: 'rgba(59,130,246,0.15)',  color: '#1d4ed8' },
  'L2':  { bg: 'rgba(59,130,246,0.10)',  color: '#2563eb' },
  'L1+': { bg: 'rgba(168,85,247,0.12)',  color: '#7c3aed' },
  'L1':  { bg: 'rgba(168,85,247,0.08)',  color: '#8b5cf6' },
}

function certBadge(level: string | null) {
  if (!level) return null
  const style = CERT_LEVEL_COLORS[level] ?? { bg: 'rgba(100,116,139,0.1)', color: '#475569' }
  return (
    <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full"
      style={{ background: style.bg, color: style.color }}>
      <ShieldCheck size={10} /> {level}
    </span>
  )
}

function statusChip(s: string) {
  const isOk = ['FIDO_CERTIFIED', 'FIDO_CERTIFIED_L1', 'FIDO_CERTIFIED_L2', 'FIDO_CERTIFIED_L3'].some(x => s.startsWith(x))
  const isWarn = ['USER_VERIFICATION_BYPASS', 'ATTESTATION_KEY_COMPROMISE',
                  'USER_KEY_REMOTE_COMPROMISE', 'USER_KEY_PHYSICAL_COMPROMISE'].includes(s)
  const isRev = s === 'REVOKED'
  const bg = isRev ? 'rgba(239,68,68,0.12)' : isWarn ? 'rgba(245,158,11,0.12)' : 'rgba(6,214,160,0.1)'
  const color = isRev ? '#dc2626' : isWarn ? '#b45309' : '#047857'
  return (
    <span key={s} className="inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-md"
      style={{ background: bg, color }}>
      {isOk ? <CheckCircle size={8} /> : <AlertTriangle size={8} />}
      {s.replace(/_/g, ' ')}
    </span>
  )
}

function fmtDate(iso: string | null) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

// ── Constants ─────────────────────────────────────────────────────────────────

const CERT_LEVELS = ['', 'L1', 'L1+', 'L2', 'L2+', 'L3', 'L3+']

const card: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '16px 20px',
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function MDSCatalogPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const [entries, setEntries] = useState<MDSEntry[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const limit = 50
  const [search, setSearch] = useState('')
  const [certLevel, setCertLevel] = useState('')
  const [excludeRevoked, setExcludeRevoked] = useState(false)
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [syncStatus, setSyncStatus] = useState<SyncStatus | null>(null)
  const searchRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const loadSyncStatus = useCallback(async () => {
    if (!orgId) return
    try {
      const res = await api.get(`/organizations/${orgId}/mds/sync`)
      setSyncStatus(res.data)
    } catch { /* ignore */ }
  }, [orgId])

  const loadEntries = useCallback(async (q: string, cl: string, excl: boolean, off: number) => {
    if (!orgId) return
    setLoading(true)
    try {
      const params: Record<string, string> = {
        limit: String(limit),
        offset: String(off),
      }
      if (q) params.q = q
      if (cl) params.cert_level = cl
      if (excl) params.exclude_revoked = 'true'
      const res = await api.get(`/organizations/${orgId}/mds/entries`, { params })
      setEntries(res.data.entries ?? [])
      setTotal(res.data.total ?? 0)
    } catch {
      toast.error('Failed to load MDS catalog')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => {
    loadSyncStatus()
  }, [loadSyncStatus])

  useEffect(() => {
    if (searchRef.current) clearTimeout(searchRef.current)
    searchRef.current = setTimeout(() => {
      setOffset(0)
      loadEntries(search, certLevel, excludeRevoked, 0)
    }, 300)
    return () => { if (searchRef.current) clearTimeout(searchRef.current) }
  }, [search, certLevel, excludeRevoked, loadEntries])

  const triggerSync = async () => {
    if (!orgId || syncing) return
    setSyncing(true)
    try {
      await api.post(`/organizations/${orgId}/mds/sync`)
      toast.success('MDS3 refresh triggered — catalog will update shortly')
      setTimeout(() => { loadSyncStatus(); loadEntries(search, certLevel, excludeRevoked, offset) }, 3000)
    } catch {
      toast.error('Failed to trigger MDS3 refresh')
    } finally {
      setSyncing(false)
    }
  }

  const changePage = (newOffset: number) => {
    setOffset(newOffset)
    loadEntries(search, certLevel, excludeRevoked, newOffset)
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>Clavex TrustScore</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
            Certified authenticators from the FIDO Alliance Metadata Service (MDS3) — refreshed daily
          </p>
        </div>
        <button onClick={triggerSync} disabled={syncing}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold"
          style={{ background: 'var(--clavex-primary)', color: 'white', opacity: syncing ? 0.7 : 1 }}>
          <RefreshCw size={13} className={syncing ? 'animate-spin' : ''} />
          {syncing ? 'Syncing…' : 'Refresh now'}
        </button>
      </div>

      {/* Sync status bar */}
      {syncStatus && (
        <div style={{ ...card, padding: '12px 16px' }} className="flex flex-wrap items-center gap-4 text-xs">
          <span className="flex items-center gap-1.5" style={{ color: 'var(--clavex-ink-subtle)' }}>
            <Database size={12} style={{ color: 'var(--clavex-primary)' }} />
            <strong>{syncStatus.entry_count.toLocaleString()}</strong> FIDO2 entries
          </span>
          <span className="flex items-center gap-1.5" style={{ color: 'var(--clavex-ink-subtle)' }}>
            <Clock size={12} style={{ color: 'var(--clavex-primary)' }} />
            Last synced: <strong>{fmtDate(syncStatus.last_synced_at)}</strong>
          </span>
          {syncStatus.last_error && (
            <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-md"
              style={{ background: 'rgba(239,68,68,0.08)', color: '#dc2626' }}>
              <AlertTriangle size={10} />
              Last sync error: {syncStatus.last_error.slice(0, 80)}
            </span>
          )}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-52">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--clavex-neutral)' }} />
          <input
            type="text"
            placeholder="Search by name or AAGUID…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-2 text-sm rounded-lg outline-none"
            style={{ background: 'white', border: '0.5px solid var(--clavex-border)', color: 'var(--clavex-ink)' }}
          />
        </div>
        <select value={certLevel} onChange={(e) => setCertLevel(e.target.value)}
          className="text-sm px-3 py-2 rounded-lg outline-none"
          style={{ background: 'white', border: '0.5px solid var(--clavex-border)', color: 'var(--clavex-ink)' }}>
          {CERT_LEVELS.map((l) => (
            <option key={l} value={l}>{l ? `≥ ${l}` : 'All levels'}</option>
          ))}
        </select>
        <label className="flex items-center gap-2 text-sm cursor-pointer px-3 py-2 rounded-lg"
          style={{ background: 'white', border: '0.5px solid var(--clavex-border)', color: 'var(--clavex-ink)' }}>
          <input type="checkbox" checked={excludeRevoked} onChange={(e) => setExcludeRevoked(e.target.checked)}
            className="accent-green-400" />
          Exclude revoked
        </label>
      </div>

      {/* Table */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <RefreshCw size={24} className="animate-spin" style={{ color: 'var(--clavex-primary)' }} />
        </div>
      ) : entries.length === 0 ? (
        <div className="text-center py-16" style={{ color: 'var(--clavex-neutral)' }}>
          <ShieldCheck size={40} className="mx-auto mb-3 opacity-30" />
          <p className="text-sm font-medium">No entries found</p>
          <p className="text-xs mt-1">Try adjusting filters or trigger a catalog refresh</p>
        </div>
      ) : (
        <div style={{ background: 'white', border: '0.5px solid var(--clavex-border)', borderRadius: 12, overflow: 'hidden' }}>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '0.5px solid var(--clavex-border)', background: 'rgba(0,0,0,0.015)' }}>
                <th className="text-left px-4 py-3 text-xs font-semibold" style={{ color: 'var(--clavex-neutral)' }}>Authenticator</th>
                <th className="text-left px-4 py-3 text-xs font-semibold" style={{ color: 'var(--clavex-neutral)' }}>AAGUID</th>
                <th className="text-left px-4 py-3 text-xs font-semibold" style={{ color: 'var(--clavex-neutral)' }}>Level</th>
                <th className="text-left px-4 py-3 text-xs font-semibold" style={{ color: 'var(--clavex-neutral)' }}>Type</th>
                <th className="text-left px-4 py-3 text-xs font-semibold" style={{ color: 'var(--clavex-neutral)' }}>Status</th>
                <th className="text-left px-4 py-3 text-xs font-semibold" style={{ color: 'var(--clavex-neutral)' }}>Refreshed</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={e.aaguid}
                  style={{ borderBottom: i < entries.length - 1 ? '0.5px solid var(--clavex-border-subtle)' : undefined }}>
                  <td className="px-4 py-3">
                    <p className="font-medium text-xs" style={{ color: 'var(--clavex-ink)' }}>{e.description || '—'}</p>
                    {e.certificate_number && (
                      <p className="text-[10px] mt-0.5" style={{ color: 'var(--clavex-neutral)' }}>{e.certificate_number}</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-[11px]" style={{ color: 'var(--clavex-neutral)' }}>{e.aaguid}</span>
                  </td>
                  <td className="px-4 py-3">
                    {certBadge(e.certification_level)}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-[11px]" style={{ color: 'var(--clavex-ink-subtle)', textTransform: 'capitalize' }}>
                      {e.authenticator_type}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(e.status_reports ?? []).map((s) => statusChip(s))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-[11px]" style={{ color: 'var(--clavex-neutral)' }}>{fmtDate(e.refreshed_at)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {total > limit && (
        <div className="flex items-center justify-between text-xs" style={{ color: 'var(--clavex-neutral)' }}>
          <span>{offset + 1}–{Math.min(offset + limit, total)} of {total.toLocaleString()}</span>
          <div className="flex gap-2">
            <button disabled={offset === 0} onClick={() => changePage(Math.max(0, offset - limit))}
              className="px-3 py-1.5 rounded-lg disabled:opacity-40"
              style={{ background: 'white', border: '0.5px solid var(--clavex-border)' }}>
              ← Prev
            </button>
            <button disabled={offset + limit >= total} onClick={() => changePage(offset + limit)}
              className="px-3 py-1.5 rounded-lg disabled:opacity-40"
              style={{ background: 'white', border: '0.5px solid var(--clavex-border)' }}>
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
