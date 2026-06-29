import { useEffect, useState, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import { ShieldOff, ShieldCheck, RotateCcw, Clock, Hash, Eye, AlertTriangle } from 'lucide-react'

interface IssuedCredential {
  id: string
  user_id?: string
  vct: string
  sd_jwt_hash: string
  issued_at: string
  expires_at?: string
  is_revoked: boolean
  revoked_at?: string
  revocation_reason?: string
  status_list_id?: string
  status_index?: number
}

interface PresentationSession {
  id: string
  request_id: string
  status: string
  created_at: string
  vp_claims?: Record<string, unknown>
}

function StatusBadge({ revoked }: { revoked: boolean }) {
  return revoked ? (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
      style={{ background: '#FCEBEB', color: '#A32D2D' }}>
      <ShieldOff size={10} /> Revoked
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
      style={{ background: 'var(--clavex-50)', color: 'var(--clavex-700)' }}>
      <ShieldCheck size={10} /> Valid
    </span>
  )
}

function RevokeModal({
  cred,
  onClose,
  onRevoked,
}: {
  cred: IssuedCredential
  onClose: () => void
  onRevoked: () => void
}) {
  const orgId = useAuthStore((s) => s.orgId)
  const [reason, setReason] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    setLoading(true)
    try {
      await api.post(`/organizations/${orgId}/oid4vci/issued/${cred.id}/revoke`, { reason })
      toast.success('Credential revoked')
      onRevoked()
    } catch {
      toast.error('Revocation failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.6)' }}>
      <div className="rounded-xl p-6 w-full max-w-md" style={{ background: 'white', border: '0.5px solid var(--clavex-border)' }}>
        <h3 className="text-lg font-semibold mb-1" style={{ color: 'var(--clavex-ink)' }}>Revoke Credential</h3>
        <p className="text-sm mb-4" style={{ color: 'var(--clavex-ink-subtle)' }}>
          Credential type: <span className="font-mono text-xs" style={{ color: 'var(--clavex-primary)' }}>{cred.vct}</span>
        </p>
        <div className="mb-4">
          <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--clavex-ink-muted)' }}>
            Revocation reason <span style={{ color: 'var(--clavex-neutral)' }}>(optional)</span>
          </label>
          <select
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="w-full rounded-lg px-3 py-2 text-sm"
            style={{ background: 'white', color: 'var(--clavex-ink)', border: '0.5px solid var(--clavex-border)' }}
          >
            <option value="">— select reason —</option>
            <option value="keyCompromise">Key Compromise</option>
            <option value="caCompromise">CA Compromise</option>
            <option value="affiliationChanged">Affiliation Changed</option>
            <option value="superseded">Superseded</option>
            <option value="cessationOfOperation">Cessation of Operation</option>
            <option value="privilegeWithdrawn">Privilege Withdrawn</option>
          </select>
        </div>
        <div className="flex gap-3 justify-end">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--clavex-ink-subtle)' }}>
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={loading}
            className="px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2"
            style={{ background: 'rgba(239,68,68,0.8)', color: '#fff' }}
          >
            {loading ? <RotateCcw size={14} className="animate-spin" /> : <ShieldOff size={14} />}
            Revoke
          </button>
        </div>
      </div>
    </div>
  )
}

export default function CredentialStatusPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const [creds, setCreds] = useState<IssuedCredential[]>([])
  const [sessions, setSessions] = useState<PresentationSession[]>([])
  const [loading, setLoading] = useState(true)
  const [revokeTarget, setRevokeTarget] = useState<IssuedCredential | null>(null)
  const [selected, setSelected] = useState<IssuedCredential | null>(null)

  const load = useCallback(async () => {
    if (!orgId) return
    setLoading(true)
    try {
      const [cResult, sResult] = await Promise.allSettled([
        api.get(`/organizations/${orgId}/oid4vci/issued`),
        api.get(`/organizations/${orgId}/oid4vp/sessions`),
      ])
      if (cResult.status === 'fulfilled') {
        setCreds(toArr<IssuedCredential>(cResult.value.data))
      } else {
        toast.error('Failed to load credentials')
      }
      if (sResult.status === 'fulfilled') {
        setSessions(toArr<PresentationSession>(sResult.value.data))
      }
    } catch {
      toast.error('Failed to load credentials')
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => { load() }, [load])

  const handleRestore = async (cred: IssuedCredential) => {
    try {
      await api.post(`/organizations/${orgId}/oid4vci/issued/${cred.id}/restore`)
      toast.success('Credential restored')
      load()
    } catch {
      toast.error('Restore failed')
    }
  }

  const validCount = creds.filter((c) => !c.is_revoked).length
  const revokedCount = creds.filter((c) => c.is_revoked).length
  const presentedCount = sessions.filter((s) => s.status === 'verified').length

  const cardStyle = {
    background: 'white',
    border: '0.5px solid var(--clavex-border)',
    borderRadius: 12,
    padding: '20px 24px',
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--clavex-ink)' }}>Credential Status</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
          W3C StatusList2021 — manage issued VCs, revoke with reason, track OID4VP presentations
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Valid', value: validCount, color: 'var(--clavex-primary)', icon: ShieldCheck },
          { label: 'Revoked', value: revokedCount, color: '#f87171', icon: ShieldOff },
          { label: 'Presented (VP)', value: presentedCount, color: '#a78bfa', icon: Eye },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} style={cardStyle}>
            <div className="flex items-center gap-3">
              <Icon size={20} style={{ color }} />
              <div>
                <p className="text-2xl font-bold" style={{ color }}>{value}</p>
                <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>{label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Two-panel layout */}
      <div className="grid grid-cols-5 gap-4">
        {/* Issued credentials list */}
        <div className="col-span-3" style={cardStyle}>
          <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--clavex-ink)' }}>Issued Credentials</h2>
          {loading ? (
            <p className="text-xs py-4 text-center" style={{ color: 'var(--clavex-neutral)' }}>Loading…</p>
          ) : creds.length === 0 ? (
            <p className="text-xs py-4 text-center" style={{ color: 'var(--clavex-neutral)' }}>No credentials issued yet</p>
          ) : (
            <div className="space-y-2 max-h-[480px] overflow-y-auto pr-1">
              {creds.map((c) => (
                <div
                  key={c.id}
                  onClick={() => setSelected(c)}
                  className="flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors"
                  style={{
                    background: selected?.id === c.id ? 'rgba(93,202,165,0.08)' : 'rgba(93,202,165,0.03)',
                    border: `1px solid ${selected?.id === c.id ? 'rgba(93,202,165,0.25)' : 'rgba(93,202,165,0.07)'}`,
                  }}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-xs font-mono font-medium truncate" style={{ color: 'var(--clavex-ink)' }}>{c.vct}</span>
                      <StatusBadge revoked={c.is_revoked} />
                    </div>
                    <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--clavex-neutral)' }}>
                      <span className="flex items-center gap-1">
                        <Clock size={9} /> {new Date(c.issued_at).toLocaleDateString()}
                      </span>
                      {c.user_id && (
                        <span className="flex items-center gap-1">
                          <Hash size={9} /> {c.user_id.slice(0, 8)}…
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex gap-1.5 flex-shrink-0">
                    {c.is_revoked ? (
                      <button
                        onClick={(e) => { e.stopPropagation(); handleRestore(c) }}
                        className="px-2.5 py-1 rounded text-xs font-medium"
                        style={{ background: 'rgba(93,202,165,0.12)', color: 'var(--clavex-primary)' }}
                        title="Restore credential"
                      >
                        Restore
                      </button>
                    ) : (
                      <button
                        onClick={(e) => { e.stopPropagation(); setRevokeTarget(c) }}
                        className="px-2.5 py-1 rounded text-xs font-medium"
                        style={{ background: 'rgba(239,68,68,0.12)', color: '#f87171' }}
                        title="Revoke credential"
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right panel: detail + VP sessions */}
        <div className="col-span-2 flex flex-col gap-4">
          {/* Credential detail */}
          <div style={{ ...cardStyle, flex: '0 0 auto' }}>
            <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--clavex-ink)' }}>
              {selected ? 'Credential Detail' : 'Select a credential'}
            </h2>
            {selected ? (
              <div className="space-y-2 text-xs" style={{ color: 'var(--clavex-ink-muted)' }}>
                <div><span style={{ color: 'var(--clavex-neutral)' }}>ID:</span>
                  <span className="ml-2 font-mono text-[10px]">{selected.id}</span></div>
                <div><span style={{ color: 'var(--clavex-neutral)' }}>VCT:</span>
                  <span className="ml-2 font-mono" style={{ color: 'var(--clavex-primary)' }}>{selected.vct}</span></div>
                <div><span style={{ color: 'var(--clavex-neutral)' }}>Issued:</span>
                  <span className="ml-2">{new Date(selected.issued_at).toLocaleString()}</span></div>
                {selected.expires_at && (
                  <div><span style={{ color: 'var(--clavex-neutral)' }}>Expires:</span>
                    <span className="ml-2">{new Date(selected.expires_at).toLocaleString()}</span></div>
                )}
                {selected.status_index !== undefined && (
                  <div><span style={{ color: 'var(--clavex-neutral)' }}>Status slot:</span>
                    <span className="ml-2 font-mono">#{selected.status_index}</span></div>
                )}
                {selected.is_revoked && (
                  <div className="mt-2 p-2 rounded" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
                    <p className="flex items-center gap-1.5 font-medium" style={{ color: '#f87171' }}>
                      <AlertTriangle size={11} /> Revoked {selected.revoked_at ? new Date(selected.revoked_at).toLocaleDateString() : ''}
                    </p>
                    {selected.revocation_reason && (
                      <p className="mt-0.5" style={{ color: 'var(--clavex-ink-subtle)' }}>Reason: {selected.revocation_reason}</p>
                    )}
                  </div>
                )}
                <div className="mt-2 pt-2" style={{ borderTop: '1px solid rgba(93,202,165,0.08)' }}>
                  <span style={{ color: 'var(--clavex-neutral)' }}>SD-JWT hash:</span>
                  <p className="font-mono text-[10px] mt-0.5 break-all" style={{ color: 'var(--clavex-neutral)' }}>
                    {selected.sd_jwt_hash}
                  </p>
                </div>
              </div>
            ) : (
              <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>
                Click a credential to inspect its details and status.
              </p>
            )}
          </div>

          {/* Recent VP presentations */}
          <div style={{ ...cardStyle, flex: '1 1 0' }}>
            <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--clavex-ink)' }}>VP Presentation Log</h2>
            {sessions.length === 0 ? (
              <p className="text-xs" style={{ color: 'var(--clavex-neutral)' }}>No presentations yet</p>
            ) : (
              <div className="space-y-2 max-h-[200px] overflow-y-auto pr-1">
                {sessions.slice(0, 20).map((s) => (
                  <div key={s.id} className="flex items-center justify-between p-2 rounded"
                    style={{ background: 'rgba(93,202,165,0.03)', border: '1px solid rgba(93,202,165,0.07)' }}>
                    <span className="text-xs font-mono truncate max-w-[120px]" style={{ color: 'var(--clavex-ink-subtle)' }}>
                      {s.request_id.slice(0, 12)}…
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px]" style={{ color: 'rgba(196,223,240,0.35)' }}>
                        {new Date(s.created_at).toLocaleDateString()}
                      </span>
                      <span
                        className="text-[10px] px-1.5 py-0.5 rounded font-medium"
                        style={{
                          background: s.status === 'verified'
                            ? 'rgba(93,202,165,0.15)'
                            : s.status === 'failed'
                              ? 'rgba(239,68,68,0.12)'
                              : 'rgba(234,179,8,0.12)',
                          color: s.status === 'verified'
                            ? 'var(--clavex-primary)'
                            : s.status === 'failed'
                              ? '#f87171'
                              : '#fbbf24',
                        }}
                      >
                        {s.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {revokeTarget && (
        <RevokeModal
          cred={revokeTarget}
          onClose={() => setRevokeTarget(null)}
          onRevoked={() => { setRevokeTarget(null); load() }}
        />
      )}
    </div>
  )
}
