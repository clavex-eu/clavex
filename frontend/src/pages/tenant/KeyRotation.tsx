import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { RotateCw, Lock, ShieldCheck } from 'lucide-react'

interface KeyEntry {
  key_kind: string
  rotation_policy: string
  rotation_interval_days: number
  last_rotated_at: string | null
  schedulable: boolean
  reason?: string
}

interface KeyRotationStatus {
  keys: KeyEntry[]
  byok_active: boolean
}

const KIND_LABELS: Record<string, { title: string; subtitle: string }> = {
  oidc: { title: 'OIDC Signing Key', subtitle: 'Classical RSA key (PS256) used to sign OIDC/JWT tokens' },
  pqc: { title: 'PQC Signing Key', subtitle: 'Post-quantum ML-DSA-65 key (FIPS 204) published in JWKS' },
  byok: { title: 'Organization Key (BYOK)', subtitle: 'Key you provided through your own key management' },
}

const card: React.CSSProperties = {
  background: 'var(--clavex-surface)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
  marginBottom: 16,
}

const inputStyle: React.CSSProperties = {
  padding: '6px 10px', borderRadius: 8, border: '0.5px solid var(--clavex-border)',
  fontSize: 13, background: 'white', color: 'var(--clavex-text)', width: 90,
}

const btnPrimary: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 6,
  padding: '7px 14px', borderRadius: 8, fontSize: 13, fontWeight: 500,
  background: 'var(--clavex-primary)', color: 'white', border: 'none', cursor: 'pointer',
}

function formatDate(iso: string | null) {
  if (!iso) return 'never'
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function KeyCard({ entry, orgId }: { entry: KeyEntry; orgId: string }) {
  const qc = useQueryClient()
  const label = KIND_LABELS[entry.key_kind] ?? { title: entry.key_kind, subtitle: '' }
  const [policy, setPolicy] = useState(entry.rotation_policy)
  const [interval, setInterval] = useState(entry.rotation_interval_days || 90)

  // Keep local edits in sync when the server data refreshes.
  useEffect(() => {
    setPolicy(entry.rotation_policy)
    setInterval(entry.rotation_interval_days || 90)
  }, [entry.rotation_policy, entry.rotation_interval_days])

  const save = useMutation({
    mutationFn: (body: object) => api.put(`/organizations/${orgId}/key-rotation/${entry.key_kind}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['key-rotation', orgId] })
      toast.success(`${label.title} policy updated`)
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg || 'Failed to update policy')
    },
  })

  // OIDC and PQC keys are both per-org now, so an org admin manages their own
  // rotation policy for each. Non-schedulable entries (an imported BYOK OIDC
  // key, or the BYOK card) are read-only and show a reason instead.
  const editable = entry.schedulable
  const dirty = policy !== entry.rotation_policy || interval !== entry.rotation_interval_days

  return (
    <div style={card}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
        <div style={{ display: 'flex', gap: 12 }}>
          {entry.schedulable
            ? <ShieldCheck size={20} color="var(--clavex-primary)" style={{ marginTop: 2 }} />
            : <Lock size={20} color="var(--clavex-neutral)" style={{ marginTop: 2 }} />}
          <div>
            <h2 style={{ fontSize: 15, fontWeight: 600, margin: 0 }}>{label.title}</h2>
            <p style={{ fontSize: 12, margin: '2px 0 0', color: 'var(--clavex-neutral)' }}>{label.subtitle}</p>
            {entry.key_kind !== 'byok' && (
              <p style={{ fontSize: 12, margin: '6px 0 0', color: 'var(--clavex-neutral)' }}>
                Last rotated: <strong>{formatDate(entry.last_rotated_at)}</strong>
              </p>
            )}
          </div>
        </div>
        <span style={{
          fontSize: 11, padding: '2px 10px', borderRadius: 12, whiteSpace: 'nowrap',
          background: entry.rotation_policy === 'scheduled' ? '#dcfce7' : '#f1f5f9',
          color: entry.rotation_policy === 'scheduled' ? '#15803d' : '#64748b',
        }}>
          {entry.schedulable ? entry.rotation_policy : 'manual only'}
        </span>
      </div>

      {editable ? (
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 16, marginTop: 16, flexWrap: 'wrap' }}>
          <div>
            <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Rotation policy</label>
            <select value={policy} onChange={e => setPolicy(e.target.value)}
              style={{ ...inputStyle, width: 140 }}>
              <option value="manual">Manual</option>
              <option value="scheduled">Scheduled</option>
            </select>
          </div>
          {policy === 'scheduled' && (
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Every (days)</label>
              <input type="number" min={1} max={3650} value={interval}
                onChange={e => setInterval(parseInt(e.target.value) || 90)} style={inputStyle} />
            </div>
          )}
          <button style={{ ...btnPrimary, opacity: dirty && !save.isPending ? 1 : 0.5 }}
            disabled={!dirty || save.isPending}
            onClick={() => save.mutate({ rotation_policy: policy, rotation_interval_days: interval })}>
            <RotateCw size={14} /> {save.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      ) : (
        <div style={{ marginTop: 14, padding: '10px 14px', borderRadius: 8, background: '#fef9c3', border: '0.5px solid #fde68a' }}>
          <p style={{ fontSize: 12, margin: 0, color: '#854d0e' }}>{entry.reason}</p>
        </div>
      )}
    </div>
  )
}

export default function KeyRotationPage() {
  const { orgId } = useAuthStore()

  const { data, isLoading } = useQuery<KeyRotationStatus>({
    queryKey: ['key-rotation', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/key-rotation`).then(r => r.data),
    enabled: !!orgId,
  })

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 28 }}>
        <RotateCw size={22} color="var(--clavex-primary)" />
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Key Rotation</h1>
          <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
            Scheduled rotation policy for signing keys. Rotations reuse the JWKS grace window, so tokens signed with the retired key stay verifiable.
          </p>
        </div>
      </div>

      {isLoading ? (
        <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>
      ) : (
        <>
          {(data?.keys ?? []).map(entry => (
            <KeyCard key={entry.key_kind} entry={entry} orgId={orgId!} />
          ))}
          <SSHCARotationCard orgId={orgId!} />
        </>
      )}
    </div>
  )
}

interface RotationStatus {
  id?: string
  state: string
  old_ca_fingerprint?: string
  new_ca_fingerprint?: string
  started_at?: string
  cutover_ready_at?: string
}

const STATE_META: Record<string, { label: string; color: string; bg: string }> = {
  idle: { label: 'Idle', color: '#64748b', bg: '#f1f5f9' },
  rotating: { label: 'Rotating', color: '#854d0e', bg: '#fef9c3' },
  cutover_ready: { label: 'Cutover ready', color: '#1d4ed8', bg: '#dbeafe' },
  rollback: { label: 'Rolled back', color: '#dc2626', bg: '#fee2e2' },
}

function SSHCARotationCard({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const { data, isLoading, isError } = useQuery<RotationStatus>({
    queryKey: ['ssh-ca-rotation', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/pam/ssh-ca/rotation`).then(r => r.data),
    enabled: !!orgId,
    retry: false,
  })

  const start = useMutation({
    mutationFn: () => api.post(`/organizations/${orgId}/pam/ssh-ca/rotation/start`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ssh-ca-rotation', orgId] }); toast.success('SSH CA rotation started') },
    onError: (e: unknown) => toast.error((e as { response?: { data?: { message?: string } } })?.response?.data?.message || 'Failed to start rotation'),
  })
  const abort = useMutation({
    mutationFn: (id: string) => api.post(`/organizations/${orgId}/pam/ssh-ca/rotation/${id}/abort`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ssh-ca-rotation', orgId] }); toast.success('Rotation aborted') },
    onError: () => toast.error('Failed to abort'),
  })

  // Manual force (admin) of mark-ready / complete, behind an explicit typed
  // confirmation (not a browser confirm()).
  const [confirmStep, setConfirmStep] = useState<null | 'mark-ready' | 'complete'>(null)
  const [confirmText, setConfirmText] = useState('')
  const forceErr = (e: unknown) => toast.error((e as { response?: { data?: { message?: string } } })?.response?.data?.message || 'Action failed')
  const closeConfirm = () => { setConfirmStep(null); setConfirmText('') }
  const markReady = useMutation({
    mutationFn: (id: string) => api.post(`/organizations/${orgId}/pam/ssh-ca/rotation/${id}/mark-ready`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ssh-ca-rotation', orgId] }); toast.success('Marked propagation ready'); closeConfirm() },
    onError: forceErr,
  })
  const complete = useMutation({
    mutationFn: (id: string) => api.post(`/organizations/${orgId}/pam/ssh-ca/rotation/${id}/complete`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ssh-ca-rotation', orgId] }); toast.success('Rotation completed'); closeConfirm() },
    onError: forceErr,
  })

  if (isError) {
    return (
      <div style={{ ...card, background: '#f8fafc' }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, margin: 0 }}>SSH Certificate Authority</h2>
        <p style={{ fontSize: 12, margin: '6px 0 0', color: 'var(--clavex-neutral)' }}>
          No SSH CA is configured for this organization, or you lack permission to view it.
        </p>
      </div>
    )
  }

  const state = data?.state ?? 'idle'
  const meta = STATE_META[state] ?? STATE_META.idle
  const active = state === 'rotating' || state === 'cutover_ready'

  return (
    <div style={card}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
        <div style={{ display: 'flex', gap: 12 }}>
          <ShieldCheck size={20} color="var(--clavex-primary)" style={{ marginTop: 2 }} />
          <div>
            <h2 style={{ fontSize: 15, fontWeight: 600, margin: 0 }}>SSH Certificate Authority</h2>
            <p style={{ fontSize: 12, margin: '2px 0 0', color: 'var(--clavex-neutral)' }}>
              Staged Vault CA rotation with an intermediate checkpoint (start → propagation ready → complete).
            </p>
          </div>
        </div>
        <span style={{ fontSize: 11, padding: '2px 10px', borderRadius: 12, whiteSpace: 'nowrap', background: meta.bg, color: meta.color }}>
          {isLoading ? '…' : meta.label}
        </span>
      </div>

      {active && (
        <div style={{ marginTop: 14, fontSize: 12, color: 'var(--clavex-neutral)' }}>
          {data?.old_ca_fingerprint && <div>Current CA: <code style={{ fontSize: 11 }}>{data.old_ca_fingerprint}</code></div>}
          {data?.new_ca_fingerprint && <div>Incoming CA: <code style={{ fontSize: 11 }}>{data.new_ca_fingerprint}</code></div>}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 16, flexWrap: 'wrap' }}>
        {!active && (
          <button style={{ ...btnPrimary, opacity: start.isPending ? 0.5 : 1 }} disabled={start.isPending}
            onClick={() => start.mutate()}>
            <RotateCw size={14} /> {start.isPending ? 'Starting…' : 'Start rotation'}
          </button>
        )}
        {state === 'rotating' && data?.id && (
          <button style={btnPrimary} onClick={() => { setConfirmStep('mark-ready'); setConfirmText('') }}>
            Mark propagation ready
          </button>
        )}
        {state === 'cutover_ready' && data?.id && (
          <button style={btnPrimary} onClick={() => { setConfirmStep('complete'); setConfirmText('') }}>
            Complete rotation
          </button>
        )}
        {active && data?.id && (
          <button style={{ ...btnPrimary, background: 'transparent', color: '#dc2626', border: '0.5px solid #dc2626' }}
            disabled={abort.isPending}
            onClick={() => { if (window.confirm('Abort the rotation? The new CA is discarded; the current CA is untouched.')) abort.mutate(data.id!) }}>
            Abort
          </button>
        )}
      </div>

      {confirmStep && data?.id && (
        <div style={{ marginTop: 14, padding: '14px', borderRadius: 8, background: '#fef2f2', border: '0.5px solid #fecaca' }}>
          <p style={{ fontSize: 12, margin: 0, color: '#991b1b', fontWeight: 600 }}>
            {confirmStep === 'mark-ready' ? 'Force mark propagation ready?' : 'Force complete rotation?'}
          </p>
          <p style={{ fontSize: 12, margin: '6px 0 0', color: '#7f1d1d' }}>
            Forcing this step without confirmed propagation to all devices may cause SSH access failures on devices that
            haven't received the new CA key yet. Only proceed if you have verified propagation through your own process.
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
            <input value={confirmText} onChange={e => setConfirmText(e.target.value)} placeholder="Type CONFIRM"
              style={{ ...inputStyle, width: 160 }} />
            <button
              style={{ ...btnPrimary, background: '#dc2626', opacity: confirmText === 'CONFIRM' ? 1 : 0.5 }}
              disabled={confirmText !== 'CONFIRM' || markReady.isPending || complete.isPending}
              onClick={() => (confirmStep === 'mark-ready' ? markReady : complete).mutate(data.id!)}>
              {confirmStep === 'mark-ready' ? 'Confirm mark ready' : 'Confirm complete'}
            </button>
            <button style={{ ...btnPrimary, background: 'transparent', color: 'var(--clavex-text)', border: '0.5px solid var(--clavex-border)' }}
              onClick={closeConfirm}>Cancel</button>
          </div>
        </div>
      )}

      {active && !confirmStep && (
        <div style={{ marginTop: 14, padding: '10px 14px', borderRadius: 8, background: '#eff6ff', border: '0.5px solid #bfdbfe' }}>
          <p style={{ fontSize: 12, margin: 0, color: '#1e40af' }}>
            {state === 'rotating'
              ? 'Normally the fleet consumer marks propagation ready once every host trusts the new CA.'
              : 'Normally the consumer completes the rotation to promote the new CA and start the grace window.'}
          </p>
          <p style={{ fontSize: 11, margin: '8px 0 0', color: '#3730a3' }}>
            The consumer (e.g. Keel) uses an <strong>Agent Token</strong> scoped <code>pam:ssh_ca:rotation:manage</code>{' '}
            (create one on the Agent Tokens page). The buttons above let an admin force the step manually.
          </p>
        </div>
      )}
    </div>
  )
}
