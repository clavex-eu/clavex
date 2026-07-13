import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { RotateCw, KeyRound } from 'lucide-react'

interface KeyEntry {
  key_kind: string
  rotation_policy: string
  rotation_interval_days: number
  last_rotated_at: string | null
}

const LABELS: Record<string, { title: string; subtitle: string; rotatePath: string }> = {
  oidc: {
    title: 'OIDC Signing Key (RSA / PS256)',
    subtitle: 'Global installation key used to sign OIDC/JWT tokens for every organization.',
    rotatePath: '/superadmin/rotate-signing-key',
  },
  pqc: {
    title: 'PQC Signing Key (ML-DSA-65)',
    subtitle: 'Global post-quantum key published in JWKS for every organization.',
    rotatePath: '/superadmin/rotate-pqc-signing-key',
  },
}

const card: React.CSSProperties = {
  background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)',
  borderRadius: 12, padding: '20px 24px', marginBottom: 16,
}
const inputStyle: React.CSSProperties = {
  padding: '6px 10px', borderRadius: 8, border: '0.5px solid var(--clavex-border)',
  fontSize: 13, background: 'white', color: 'var(--clavex-text)', width: 90,
}
const btn: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', borderRadius: 8,
  fontSize: 13, fontWeight: 500, border: 'none', cursor: 'pointer',
}

function formatDate(iso: string | null) {
  return iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'never'
}

function KeyCard({ entry }: { entry: KeyEntry }) {
  const qc = useQueryClient()
  const meta = LABELS[entry.key_kind]
  const [policy, setPolicy] = useState(entry.rotation_policy)
  const [interval, setInterval] = useState(entry.rotation_interval_days || 90)

  useEffect(() => {
    setPolicy(entry.rotation_policy)
    setInterval(entry.rotation_interval_days || 90)
  }, [entry.rotation_policy, entry.rotation_interval_days])

  const save = useMutation({
    mutationFn: (body: object) => api.put(`/superadmin/signing-keys/${entry.key_kind}`, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sa-signing-keys'] }); toast.success('Policy updated') },
    onError: () => toast.error('Failed to update policy'),
  })
  const rotate = useMutation({
    mutationFn: () => api.post(meta.rotatePath),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sa-signing-keys'] }); toast.success('Key rotated') },
    onError: () => toast.error('Failed to rotate key'),
  })

  const dirty = policy !== entry.rotation_policy || interval !== entry.rotation_interval_days

  return (
    <div style={card}>
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: 0 }}>{meta.title}</h2>
      <p style={{ fontSize: 12, margin: '2px 0 0', color: 'var(--clavex-neutral)' }}>{meta.subtitle}</p>
      <p style={{ fontSize: 12, margin: '6px 0 0', color: 'var(--clavex-neutral)' }}>
        Last rotated: <strong>{formatDate(entry.last_rotated_at)}</strong>
      </p>

      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 16, marginTop: 16, flexWrap: 'wrap' }}>
        <div>
          <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Rotation policy</label>
          <select value={policy} onChange={e => setPolicy(e.target.value)} style={{ ...inputStyle, width: 140 }}>
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
        <button style={{ ...btn, background: 'var(--clavex-primary)', color: 'white', opacity: dirty && !save.isPending ? 1 : 0.5 }}
          disabled={!dirty || save.isPending}
          onClick={() => save.mutate({ rotation_policy: policy, rotation_interval_days: interval })}>
          Save policy
        </button>
        <button style={{ ...btn, background: 'transparent', color: 'var(--clavex-text)', border: '0.5px solid var(--clavex-border)' }}
          disabled={rotate.isPending}
          onClick={() => { if (confirm('Rotate this global signing key now? The retired key stays in JWKS during the grace window.')) rotate.mutate() }}>
          <RotateCw size={14} /> {rotate.isPending ? 'Rotating…' : 'Rotate now'}
        </button>
      </div>
    </div>
  )
}

export default function SuperadminSigningKeysPage() {
  const { data, isLoading } = useQuery<{ keys: KeyEntry[] }>({
    queryKey: ['sa-signing-keys'],
    queryFn: () => api.get('/superadmin/signing-keys').then(r => r.data),
  })

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 28 }}>
        <KeyRound size={22} color="var(--clavex-primary)" />
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Installation Signing Keys</h1>
          <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
            Global OIDC and PQC signing keys shared by every organization. Changing these rotates the key for the whole installation.
          </p>
        </div>
      </div>
      {isLoading ? (
        <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>
      ) : (
        (data?.keys ?? []).map(k => <KeyCard key={k.key_kind} entry={k} />)
      )}
    </div>
  )
}
