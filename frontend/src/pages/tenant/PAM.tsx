import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  KeyRound, ShieldCheck, Terminal, Server, ClipboardCopy,
  CheckCircle2, Clock, XCircle, Ban, RefreshCw,
  Eye, EyeOff, Trash2, Plus, RotateCw, FileText, FolderOpen,
  PlugZap, Unplug, Info, Download, History, AlertTriangle, Zap,
} from 'lucide-react'

// ── Styles ────────────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'var(--clavex-surface)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}

const btn = (variant: 'primary' | 'danger' | 'ghost' = 'primary'): React.CSSProperties => ({
  display: 'inline-flex', alignItems: 'center', gap: 6,
  padding: '6px 14px', borderRadius: 8, fontSize: 13, fontWeight: 600,
  border: 'none', cursor: 'pointer',
  background: variant === 'primary' ? 'var(--clavex-primary)'
    : variant === 'danger' ? 'var(--clavex-danger)'
    : 'transparent',
  color: variant === 'ghost' ? 'var(--clavex-text)' : '#fff',
  outline: variant === 'ghost' ? '0.5px solid var(--clavex-border)' : 'none',
})

const inp: React.CSSProperties = {
  width: '100%', padding: '8px 12px', borderRadius: 8, fontSize: 13,
  border: '0.5px solid var(--clavex-border)',
  background: 'var(--clavex-surface)', color: 'var(--clavex-text)',
  outline: 'none',
}

const label: React.CSSProperties = {
  display: 'block', fontSize: 12, fontWeight: 600,
  color: 'var(--clavex-neutral)', marginBottom: 4,
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface AccessRequest {
  id: string
  org_id: string
  requester_id: string
  reviewer_id?: string
  resource_type: string
  resource_id: string
  resource_name: string
  justification: string
  status: 'pending' | 'active' | 'denied' | 'expired' | 'revoked'
  requested_duration: number
  approved_duration?: number
  review_note?: string
  expires_at?: string
  created_at: string
  updated_at: string
}

interface PAMSession {
  id: string
  org_id: string
  access_request_id?: string
  user_id: string
  session_type: string
  target_host?: string
  target_port?: number
  target_user?: string
  client_ip?: string
  event_count: number
  started_at: string
  ended_at?: string
}

interface SessionEvent {
  id: string
  session_id: string
  event_type: string
  payload: Record<string, unknown>
  ts: string
  recorded_at: string // alias used in older responses
}

interface Credential {
  id: string
  org_id: string
  name: string
  description?: string
  credential_type: string
  username?: string
  target_host?: string
  checkout_duration: number
  require_access_request: boolean
  is_active: boolean
  rotation_interval_days?: number
  last_rotated_at?: string
  created_at: string
  updated_at: string
}

interface RotationLogEntry {
  id: number
  credential_id: string
  org_id: string
  rotated_by: string
  rotation_type: string
  note?: string
  rotated_at: string
}

interface SSHCAConfig {
  org_id: string
  vault_addr: string
  vault_mount: string
  vault_role: string
  cert_ttl_seconds: number
  require_access_request: boolean
  ca_public_key?: string
  created_at: string
  updated_at: string
}

interface BreakGlassConfig {
  org_id: string
  enabled: boolean
  max_uses_per_week: number
  require_justification: boolean
  notify_on_use: boolean
  created_at?: string
  updated_at?: string
}

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: AccessRequest['status'] }) {
  const cfg = {
    pending:  { color: '#d97706', bg: '#d9780612', Icon: Clock,        label: 'Pending'  },
    active:   { color: '#16a34a', bg: '#16a34a12', Icon: CheckCircle2, label: 'Active'   },
    denied:   { color: '#dc2626', bg: '#dc262612', Icon: XCircle,      label: 'Denied'   },
    expired:  { color: '#6b7280', bg: '#6b728012', Icon: Clock,        label: 'Expired'  },
    revoked:  { color: '#7c3aed', bg: '#7c3aed12', Icon: Ban,          label: 'Revoked'  },
  }[status] ?? { color: '#6b7280', bg: '#6b728012', Icon: Clock, label: status }
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 99, background: cfg.bg, color: cfg.color,
      fontSize: 11, fontWeight: 700 }}>
      <cfg.Icon size={11} />
      {cfg.label}
    </span>
  )
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'requests',    label: 'Access Requests',   Icon: ShieldCheck    },
  { id: 'vault',       label: 'Credential Vault',  Icon: KeyRound       },
  { id: 'sessions',    label: 'Sessions',          Icon: Terminal       },
  { id: 'sshca',       label: 'SSH CA (Linux SSO)', Icon: Server        },
  { id: 'break-glass', label: 'Break Glass',       Icon: AlertTriangle  },
]

// ── ACCESS REQUESTS tab ───────────────────────────────────────────────────────

function AccessRequestsTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [status, setStatus] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    resource_type: 'server', resource_id: '', resource_name: '',
    justification: '', requested_duration: 60,
  })

  const { data, isLoading } = useQuery({
    queryKey: ['pam-requests', orgId, status],
    queryFn: () => api.get(`/organizations/${orgId}/pam/access-requests`, { params: { status, per_page: 50 } }).then(r => r.data),
  })

  const createMut = useMutation({
    mutationFn: (body: typeof form) => api.post(`/organizations/${orgId}/pam/access-requests`, body).then(r => r.data),
    onSuccess: () => { toast.success('Access request created'); qc.invalidateQueries({ queryKey: ['pam-requests', orgId] }); setShowForm(false) },
    onError: () => toast.error('Failed to create request'),
  })

  const approveMut = useMutation({
    mutationFn: (id: string) => api.post(`/organizations/${orgId}/pam/access-requests/${id}/approve`, {}).then(r => r.data),
    onSuccess: () => { toast.success('Approved'); qc.invalidateQueries({ queryKey: ['pam-requests', orgId] }) },
    onError: () => toast.error('Failed to approve'),
  })

  const denyMut = useMutation({
    mutationFn: (id: string) => api.post(`/organizations/${orgId}/pam/access-requests/${id}/deny`, {}).then(r => r.data),
    onSuccess: () => { toast.success('Denied'); qc.invalidateQueries({ queryKey: ['pam-requests', orgId] }) },
    onError: () => toast.error('Failed to deny'),
  })

  const revokeMut = useMutation({
    mutationFn: (id: string) => api.post(`/organizations/${orgId}/pam/access-requests/${id}/revoke`, { reason: 'Manually revoked' }).then(r => r.data),
    onSuccess: () => { toast.success('Revoked'); qc.invalidateQueries({ queryKey: ['pam-requests', orgId] }) },
    onError: () => toast.error('Failed to revoke'),
  })

  const requests: AccessRequest[] = data?.data ?? []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <select value={status} onChange={e => setStatus(e.target.value)}
          style={{ ...inp, width: 160 }}>
          <option value="">All statuses</option>
          {['pending','active','denied','expired','revoked'].map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <button style={btn('primary')} onClick={() => setShowForm(v => !v)}>
          <Plus size={14} /> New Request
        </button>
      </div>

      {/* Create form */}
      {showForm && (
        <div style={card}>
          <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>New JIT Access Request</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <span style={label}>Resource Type</span>
              <select value={form.resource_type} onChange={e => setForm(f => ({ ...f, resource_type: e.target.value }))} style={inp}>
                {['server','database','application','credential','admin_role'].map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
            <div>
              <span style={label}>Resource ID</span>
              <input style={inp} placeholder="e.g. prod-db-01" value={form.resource_id}
                onChange={e => setForm(f => ({ ...f, resource_id: e.target.value }))} />
            </div>
            <div>
              <span style={label}>Resource Name</span>
              <input style={inp} placeholder="Human-readable name" value={form.resource_name}
                onChange={e => setForm(f => ({ ...f, resource_name: e.target.value }))} />
            </div>
            <div>
              <span style={label}>Duration (minutes)</span>
              <input style={inp} type="number" min={1} value={form.requested_duration}
                onChange={e => setForm(f => ({ ...f, requested_duration: parseInt(e.target.value) || 60 }))} />
            </div>
            <div style={{ gridColumn: '1/-1' }}>
              <span style={label}>Justification</span>
              <textarea style={{ ...inp, height: 64, resize: 'vertical' }} placeholder="Business reason for access..."
                value={form.justification}
                onChange={e => setForm(f => ({ ...f, justification: e.target.value }))} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button style={btn('primary')} onClick={() => createMut.mutate(form)} disabled={createMut.isPending}>
              {createMut.isPending ? 'Submitting…' : 'Submit Request'}
            </button>
            <button style={btn('ghost')} onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* List */}
      {isLoading ? <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {requests.length === 0 && (
            <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>No access requests found.</p>
          )}
          {requests.map(ar => (
            <div key={ar.id} style={{ ...card, display: 'flex', alignItems: 'flex-start', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <StatusBadge status={ar.status} />
                  <span style={{ fontSize: 13, fontWeight: 700 }}>{ar.resource_name}</span>
                  <span style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>({ar.resource_type})</span>
                </div>
                <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: 0 }}>{ar.justification}</p>
                <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', margin: '4px 0 0' }}>
                  {ar.requested_duration} min • {new Date(ar.created_at).toLocaleString()}
                </p>
              </div>
              {ar.status === 'pending' && (
                <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                  <button style={{ ...btn('primary'), padding: '4px 10px', fontSize: 12 }}
                    onClick={() => approveMut.mutate(ar.id)} disabled={approveMut.isPending}>Approve</button>
                  <button style={{ ...btn('danger'), padding: '4px 10px', fontSize: 12 }}
                    onClick={() => denyMut.mutate(ar.id)} disabled={denyMut.isPending}>Deny</button>
                </div>
              )}
              {ar.status === 'active' && (
                <button style={{ ...btn('ghost'), padding: '4px 10px', fontSize: 12 }}
                  onClick={() => revokeMut.mutate(ar.id)} disabled={revokeMut.isPending}>Revoke</button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── CREDENTIAL VAULT tab ──────────────────────────────────────────────────────

const ROTATION_OPTIONS = [
  { label: 'No auto-rotation', value: '' },
  { label: 'Every 30 days (PCI DSS)', value: '30' },
  { label: 'Every 60 days', value: '60' },
  { label: 'Every 90 days (NIST)', value: '90' },
  { label: 'Every 180 days', value: '180' },
]

function rotationStatus(cred: Credential): { color: string; bg: string; text: string } | null {
  if (!cred.rotation_interval_days) return null
  const daysAgo = cred.last_rotated_at
    ? (Date.now() - new Date(cred.last_rotated_at).getTime()) / 86_400_000
    : Infinity
  const due = cred.rotation_interval_days
  if (daysAgo >= due)    return { color: '#dc2626', bg: '#dc262612', text: 'Overdue' }
  if (daysAgo >= due * 0.85) return { color: '#d97706', bg: '#d9780612', text: 'Due soon' }
  return { color: '#16a34a', bg: '#16a34a12', text: `Rotates every ${due}d` }
}

function CredentialVaultTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [revealedCheckout, setRevealedCheckout] = useState<{ id: string; secret: string; warning: string } | null>(null)
  const [rotLogId, setRotLogId] = useState<string | null>(null)
  const [form, setForm] = useState({
    name: '', description: '', credential_type: 'password', username: '',
    secret: '', target_host: '', checkout_duration: 60, require_access_request: false,
    rotation_interval_days: null as number | null,
  })

  const { data, isLoading } = useQuery({
    queryKey: ['pam-credentials', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/pam/credentials`).then(r => r.data),
  })

  const { data: rotLogData } = useQuery({
    queryKey: ['pam-rotation-log', orgId, rotLogId],
    queryFn: () => api.get(`/organizations/${orgId}/pam/credentials/${rotLogId}/rotation-log`).then(r => r.data),
    enabled: !!rotLogId,
  })

  const createMut = useMutation({
    mutationFn: (body: typeof form) => api.post(`/organizations/${orgId}/pam/credentials`, body).then(r => r.data),
    onSuccess: () => { toast.success('Credential added'); qc.invalidateQueries({ queryKey: ['pam-credentials', orgId] }); setShowForm(false) },
    onError: () => toast.error('Failed to create credential'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/pam/credentials/${id}`),
    onSuccess: () => { toast.success('Deleted'); qc.invalidateQueries({ queryKey: ['pam-credentials', orgId] }) },
    onError: () => toast.error('Failed to delete'),
  })

  const checkoutMut = useMutation({
    mutationFn: (id: string) => api.post(`/organizations/${orgId}/pam/credentials/${id}/checkout`, { reason: 'Manual checkout' }).then(r => r.data),
    onSuccess: (data) => { setRevealedCheckout({ id: data.checkout.id, secret: data.secret, warning: data.warning }) },
    onError: () => toast.error('Checkout failed'),
  })

  const returnMut = useMutation({
    mutationFn: (checkoutId: string) => api.post(`/organizations/${orgId}/pam/credentials/unused/return`, { checkout_id: checkoutId }),
    onSuccess: () => { toast.success('Returned'); setRevealedCheckout(null) },
    onError: () => toast.error('Return failed'),
  })

  const credentials: Credential[] = data?.data ?? []
  const rotLog: RotationLogEntry[] = rotLogData?.data ?? []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Secret reveal banner */}
      {revealedCheckout && (
        <div style={{ background: '#16a34a12', border: '1px solid #16a34a30', borderRadius: 10, padding: '14px 18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: '#16a34a' }}>Credential Checked Out</span>
            <button style={btn('ghost')} onClick={() => setRevealedCheckout(null)}>Dismiss</button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--clavex-surface)',
            borderRadius: 8, padding: '8px 12px', fontFamily: 'monospace', fontSize: 13 }}>
            <span style={{ flex: 1, wordBreak: 'break-all' }}>{revealedCheckout.secret}</span>
            <button style={btn('ghost')} onClick={() => { navigator.clipboard.writeText(revealedCheckout.secret); toast.success('Copied') }}>
              <ClipboardCopy size={14} /> Copy
            </button>
          </div>
          <p style={{ fontSize: 11, color: '#d97706', margin: '6px 0 0' }}>{revealedCheckout.warning}</p>
          <button style={{ ...btn('ghost'), marginTop: 10, fontSize: 12 }}
            onClick={() => returnMut.mutate(revealedCheckout.id)}>Return Checkout</button>
        </div>
      )}

      {/* Toolbar */}
      <button style={{ ...btn('primary'), alignSelf: 'flex-start' }} onClick={() => setShowForm(v => !v)}>
        <Plus size={14} /> Add Credential
      </button>

      {/* Create form */}
      {showForm && (
        <div style={card}>
          <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>New Vault Credential</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <span style={label}>Name</span>
              <input style={inp} placeholder="prod-db-root" value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div>
              <span style={label}>Type</span>
              <select value={form.credential_type} onChange={e => setForm(f => ({ ...f, credential_type: e.target.value }))} style={inp}>
                {['password','api_key','token','ssh_key','certificate'].map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
            <div>
              <span style={label}>Username</span>
              <input style={inp} placeholder="root" value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))} />
            </div>
            <div>
              <span style={label}>Target Host</span>
              <input style={inp} placeholder="db.internal.example.com" value={form.target_host}
                onChange={e => setForm(f => ({ ...f, target_host: e.target.value }))} />
            </div>
            <div style={{ gridColumn: '1/-1' }}>
              <span style={label}>Secret (encrypted at rest)</span>
              <textarea style={{ ...inp, height: 80, fontFamily: 'monospace', fontSize: 12, resize: 'vertical' }}
                placeholder="Paste password, SSH private key, API token..."
                value={form.secret}
                onChange={e => setForm(f => ({ ...f, secret: e.target.value }))} />
            </div>
            <div>
              <span style={label}>Checkout Duration (min)</span>
              <input style={inp} type="number" min={1} value={form.checkout_duration}
                onChange={e => setForm(f => ({ ...f, checkout_duration: parseInt(e.target.value) || 60 }))} />
            </div>
            <div>
              <span style={label}>Auto-rotation (PCI DSS / NIS2)</span>
              <select style={inp}
                value={form.rotation_interval_days?.toString() ?? ''}
                onChange={e => setForm(f => ({ ...f, rotation_interval_days: e.target.value ? parseInt(e.target.value) : null }))}>
                {ROTATION_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              {form.rotation_interval_days && ['ssh_key','certificate'].includes(form.credential_type) && (
                <p style={{ fontSize: 11, color: '#d97706', margin: '4px 0 0' }}>
                  ssh_key / certificate types log a reminder — auto-rotation requires PKI integration.
                </p>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 20 }}>
              <input type="checkbox" id="req-ar" checked={form.require_access_request}
                onChange={e => setForm(f => ({ ...f, require_access_request: e.target.checked }))} />
              <label htmlFor="req-ar" style={{ fontSize: 13 }}>Require access request</label>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button style={btn('primary')} onClick={() => createMut.mutate(form)} disabled={createMut.isPending}>
              {createMut.isPending ? 'Saving…' : 'Save Credential'}
            </button>
            <button style={btn('ghost')} onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* List */}
      {isLoading ? <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {credentials.length === 0 && (
            <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>No credentials in vault.</p>
          )}
          {credentials.map(cred => {
            const rs = rotationStatus(cred)
            const showLog = rotLogId === cred.id
            return (
              <div key={cred.id} style={card}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                      <span style={{ fontSize: 13, fontWeight: 700 }}>{cred.name}</span>
                      <span style={{ fontSize: 11, color: 'var(--clavex-neutral)', background: 'var(--clavex-border)',
                        borderRadius: 4, padding: '1px 6px' }}>{cred.credential_type}</span>
                      {cred.require_access_request && (
                        <span style={{ fontSize: 10, color: '#d97706', background: '#d9780618',
                          borderRadius: 4, padding: '1px 6px' }}>requires JIT</span>
                      )}
                      {rs && (
                        <span style={{ fontSize: 10, fontWeight: 700, color: rs.color, background: rs.bg,
                          borderRadius: 4, padding: '1px 6px' }}>{rs.text}</span>
                      )}
                    </div>
                    {cred.target_host && (
                      <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: 0 }}>
                        {cred.username && `${cred.username}@`}{cred.target_host}
                      </p>
                    )}
                    {cred.last_rotated_at && (
                      <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', margin: '2px 0 0' }}>
                        Last rotated: {new Date(cred.last_rotated_at).toLocaleString()}
                      </p>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    {cred.rotation_interval_days && (
                      <button style={{ ...btn('ghost'), fontSize: 12, padding: '4px 10px' }}
                        onClick={() => setRotLogId(showLog ? null : cred.id)}>
                        <History size={13} /> Log
                      </button>
                    )}
                    <button style={{ ...btn('ghost'), fontSize: 12, padding: '4px 10px' }}
                      onClick={() => checkoutMut.mutate(cred.id)} disabled={checkoutMut.isPending}>
                      <Eye size={13} /> Checkout
                    </button>
                    <button style={{ ...btn('ghost'), fontSize: 12, padding: '4px 10px', color: 'var(--clavex-danger)' }}
                      onClick={() => { if (confirm('Delete credential?')) deleteMut.mutate(cred.id) }}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
                {/* Rotation log panel */}
                {showLog && (
                  <div style={{ marginTop: 12, borderTop: '0.5px solid var(--clavex-border)', paddingTop: 12 }}>
                    <p style={{ fontSize: 12, fontWeight: 700, margin: '0 0 8px' }}>Rotation Log</p>
                    {rotLog.length === 0
                      ? <p style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>No rotation events yet.</p>
                      : rotLog.map(e => (
                        <div key={e.id} style={{ display: 'flex', gap: 12, fontSize: 12, marginBottom: 4, alignItems: 'center' }}>
                          <span style={{ color: 'var(--clavex-neutral)', fontFamily: 'monospace', flexShrink: 0 }}>
                            {new Date(e.rotated_at).toLocaleString()}
                          </span>
                          <span style={{ padding: '1px 6px', borderRadius: 4, fontSize: 11,
                            background: e.rotation_type === 'auto' ? '#0369a112' : '#6d28d912',
                            color: e.rotation_type === 'auto' ? '#0369a1' : '#6d28d9' }}>
                            {e.rotation_type}
                          </span>
                          <span style={{ color: 'var(--clavex-neutral)' }}>{e.rotated_by}</span>
                          {e.note && <span style={{ color: 'var(--clavex-neutral)', fontStyle: 'italic' }}>{e.note}</span>}
                        </div>
                      ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Session Playback ──────────────────────────────────────────────────────────

const EVENT_TYPE_META: Record<string, { color: string; bg: string; Icon: React.ComponentType<{ size?: number; color?: string }> }> = {
  command:    { color: '#16a34a', bg: '#16a34a12', Icon: Terminal   },
  output:     { color: '#6b7280', bg: '#6b728012', Icon: FileText   },
  file_access:{ color: '#0369a1', bg: '#0369a112', Icon: FolderOpen },
  connect:    { color: '#7c3aed', bg: '#7c3aed12', Icon: PlugZap    },
  disconnect: { color: '#6b7280', bg: '#6b728012', Icon: Unplug     },
}

function eventMeta(type: string) {
  return EVENT_TYPE_META[type] ?? { color: '#6b7280', bg: '#6b728012', Icon: Info as React.ComponentType<{ size?: number; color?: string }> }
}

function renderPayload(ev: SessionEvent): string {
  const p = ev.payload
  if (ev.event_type === 'command' && p.command) return String(p.command)
  if (ev.event_type === 'output'  && p.data)    return String(p.data).slice(0, 500)
  if (ev.event_type === 'file_access' && p.path) return `${p.operation ?? 'access'} ${p.path}`
  if (ev.event_type === 'connect' || ev.event_type === 'disconnect') return String(p.host ?? '')
  return JSON.stringify(p)
}

function downloadTranscript(session: PAMSession, events: SessionEvent[]) {
  const lines: string[] = [
    `PAM Session Transcript`,
    `Session ID : ${session.id}`,
    `Type       : ${session.session_type}`,
    `Target     : ${session.target_user ? session.target_user + '@' : ''}${session.target_host ?? '—'}`,
    `Started    : ${new Date(session.started_at).toISOString()}`,
    `Ended      : ${session.ended_at ? new Date(session.ended_at).toISOString() : '(active)'}`,
    `Events     : ${events.length}`,
    ``,
    `${'─'.repeat(72)}`,
    ``,
    ...events.map(ev => {
      const ts = new Date(ev.ts ?? ev.recorded_at).toISOString()
      return `[${ts}] ${ev.event_type.padEnd(12)} ${renderPayload(ev)}`
    }),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/plain' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `pam-session-${session.id.slice(0, 8)}.txt`
  a.click()
  URL.revokeObjectURL(a.href)
}

function SessionPlaybackPanel({ orgId, session, onClose }: {
  orgId: string
  session: PAMSession
  onClose: () => void
}) {
  const [filter, setFilter] = useState<string>('all')

  const { data: eventsData, isLoading } = useQuery({
    queryKey: ['pam-session-events', orgId, session.id],
    queryFn: () => api.get(`/organizations/${orgId}/pam/sessions/${session.id}/events`).then(r => r.data),
  })

  const allEvents: SessionEvent[] = eventsData?.data ?? []
  const eventTypes = useMemo(() => Array.from(new Set(allEvents.map(e => e.event_type))), [allEvents])
  const shown = filter === 'all' ? allEvents : allEvents.filter(e => e.event_type === filter)

  return (
    <div style={{ ...card, marginTop: 8, border: '1px solid var(--clavex-primary)40' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12 }}>
        <div>
          <p style={{ fontSize: 13, fontWeight: 700, margin: 0 }}>
            Session Playback — {session.session_type}
            {session.target_host && ` → ${session.target_user ? session.target_user + '@' : ''}${session.target_host}`}
          </p>
          <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', margin: '2px 0 0' }}>
            {new Date(session.started_at).toLocaleString()}
            {session.ended_at ? ` → ${new Date(session.ended_at).toLocaleString()}` : ' (active)'}
            {session.client_ip ? ` • ${session.client_ip}` : ''}
            {' • '}{allEvents.length} events
          </p>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button style={{ ...btn('ghost'), fontSize: 12, padding: '4px 10px' }}
            onClick={() => downloadTranscript(session, shown)}>
            <Download size={13} /> Export
          </button>
          <button style={{ ...btn('ghost'), fontSize: 12, padding: '4px 10px' }} onClick={onClose}>✕</button>
        </div>
      </div>

      {/* Event type filter */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
        {['all', ...eventTypes].map(t => {
          const active = filter === t
          const m = t === 'all' ? null : eventMeta(t)
          return (
            <button key={t} onClick={() => setFilter(t)} style={{
              padding: '3px 10px', borderRadius: 99, fontSize: 11, fontWeight: active ? 700 : 400,
              border: `1px solid ${active && m ? m.color : 'var(--clavex-border)'}`,
              background: active && m ? m.bg : 'transparent',
              color: active && m ? m.color : 'var(--clavex-neutral)',
              cursor: 'pointer',
            }}>
              {t}
              {t !== 'all' && ` (${allEvents.filter(e => e.event_type === t).length})`}
            </button>
          )
        })}
      </div>

      {/* Timeline */}
      {isLoading && <p style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>Loading events…</p>}
      {!isLoading && shown.length === 0 && (
        <p style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>No events match the current filter.</p>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 480, overflowY: 'auto' }}>
        {shown.map(ev => {
          const m = eventMeta(ev.event_type)
          const content = renderPayload(ev)
          const isCode = ['command','output'].includes(ev.event_type)
          return (
            <div key={ev.id} style={{ display: 'flex', gap: 10, fontSize: 12, alignItems: 'flex-start',
              padding: '5px 8px', borderRadius: 6, background: m.bg }}>
              <m.Icon size={13} color={m.color} />
              <span style={{ color: 'var(--clavex-neutral)', flexShrink: 0, fontFamily: 'monospace', fontSize: 11 }}>
                {new Date(ev.ts ?? ev.recorded_at).toLocaleTimeString()}
              </span>
              <span style={{ fontWeight: 700, color: m.color, flexShrink: 0, minWidth: 90 }}>{ev.event_type}</span>
              {isCode
                ? <code style={{ fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all', flex: 1 }}>{content}</code>
                : <span style={{ color: 'var(--clavex-neutral)', flex: 1, wordBreak: 'break-all' }}>{content}</span>
              }
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── SESSIONS tab ──────────────────────────────────────────────────────────────

function SessionsTab({ orgId }: { orgId: string }) {
  const [playbackSession, setPlaybackSession] = useState<PAMSession | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['pam-sessions', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/pam/sessions`, { params: { per_page: 50 } }).then(r => r.data),
  })

  const sessions: PAMSession[] = data?.data ?? []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {isLoading && <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>}
      {!isLoading && sessions.length === 0 && (
        <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>No privileged sessions recorded yet.</p>
      )}
      {sessions.map(s => (
        <div key={s.id}>
          <div style={card}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                  <span style={{ fontSize: 13, fontWeight: 700 }}>{s.session_type}</span>
                  {s.target_host && (
                    <span style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>
                      → {s.target_user ? `${s.target_user}@` : ''}{s.target_host}{s.target_port ? `:${s.target_port}` : ''}
                    </span>
                  )}
                  <span style={{ fontSize: 11, padding: '1px 7px', borderRadius: 99,
                    background: s.ended_at ? '#6b728012' : '#16a34a18',
                    color: s.ended_at ? '#6b7280' : '#16a34a' }}>
                    {s.ended_at ? 'Ended' : 'Active'}
                  </span>
                </div>
                <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', margin: 0 }}>
                  {new Date(s.started_at).toLocaleString()}
                  {s.ended_at ? ` → ${new Date(s.ended_at).toLocaleString()}` : ''}
                  {' • '}{s.event_count} event{s.event_count !== 1 ? 's' : ''}
                  {s.client_ip ? ` • ${s.client_ip}` : ''}
                </p>
              </div>
              <button style={{ ...btn('ghost'), fontSize: 12, padding: '4px 12px' }}
                onClick={() => setPlaybackSession(playbackSession?.id === s.id ? null : s)}>
                {playbackSession?.id === s.id ? 'Close' : '▶ Playback'}
              </button>
            </div>
          </div>
          {playbackSession?.id === s.id && (
            <SessionPlaybackPanel orgId={orgId} session={s} onClose={() => setPlaybackSession(null)} />
          )}
        </div>
      ))}
    </div>
  )
}

// ── SSH CA tab ────────────────────────────────────────────────────────────────

function SSHCATab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [showPubKey, setShowPubKey] = useState(false)
  const [showSignForm, setShowSignForm] = useState(false)
  const [signedCert, setSignedCert] = useState<{ signed_key: string; principals: string; expires_at: string; instructions: string } | null>(null)
  const [form, setForm] = useState({
    vault_addr: '', vault_token: '', vault_mount: 'ssh',
    vault_role: '', cert_ttl_seconds: 3600, require_access_request: false,
  })
  const [signForm, setSignForm] = useState({ public_key: '', valid_principals: '' })

  const { data: cfg, isLoading } = useQuery<SSHCAConfig | null>({
    queryKey: ['pam-sshca', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/pam/ssh-ca`).then(r => r.data).catch((e: { response?: { status?: number } }) => e?.response?.status === 404 ? null : Promise.reject(e)),
  })

  const upsertMut = useMutation({
    mutationFn: (body: typeof form) => api.put(`/organizations/${orgId}/pam/ssh-ca`, body).then(r => r.data),
    onSuccess: () => { toast.success('SSH CA configured'); qc.invalidateQueries({ queryKey: ['pam-sshca', orgId] }) },
    onError: () => toast.error('Failed to save SSH CA config'),
  })

  const deleteMut = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/pam/ssh-ca`),
    onSuccess: () => { toast.success('SSH CA removed'); qc.invalidateQueries({ queryKey: ['pam-sshca', orgId] }) },
    onError: () => toast.error('Failed to delete'),
  })

  const signMut = useMutation({
    mutationFn: (body: typeof signForm) => api.post(`/organizations/${orgId}/pam/ssh-ca/sign`, body).then(r => r.data),
    onSuccess: (data) => setSignedCert(data),
    onError: () => toast.error('Signing failed'),
  })

  if (isLoading) return <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Differentiator callout */}
      <div style={{ background: 'var(--clavex-primary)12', border: '1px solid var(--clavex-primary)30',
        borderRadius: 10, padding: '12px 16px' }}>
        <p style={{ fontSize: 13, fontWeight: 600, margin: '0 0 4px' }}>Platform SSO for Linux — No Agent Required</p>
        <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: 0 }}>
          Clavex signs ephemeral SSH certificates via HashiCorp Vault SSH CA. Any Linux server with standard OpenSSH
          works — no proprietary PAM agent to install or maintain. Just add{' '}
          <code style={{ fontFamily: 'monospace', background: 'var(--clavex-border)', borderRadius: 3, padding: '0 4px' }}>
            TrustedUserCAKeys
          </code>{' '}to your sshd_config once.
        </p>
      </div>

      {/* Config form */}
      <div style={card}>
        <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>
          {cfg ? 'Update Vault SSH CA Config' : 'Configure Vault SSH CA'}
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <span style={label}>Vault Address</span>
            <input style={inp} placeholder="https://vault.internal.example.com"
              defaultValue={cfg?.vault_addr ?? ''} key={cfg?.vault_addr}
              onChange={e => setForm(f => ({ ...f, vault_addr: e.target.value }))} />
          </div>
          <div>
            <span style={label}>Vault Token (encrypted at rest)</span>
            <input style={inp} type="password" placeholder="hvs.XXXXXXXX"
              onChange={e => setForm(f => ({ ...f, vault_token: e.target.value }))} />
          </div>
          <div>
            <span style={label}>SSH Mount (default: ssh)</span>
            <input style={inp} defaultValue={cfg?.vault_mount ?? 'ssh'}
              onChange={e => setForm(f => ({ ...f, vault_mount: e.target.value }))} />
          </div>
          <div>
            <span style={label}>Vault Role</span>
            <input style={inp} placeholder="clavex-user" defaultValue={cfg?.vault_role ?? ''}
              onChange={e => setForm(f => ({ ...f, vault_role: e.target.value }))} />
          </div>
          <div>
            <span style={label}>Certificate TTL (seconds)</span>
            <input style={inp} type="number" min={60} defaultValue={cfg?.cert_ttl_seconds ?? 3600}
              onChange={e => setForm(f => ({ ...f, cert_ttl_seconds: parseInt(e.target.value) || 3600 }))} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 20 }}>
            <input type="checkbox" id="sshca-req-ar" defaultChecked={cfg?.require_access_request ?? false}
              onChange={e => setForm(f => ({ ...f, require_access_request: e.target.checked }))} />
            <label htmlFor="sshca-req-ar" style={{ fontSize: 13 }}>Require access request to sign</label>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
          <button style={btn('primary')} onClick={() => upsertMut.mutate(form)} disabled={upsertMut.isPending}>
            {upsertMut.isPending ? 'Saving…' : 'Save'}
          </button>
          {cfg && (
            <button style={{ ...btn('ghost'), color: 'var(--clavex-danger)' }}
              onClick={() => { if (confirm('Remove SSH CA config?')) deleteMut.mutate() }}>
              <Trash2 size={13} /> Remove
            </button>
          )}
        </div>
      </div>

      {cfg && (
        <>
          {/* CA Public Key */}
          <div style={card}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>CA Public Key</h3>
              <div style={{ display: 'flex', gap: 6 }}>
                <button style={btn('ghost')} onClick={() => setShowPubKey(v => !v)}>
                  {showPubKey ? <EyeOff size={13} /> : <Eye size={13} />}
                  {showPubKey ? 'Hide' : 'Show'}
                </button>
                <button style={btn('ghost')} onClick={() => {
                  api.get(`/organizations/${orgId}/pam/ssh-ca/public-key`).then(r => {
                    navigator.clipboard.writeText(r.data)
                    toast.success('Public key copied')
                  })
                }}>
                  <ClipboardCopy size={13} /> Copy
                </button>
                <button style={btn('ghost')} onClick={() => {
                  api.get(`/organizations/${orgId}/pam/ssh-ca/public-key`).then(r => {
                    qc.invalidateQueries({ queryKey: ['pam-sshca', orgId] })
                    navigator.clipboard.writeText(r.data)
                    toast.success('Refreshed and copied')
                  })
                }}>
                  <RotateCw size={13} /> Refresh
                </button>
              </div>
            </div>
            {showPubKey && cfg.ca_public_key && (
              <pre style={{ fontFamily: 'monospace', fontSize: 11, background: 'var(--clavex-surface)',
                border: '0.5px solid var(--clavex-border)', borderRadius: 6, padding: '10px 12px',
                overflowX: 'auto', margin: 0, color: 'var(--clavex-text)' }}>
                {cfg.ca_public_key}
              </pre>
            )}
            <div style={{ marginTop: 12, background: '#6b728012', borderRadius: 8, padding: '10px 14px' }}>
              <p style={{ fontSize: 12, fontWeight: 600, margin: '0 0 4px' }}>Server Setup (one-time, per host)</p>
              <pre style={{ fontSize: 11, fontFamily: 'monospace', margin: 0, whiteSpace: 'pre-wrap', color: 'var(--clavex-neutral)' }}>
{`# 1. Copy CA public key to server
curl https://<your-clavex-domain>/api/v1/organizations/${orgId}/pam/ssh-ca/public-key \\
  -H "Authorization: Bearer <token>" \\
  > /etc/ssh/clavex_ca.pub

# 2. Add to /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/clavex_ca.pub

# 3. Reload sshd
systemctl reload sshd`}
              </pre>
            </div>
          </div>

          {/* Sign SSH Key */}
          <div style={card}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Sign SSH Public Key</h3>
              <button style={btn('ghost')} onClick={() => setShowSignForm(v => !v)}>
                <RefreshCw size={13} /> {showSignForm ? 'Hide' : 'Sign Key'}
              </button>
            </div>

            {showSignForm && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div>
                  <span style={label}>SSH Public Key</span>
                  <textarea style={{ ...inp, height: 80, fontFamily: 'monospace', fontSize: 11, resize: 'vertical' }}
                    placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host"
                    value={signForm.public_key}
                    onChange={e => setSignForm(f => ({ ...f, public_key: e.target.value }))} />
                </div>
                <div>
                  <span style={label}>Valid Principals (leave blank to use your email)</span>
                  <input style={inp} placeholder="user@example.com,ubuntu"
                    value={signForm.valid_principals}
                    onChange={e => setSignForm(f => ({ ...f, valid_principals: e.target.value }))} />
                </div>
                <button style={{ ...btn('primary'), alignSelf: 'flex-start' }}
                  onClick={() => signMut.mutate(signForm)} disabled={signMut.isPending}>
                  {signMut.isPending ? 'Signing…' : 'Sign Certificate'}
                </button>

                {signedCert && (
                  <div style={{ background: '#16a34a12', border: '1px solid #16a34a30', borderRadius: 8, padding: '12px 16px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                      <span style={{ fontSize: 13, fontWeight: 700, color: '#16a34a' }}>Certificate Signed</span>
                      <button style={btn('ghost')} onClick={() => { navigator.clipboard.writeText(signedCert.signed_key); toast.success('Cert copied') }}>
                        <ClipboardCopy size={13} /> Copy
                      </button>
                    </div>
                    <pre style={{ fontFamily: 'monospace', fontSize: 10, margin: 0, overflowX: 'auto',
                      whiteSpace: 'pre-wrap', color: 'var(--clavex-text)' }}>
                      {signedCert.signed_key}
                    </pre>
                    <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 8 }}>
                      Principals: <strong>{signedCert.principals}</strong> •
                      Expires: <strong>{new Date(signedCert.expires_at).toLocaleString()}</strong>
                    </p>
                    <details style={{ marginTop: 8 }}>
                      <summary style={{ fontSize: 12, cursor: 'pointer', color: 'var(--clavex-neutral)' }}>
                        Usage instructions
                      </summary>
                      <pre style={{ fontSize: 11, fontFamily: 'monospace', margin: '8px 0 0',
                        whiteSpace: 'pre-wrap', color: 'var(--clavex-neutral)' }}>
                        {signedCert.instructions}
                      </pre>
                    </details>
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

// ── Page root ─────────────────────────────────────────────────────────────────

// ── BREAK GLASS tab (PCI DSS 8.2.6) ─────────────────────────────────────────

function BreakGlassTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    resource_type: 'server',
    resource_id: '',
    resource_name: '',
    justification: '',
    requested_duration: 60,
  })
  const [configForm, setConfigForm] = useState<BreakGlassConfig | null>(null)
  const [showConfig, setShowConfig] = useState(false)
  const [confirmPending, setConfirmPending] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['pam-break-glass-config', orgId],
    queryFn: () => api.get<{ config: BreakGlassConfig; uses_this_week: number }>(
      `/organizations/${orgId}/pam/break-glass/config`
    ).then(r => r.data),
  })
  const cfg = data?.config
  const usesThisWeek = data?.uses_this_week ?? 0
  const remaining = cfg ? (cfg.max_uses_per_week === 0 ? '∞' : String(Math.max(0, cfg.max_uses_per_week - usesThisWeek))) : '…'

  const { data: recentData } = useQuery({
    queryKey: ['pam-break-glass-requests', orgId],
    queryFn: () => api.get<{ data: (AccessRequest & { is_break_glass: boolean })[] }>(
      `/organizations/${orgId}/pam/access-requests?status=active&is_break_glass=true`
    ).then(r => r.data),
  })
  const recent = (recentData?.data ?? []).filter((r: AccessRequest & { is_break_glass: boolean }) => r.is_break_glass)

  const breakGlassMut = useMutation({
    mutationFn: (body: typeof form) =>
      api.post(`/organizations/${orgId}/pam/access-requests/break-glass`, body),
    onSuccess: () => {
      toast.success('Emergency access granted — all admins notified')
      qc.invalidateQueries({ queryKey: ['pam-break-glass-config', orgId] })
      qc.invalidateQueries({ queryKey: ['pam-break-glass-requests', orgId] })
      setForm({ resource_type: 'server', resource_id: '', resource_name: '', justification: '', requested_duration: 60 })
      setConfirmPending(false)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const saveConfigMut = useMutation({
    mutationFn: (body: BreakGlassConfig) =>
      api.put(`/organizations/${orgId}/pam/break-glass/config`, body),
    onSuccess: () => {
      toast.success('Break-glass policy saved')
      qc.invalidateQueries({ queryKey: ['pam-break-glass-config', orgId] })
      setShowConfig(false)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  if (isLoading) return <div style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Warning banner */}
      <div style={{ background: '#dc262610', border: '1px solid #dc262640', borderRadius: 12, padding: '16px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <AlertTriangle size={18} style={{ color: '#dc2626', flexShrink: 0 }} />
          <strong style={{ fontSize: 14, color: '#dc2626' }}>Emergency Access — PCI DSS 8.2.6</strong>
        </div>
        <p style={{ fontSize: 12, color: '#dc2626', margin: 0, lineHeight: 1.5 }}>
          Break-glass bypasses the normal JIT approval workflow. Every use is
          immediately audited, logged with <code>is_break_glass: true</code>, and
          triggers an instant webhook notification to all configured endpoints.
          Use only in genuine emergencies.
        </p>
      </div>

      {/* Usage counter */}
      {cfg && (
        <div style={{ ...card, display: 'flex', alignItems: 'center', gap: 20 }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 32, fontWeight: 900, color: usesThisWeek >= (cfg.max_uses_per_week || 99) ? '#dc2626' : 'var(--clavex-primary)' }}>
              {usesThisWeek}
            </div>
            <div style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>used this week</div>
          </div>
          <div style={{ color: 'var(--clavex-neutral)', fontSize: 18 }}>/</div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 32, fontWeight: 900, color: 'var(--clavex-text)' }}>
              {cfg.max_uses_per_week === 0 ? '∞' : cfg.max_uses_per_week}
            </div>
            <div style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>max per week</div>
          </div>
          <div style={{ flex: 1 }} />
          {!cfg.enabled && (
            <span style={{ padding: '4px 12px', borderRadius: 99, background: '#dc262612', color: '#dc2626', fontSize: 12, fontWeight: 700 }}>
              DISABLED
            </span>
          )}
          <button style={btn('ghost')} onClick={() => { setConfigForm(cfg); setShowConfig(true) }}>
            Configure policy
          </button>
        </div>
      )}

      {/* Emergency access form */}
      {cfg?.enabled && (
        <div style={card}>
          <h3 style={{ fontSize: 14, fontWeight: 700, margin: '0 0 16px' }}>
            <Zap size={14} style={{ marginRight: 6, color: '#d97706' }} />
            Request Emergency Access
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div>
              <label style={label}>Resource Name *</label>
              <input style={inp} value={form.resource_name}
                onChange={e => setForm(f => ({ ...f, resource_name: e.target.value }))}
                placeholder="e.g. prod-db-01" />
            </div>
            <div>
              <label style={label}>Resource Type</label>
              <select style={inp} value={form.resource_type}
                onChange={e => setForm(f => ({ ...f, resource_type: e.target.value }))}>
                <option value="server">Server</option>
                <option value="database">Database</option>
                <option value="kubernetes">Kubernetes</option>
                <option value="cloud_console">Cloud Console</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div>
              <label style={label}>Resource ID</label>
              <input style={inp} value={form.resource_id}
                onChange={e => setForm(f => ({ ...f, resource_id: e.target.value }))}
                placeholder="e.g. i-0abc123def456" />
            </div>
            <div>
              <label style={label}>Duration (minutes)</label>
              <input style={inp} type="number" min={1} max={480} value={form.requested_duration}
                onChange={e => setForm(f => ({ ...f, requested_duration: Number(e.target.value) }))} />
            </div>
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={label}>
              Justification {cfg.require_justification && '* (min 20 chars)'}
            </label>
            <textarea style={{ ...inp, minHeight: 80, resize: 'vertical' }}
              value={form.justification}
              onChange={e => setForm(f => ({ ...f, justification: e.target.value }))}
              placeholder="Describe the emergency that requires immediate privileged access…" />
            {cfg.require_justification && form.justification.trim().length < 20 && form.justification.length > 0 && (
              <div style={{ fontSize: 11, color: '#dc2626', marginTop: 4 }}>
                {20 - form.justification.trim().length} more characters required
              </div>
            )}
          </div>
          {!confirmPending ? (
            <button style={{ ...btn('danger'), gap: 8 }}
              disabled={!form.resource_name || (cfg.require_justification && form.justification.trim().length < 20)}
              onClick={() => setConfirmPending(true)}>
              <AlertTriangle size={14} />
              Request Emergency Access ({remaining} remaining this week)
            </button>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: 12,
              background: '#dc262608', border: '1px solid #dc262640', borderRadius: 8, padding: '12px 16px' }}>
              <AlertTriangle size={16} style={{ color: '#dc2626' }} />
              <span style={{ fontSize: 13, flex: 1 }}>
                <strong>Confirm emergency access to "{form.resource_name}".</strong>{' '}
                This action is permanent and will notify all administrators.
              </span>
              <button style={btn('ghost')} onClick={() => setConfirmPending(false)}>Cancel</button>
              <button style={btn('danger')} onClick={() => breakGlassMut.mutate(form)}
                disabled={breakGlassMut.isPending}>
                {breakGlassMut.isPending ? 'Granting…' : 'Confirm'}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Recent break-glass accesses */}
      {recent.length > 0 && (
        <div style={card}>
          <h3 style={{ fontSize: 14, fontWeight: 700, margin: '0 0 12px' }}>Active Emergency Accesses</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ color: 'var(--clavex-neutral)', textAlign: 'left' }}>
                <th style={{ padding: '4px 8px', fontWeight: 600 }}>Resource</th>
                <th style={{ padding: '4px 8px', fontWeight: 600 }}>Type</th>
                <th style={{ padding: '4px 8px', fontWeight: 600 }}>Justification</th>
                <th style={{ padding: '4px 8px', fontWeight: 600 }}>Expires</th>
              </tr>
            </thead>
            <tbody>
              {recent.map(r => (
                <tr key={r.id} style={{ borderTop: '0.5px solid var(--clavex-border)' }}>
                  <td style={{ padding: '8px' }}>{r.resource_name}</td>
                  <td style={{ padding: '8px' }}>{r.resource_type}</td>
                  <td style={{ padding: '8px', maxWidth: 240 }}>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>
                      {r.justification}
                    </span>
                  </td>
                  <td style={{ padding: '8px' }}>
                    {r.expires_at ? new Date(r.expires_at).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Config modal */}
      {showConfig && configForm && (
        <div style={{ position: 'fixed', inset: 0, background: '#0008', display: 'flex',
          alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ ...card, width: 460 }}>
            <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 16px' }}>Break-Glass Policy</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13 }}>
                <input type="checkbox" checked={configForm.enabled}
                  onChange={e => setConfigForm(f => f && ({ ...f, enabled: e.target.checked }))} />
                Break-glass access enabled
              </label>
              <div>
                <label style={label}>Max uses per week (0 = unlimited)</label>
                <input style={inp} type="number" min={0} value={configForm.max_uses_per_week}
                  onChange={e => setConfigForm(f => f && ({ ...f, max_uses_per_week: Number(e.target.value) }))} />
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13 }}>
                <input type="checkbox" checked={configForm.require_justification}
                  onChange={e => setConfigForm(f => f && ({ ...f, require_justification: e.target.checked }))} />
                Require justification (min 20 chars)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13 }}>
                <input type="checkbox" checked={configForm.notify_on_use}
                  onChange={e => setConfigForm(f => f && ({ ...f, notify_on_use: e.target.checked }))} />
                Notify via webhook on every use
              </label>
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 20 }}>
              <button style={btn('ghost')} onClick={() => setShowConfig(false)}>Cancel</button>
              <button style={btn()} disabled={saveConfigMut.isPending}
                onClick={() => saveConfigMut.mutate(configForm)}>
                {saveConfigMut.isPending ? 'Saving…' : 'Save Policy'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}


export default function PAMPage() {
  const orgId = useAuthStore(s => s.orgId)
  const [tab, setTab] = useState<string>('requests')

  if (!orgId) return null

  return (
    <div style={{ padding: '28px 32px', maxWidth: 1100 }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <KeyRound size={22} style={{ color: 'var(--clavex-primary)' }} />
          <h1 style={{ fontSize: 20, fontWeight: 800, margin: 0 }}>Privileged Access Management</h1>
        </div>
        <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', margin: 0 }}>
          JIT access with approval workflow · Encrypted credential vault · Privileged session recording · Vault SSH CA
        </p>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '0.5px solid var(--clavex-border)', marginBottom: 24 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '8px 18px',
              background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 600,
              color: tab === t.id ? 'var(--clavex-primary)' : 'var(--clavex-neutral)',
              borderBottom: tab === t.id ? '2px solid var(--clavex-primary)' : '2px solid transparent',
              marginBottom: -1 }}>
            <t.Icon size={14} />
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'requests'    && <AccessRequestsTab orgId={orgId} />}
      {tab === 'vault'       && <CredentialVaultTab orgId={orgId} />}
      {tab === 'sessions'    && <SessionsTab orgId={orgId} />}
      {tab === 'sshca'       && <SSHCATab orgId={orgId} />}
      {tab === 'break-glass' && <BreakGlassTab orgId={orgId} />}
    </div>
  )
}
