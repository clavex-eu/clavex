import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  Zap, Plus, Trash2, Globe, ChevronDown, ChevronUp,
  Pencil, X, Eye, EyeOff, ArrowRight,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface ActionTarget {
  id: string
  name: string
  url: string
  timeout_ms: number
  is_active: boolean
  created_at: string
}

interface ActionExecution {
  id: string
  name: string
  event_type: string
  mode: string
  is_active: boolean
  target_id: string
  target_name: string
  target_url: string
  created_at: string
}

// ── Event catalogue ───────────────────────────────────────────────────────────

const EVENT_GROUPS = [
  {
    label: 'Async',
    color: '#0369a1',
    bg: '#f0f9ff',
    events: [
      { value: 'user.created',  hint: 'Fire after a new user is created — use for external provisioning' },
      { value: 'user.updated',  hint: 'Fire after a user is updated — sync attributes to external systems' },
      { value: 'user.deleted',  hint: 'Fire after a user is deleted — use for deprovisioning' },
    ],
  },
  {
    label: 'Sync',
    color: '#6d28d9',
    bg: '#f5f3ff',
    events: [
      { value: 'user.pre_login', hint: 'Called before login — can deny access or inject extra claims' },
      { value: 'user.pre_token', hint: 'Called before token issuance — can inject or override claims' },
    ],
  },
  {
    label: 'Mutation',
    color: '#b45309',
    bg: '#fef3c7',
    events: [
      { value: 'user.pre_create',          hint: 'Called before user creation — can modify or deny the request' },
      { value: 'user.pre_update',          hint: 'Called before user update — can modify or deny the request' },
      { value: 'user.pre_password_change', hint: 'Called before a password change — can deny the request' },
    ],
  },
] as const

type EventGroup = typeof EVENT_GROUPS[number]

function getEventGroup(eventType: string): EventGroup {
  return EVENT_GROUPS.find(g => g.events.some(e => e.value === eventType)) ?? EVENT_GROUPS[0]
}

function getEventHint(eventType: string): string {
  for (const g of EVENT_GROUPS) {
    const e = g.events.find(e => e.value === eventType)
    if (e) return e.hint
  }
  return ''
}

function defaultMode(eventType: string) {
  return eventType.startsWith('user.pre_') ? 'mutation' : 'fire_and_forget'
}

const ASYNC_EVENTS = new Set(['user.created', 'user.updated', 'user.deleted'])

// ── Form shapes ───────────────────────────────────────────────────────────────

interface TargetFormData {
  name: string; url: string; timeout_ms: number; signing_secret: string; is_active: boolean
}
interface ExecFormData {
  name: string; target_id: string; event_type: string; mode: string; is_active: boolean
}

const emptyTarget = (): TargetFormData => ({ name: '', url: '', timeout_ms: 3000, signing_secret: '', is_active: true })
const emptyExec   = (): ExecFormData   => ({ name: '', target_id: '', event_type: 'user.created', mode: 'fire_and_forget', is_active: true })

// ── Shared styles ─────────────────────────────────────────────────────────────

const S: Record<string, React.CSSProperties> = {
  card:    { background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)', borderRadius: 12, padding: '20px 24px' },
  input:   { width: '100%', padding: '8px 12px', borderRadius: 8, border: '0.5px solid var(--clavex-border)', fontSize: 13, background: 'white', color: 'var(--clavex-text)', boxSizing: 'border-box', outline: 'none' },
  label:   { fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 },
  hint:    { fontSize: 11, color: 'var(--clavex-neutral)', margin: '3px 0 0' },
  btnPrimary: { display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 500, background: 'var(--clavex-primary)', color: 'white', border: 'none', cursor: 'pointer' },
  btnGhost:   { padding: '7px 14px', borderRadius: 8, fontSize: 13, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: 'pointer', color: 'var(--clavex-text)' },
  iconBtn:    { background: 'none', border: 'none', cursor: 'pointer', color: 'var(--clavex-neutral)', padding: 4, borderRadius: 6, display: 'flex', alignItems: 'center' },
  divider:    { borderTop: '0.5px solid var(--clavex-border)', marginTop: 16, paddingTop: 16 },
}

// ── Target form ───────────────────────────────────────────────────────────────

function TargetForm({ initial, onSave, onCancel, pending, isEdit }: {
  initial: TargetFormData; onSave: (f: TargetFormData) => void
  onCancel: () => void; pending: boolean; isEdit: boolean
}) {
  const [f, setF] = useState<TargetFormData>(initial)
  const [showSecret, setShowSecret] = useState(false)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div>
          <label style={S.label}>Name *</label>
          <input
            style={{ ...S.input, ...(isEdit ? { background: '#f8fafc', color: '#94a3b8' } : {}) }}
            value={f.name} readOnly={isEdit}
            onChange={e => setF(p => ({ ...p, name: e.target.value }))}
            placeholder="my-hr-system"
          />
          {isEdit && <p style={S.hint}>Name is immutable — it serves as the upsert key.</p>}
        </div>
        <div>
          <label style={S.label}>Timeout (ms)</label>
          <input style={S.input} type="number" min={100} max={30000} value={f.timeout_ms}
            onChange={e => setF(p => ({ ...p, timeout_ms: Number(e.target.value) || 3000 }))} />
          <p style={S.hint}>Max wait for a response. Default: 3000 ms.</p>
        </div>
        <div style={{ gridColumn: 'span 2' }}>
          <label style={S.label}>Endpoint URL *</label>
          <input style={S.input} value={f.url}
            onChange={e => setF(p => ({ ...p, url: e.target.value }))}
            placeholder="https://api.example.com/clavex-hook" />
        </div>
        <div style={{ gridColumn: 'span 2' }}>
          <label style={S.label}>
            Signing secret{' '}
            <span style={{ fontWeight: 400, color: 'var(--clavex-neutral)' }}>
              (optional — sent as <code>X-Clavex-Signature</code> HMAC-SHA256 header)
            </span>
          </label>
          <div style={{ position: 'relative' }}>
            <input
              style={{ ...S.input, paddingRight: 38 }}
              type={showSecret ? 'text' : 'password'}
              value={f.signing_secret}
              onChange={e => setF(p => ({ ...p, signing_secret: e.target.value }))}
              placeholder={isEdit ? 'Leave blank to clear the existing secret' : 'my-webhook-secret'}
            />
            <button type="button" onClick={() => setShowSecret(s => !s)}
              style={{ ...S.iconBtn, position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)' }}>
              {showSecret ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
          {isEdit && (
            <p style={{ ...S.hint, color: '#92400e', background: '#fef9c3', padding: '4px 8px', borderRadius: 6, marginTop: 6 }}>
              Existing secret is not shown. Enter a new value to replace it, or leave blank to clear it.
            </p>
          )}
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
          <input type="checkbox" checked={f.is_active} onChange={e => setF(p => ({ ...p, is_active: e.target.checked }))} />
          Active
        </label>
        <div style={{ display: 'flex', gap: 8 }}>
          <button style={S.btnGhost} onClick={onCancel}>Cancel</button>
          <button style={{ ...S.btnPrimary, opacity: (!f.name || !f.url || pending) ? 0.6 : 1 }}
            onClick={() => onSave(f)} disabled={!f.name || !f.url || pending}>
            {pending ? 'Saving…' : isEdit ? 'Save changes' : 'Create target'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Execution form ────────────────────────────────────────────────────────────

function ExecutionForm({ initial, targets, onSave, onCancel, pending, isEdit }: {
  initial: ExecFormData; targets: ActionTarget[]
  onSave: (f: ExecFormData) => void; onCancel: () => void; pending: boolean; isEdit: boolean
}) {
  const [f, setF] = useState<ExecFormData>(initial)
  const asyncEvent = ASYNC_EVENTS.has(f.event_type)

  const handleEventChange = (val: string) => setF(p => ({ ...p, event_type: val, mode: defaultMode(val) }))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Name + target */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div>
          <label style={S.label}>Name *</label>
          <input style={S.input} value={f.name}
            onChange={e => setF(p => ({ ...p, name: e.target.value }))}
            placeholder="HR approval check" />
        </div>
        <div>
          <label style={S.label}>Target *</label>
          {targets.length === 0 ? (
            <div style={{ fontSize: 12, color: '#dc2626', padding: '8px 12px', background: '#fef2f2', borderRadius: 8 }}>
              No targets yet — create a target first.
            </div>
          ) : (
            <select style={{ ...S.input, appearance: 'none' as const }} value={f.target_id}
              onChange={e => setF(p => ({ ...p, target_id: e.target.value }))}>
              <option value="">Select target…</option>
              {targets.filter(t => t.is_active).map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          )}
        </div>
      </div>

      {/* Event type radio selector */}
      <div>
        <label style={S.label}>Event trigger *</label>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {EVENT_GROUPS.map(g => (
            <div key={g.label}>
              <div style={{ fontSize: 10, fontWeight: 700, color: g.color, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 5 }}>
                {g.label}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {g.events.map(ev => {
                  const sel = f.event_type === ev.value
                  return (
                    <label key={ev.value} style={{
                      display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', borderRadius: 8, cursor: 'pointer',
                      border: `0.5px solid ${sel ? g.color : 'var(--clavex-border)'}`,
                      background: sel ? g.bg : 'white',
                    }}>
                      <input type="radio" name="event_type" value={ev.value} checked={sel}
                        onChange={() => handleEventChange(ev.value)}
                        style={{ marginTop: 2, flexShrink: 0, accentColor: g.color }} />
                      <div>
                        <code style={{ fontSize: 12, fontWeight: 600, color: sel ? g.color : 'var(--clavex-text)' }}>{ev.value}</code>
                        <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', margin: '2px 0 0' }}>{ev.hint}</p>
                      </div>
                    </label>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Mode toggle */}
      <div>
        <label style={S.label}>Execution mode</label>
        <div style={{ display: 'flex', gap: 8 }}>
          {[
            { value: 'fire_and_forget', label: 'Fire & forget', hint: 'POST asynchronously — response is ignored', disabled: false },
            { value: 'mutation', label: 'Mutation', hint: 'POST synchronously — response can modify or deny the request', disabled: asyncEvent },
          ].map(m => {
            const active = f.mode === m.value && !m.disabled
            return (
              <button key={m.value} type="button" disabled={m.disabled}
                onClick={() => !m.disabled && setF(p => ({ ...p, mode: m.value }))}
                style={{
                  flex: 1, padding: '10px 14px', borderRadius: 8, fontSize: 13, textAlign: 'left',
                  cursor: m.disabled ? 'not-allowed' : 'pointer',
                  border: `0.5px solid ${active ? 'var(--clavex-primary)' : 'var(--clavex-border)'}`,
                  background: active ? '#eff6ff' : m.disabled ? '#f8fafc' : 'white',
                  opacity: m.disabled ? 0.5 : 1, color: 'var(--clavex-text)',
                }}>
                <div style={{ fontWeight: 600 }}>{m.label}</div>
                <div style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 3 }}>{m.hint}</div>
              </button>
            )
          })}
        </div>
        {f.mode === 'mutation' && !asyncEvent && (
          <p style={{ fontSize: 11, color: '#92400e', margin: '8px 0 0', background: '#fef3c7', padding: '6px 10px', borderRadius: 6 }}>
            Your endpoint must respond with{' '}
            <code>{'{ "action": "continue" | "deny" | "mutate", ... }'}</code>
          </p>
        )}
      </div>

      {/* Footer */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 8, borderTop: '0.5px solid var(--clavex-border)' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
          <input type="checkbox" checked={f.is_active} onChange={e => setF(p => ({ ...p, is_active: e.target.checked }))} />
          Active
        </label>
        <div style={{ display: 'flex', gap: 8 }}>
          <button style={S.btnGhost} onClick={onCancel}>Cancel</button>
          <button style={{ ...S.btnPrimary, opacity: (!f.name || !f.target_id || pending) ? 0.6 : 1 }}
            onClick={() => onSave(f)} disabled={!f.name || !f.target_id || pending}>
            {pending ? 'Saving…' : isEdit ? 'Save changes' : 'Create execution'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Badge ─────────────────────────────────────────────────────────────────────

function Badge({ children, bg, color }: { children: React.ReactNode; bg: string; color: string }) {
  return (
    <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 12, flexShrink: 0, background: bg, color }}>
      {children}
    </span>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ActionsV2Page() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()

  const [tab, setTab] = useState<'targets' | 'executions'>('targets')
  // 'new' = create form; a UUID = that item's inline edit form; null = closed
  const [targetFormId, setTargetFormId] = useState<string | null>(null)
  const [execFormId,   setExecFormId]   = useState<string | null>(null)
  const [expandedExec, setExpandedExec] = useState<string | null>(null)

  // ── Queries ────────────────────────────────────────────────────────────────

  const { data: targets = [], isLoading: tLoading } = useQuery<ActionTarget[]>({
    queryKey: ['action-targets', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/actions/targets`).then(r => Array.isArray(r.data) ? r.data : []),
    enabled: !!orgId,
  })

  const { data: executions = [], isLoading: eLoading } = useQuery<ActionExecution[]>({
    queryKey: ['action-executions', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/actions/executions`).then(r => Array.isArray(r.data) ? r.data : []),
    enabled: !!orgId,
  })

  // ── Target mutations ───────────────────────────────────────────────────────

  const upsertTarget = useMutation({
    mutationFn: (f: TargetFormData) =>
      api.put(`/organizations/${orgId}/actions/targets/${f.name}`, {
        url: f.url,
        timeout_ms: f.timeout_ms,
        ...(f.signing_secret ? { signing_secret: f.signing_secret } : {}),
        is_active: f.is_active,
      }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['action-targets', orgId] }); toast.success('Target saved'); setTargetFormId(null) },
    onError: () => toast.error('Failed to save target'),
  })

  const deleteTarget = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/actions/targets/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['action-targets', orgId] }); toast.success('Target deleted') },
    onError: () => toast.error('Failed to delete target'),
  })

  // ── Execution mutations ────────────────────────────────────────────────────

  const createExec = useMutation({
    mutationFn: (f: ExecFormData) => api.post(`/organizations/${orgId}/actions/executions`, f),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['action-executions', orgId] }); toast.success('Execution created'); setExecFormId(null) },
    onError: () => toast.error('Failed to create execution'),
  })

  const updateExec = useMutation({
    mutationFn: ({ id, body }: { id: string; body: ExecFormData }) =>
      api.put(`/organizations/${orgId}/actions/executions/${id}`, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['action-executions', orgId] }); toast.success('Execution saved'); setExecFormId(null) },
    onError: () => toast.error('Failed to save execution'),
  })

  const deleteExec = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/actions/executions/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['action-executions', orgId] }); toast.success('Execution deleted') },
    onError: () => toast.error('Failed to delete execution'),
  })

  const execToForm = (ex: ActionExecution): ExecFormData => ({
    name: ex.name, target_id: ex.target_id, event_type: ex.event_type, mode: ex.mode, is_active: ex.is_active,
  })

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 28 }}>
        <Zap size={22} color="var(--clavex-primary)" />
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Actions V2</h1>
          <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
            HTTP hooks on auth and user events — async provisioning, sync enrichment, mutation control
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', marginBottom: 20, borderBottom: '0.5px solid var(--clavex-border)' }}>
        {([
          { id: 'targets',    label: `Targets (${targets.length})` },
          { id: 'executions', label: `Executions (${executions.length})` },
        ] as const).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: '8px 20px', fontSize: 13, fontWeight: tab === t.id ? 600 : 400,
            border: 'none', background: 'none', cursor: 'pointer',
            color: tab === t.id ? 'var(--clavex-primary)' : 'var(--clavex-neutral)',
            borderBottom: tab === t.id ? '2px solid var(--clavex-primary)' : '2px solid transparent',
            marginBottom: -1,
          }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ════ Targets ════════════════════════════════════════════════════════ */}
      {tab === 'targets' && (
        <>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 14 }}>
            <button style={{ ...S.btnPrimary, opacity: targetFormId === 'new' ? 0.5 : 1 }}
              onClick={() => setTargetFormId('new')} disabled={targetFormId === 'new'}>
              <Plus size={14} /> New target
            </button>
          </div>

          {targetFormId === 'new' && (
            <div style={{ ...S.card, marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
                <h2 style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>New target</h2>
                <button style={S.iconBtn} onClick={() => setTargetFormId(null)}><X size={14} /></button>
              </div>
              <TargetForm initial={emptyTarget()} onSave={f => upsertTarget.mutate(f)}
                onCancel={() => setTargetFormId(null)} pending={upsertTarget.isPending} isEdit={false} />
            </div>
          )}

          {tLoading ? (
            <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>
          ) : targets.length === 0 && targetFormId !== 'new' ? (
            <div style={{ ...S.card, textAlign: 'center', padding: '48px 32px', color: 'var(--clavex-neutral)' }}>
              <Globe size={36} style={{ opacity: 0.3, marginBottom: 12 }} />
              <p style={{ fontSize: 14, margin: '0 0 6px', fontWeight: 500 }}>No targets configured</p>
              <p style={{ fontSize: 12, margin: 0, maxWidth: 320, marginInline: 'auto' }}>
                A target is an HTTPS endpoint that receives action payloads. Create one before adding executions.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {targets.map(t => (
                <div key={t.id} style={S.card}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <Globe size={16} color="var(--clavex-primary)" style={{ flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontWeight: 600, fontSize: 14 }}>{t.name}</div>
                      <code style={{ fontSize: 11, color: 'var(--clavex-neutral)', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {t.url}
                      </code>
                    </div>
                    <span style={{ fontSize: 11, color: 'var(--clavex-neutral)', flexShrink: 0 }}>{t.timeout_ms} ms</span>
                    <Badge bg={t.is_active ? '#dcfce7' : '#f1f5f9'} color={t.is_active ? '#15803d' : '#64748b'}>
                      {t.is_active ? 'active' : 'disabled'}
                    </Badge>
                    <button style={{ ...S.iconBtn, color: targetFormId === t.id ? 'var(--clavex-primary)' : undefined }}
                      onClick={() => setTargetFormId(targetFormId === t.id ? null : t.id)} title="Edit target">
                      <Pencil size={13} />
                    </button>
                    <button style={{ ...S.iconBtn, color: '#ef4444' }}
                      onClick={() => { if (confirm(`Delete target "${t.name}"?`)) deleteTarget.mutate(t.id) }} title="Delete target">
                      <Trash2 size={13} />
                    </button>
                  </div>
                  {targetFormId === t.id && (
                    <div style={S.divider}>
                      <TargetForm
                        initial={{ name: t.name, url: t.url, timeout_ms: t.timeout_ms, signing_secret: '', is_active: t.is_active }}
                        onSave={f => upsertTarget.mutate(f)} onCancel={() => setTargetFormId(null)}
                        pending={upsertTarget.isPending} isEdit />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* ════ Executions ═════════════════════════════════════════════════════ */}
      {tab === 'executions' && (
        <>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 14 }}>
            <button style={{ ...S.btnPrimary, opacity: execFormId === 'new' ? 0.5 : 1 }}
              onClick={() => setExecFormId('new')} disabled={execFormId === 'new'}>
              <Plus size={14} /> New execution
            </button>
          </div>

          {execFormId === 'new' && (
            <div style={{ ...S.card, marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
                <h2 style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>New execution</h2>
                <button style={S.iconBtn} onClick={() => setExecFormId(null)}><X size={14} /></button>
              </div>
              <ExecutionForm initial={emptyExec()} targets={targets}
                onSave={f => createExec.mutate(f)} onCancel={() => setExecFormId(null)}
                pending={createExec.isPending} isEdit={false} />
            </div>
          )}

          {eLoading ? (
            <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>
          ) : executions.length === 0 && execFormId !== 'new' ? (
            <div style={{ ...S.card, textAlign: 'center', padding: '48px 32px', color: 'var(--clavex-neutral)' }}>
              <Zap size={36} style={{ opacity: 0.3, marginBottom: 12 }} />
              <p style={{ fontSize: 14, margin: '0 0 6px', fontWeight: 500 }}>No executions configured</p>
              <p style={{ fontSize: 12, margin: 0, maxWidth: 340, marginInline: 'auto' }}>
                An execution binds an event trigger to a target. Create a target first, then add executions here.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {executions.map(ex => {
                const g = getEventGroup(ex.event_type)
                const isExpanded = expandedExec === ex.id
                const isEditing  = execFormId === ex.id
                return (
                  <div key={ex.id} style={S.card}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <Zap size={16} color="var(--clavex-primary)" style={{ flexShrink: 0 }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontWeight: 600, fontSize: 14 }}>{ex.name}</div>
                        <div style={{ fontSize: 12, color: 'var(--clavex-neutral)', display: 'flex', alignItems: 'center', gap: 5, marginTop: 2 }}>
                          <code style={{ color: g.color, fontSize: 11 }}>{ex.event_type}</code>
                          <ArrowRight size={10} style={{ opacity: 0.4, flexShrink: 0 }} />
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ex.target_name}</span>
                        </div>
                      </div>
                      <Badge bg={g.bg} color={g.color}>{g.label.toLowerCase()}</Badge>
                      <Badge bg={ex.mode === 'mutation' ? '#fef3c7' : '#f0f9ff'} color={ex.mode === 'mutation' ? '#92400e' : '#0369a1'}>
                        {ex.mode === 'mutation' ? 'mutation' : 'fire & forget'}
                      </Badge>
                      <Badge bg={ex.is_active ? '#dcfce7' : '#f1f5f9'} color={ex.is_active ? '#15803d' : '#64748b'}>
                        {ex.is_active ? 'active' : 'off'}
                      </Badge>
                      <button style={{ ...S.iconBtn, color: isEditing ? 'var(--clavex-primary)' : undefined }}
                        onClick={() => { setExecFormId(isEditing ? null : ex.id); if (!isEditing) setExpandedExec(null) }}
                        title="Edit execution">
                        <Pencil size={13} />
                      </button>
                      <button style={{ ...S.iconBtn, color: '#ef4444' }}
                        onClick={() => { if (confirm(`Delete "${ex.name}"?`)) deleteExec.mutate(ex.id) }} title="Delete execution">
                        <Trash2 size={13} />
                      </button>
                      <button style={S.iconBtn}
                        onClick={() => { setExpandedExec(isExpanded ? null : ex.id); if (!isExpanded) setExecFormId(null) }}>
                        {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                    </div>

                    {isExpanded && !isEditing && (
                      <div style={{ ...S.divider, fontSize: 12, color: 'var(--clavex-neutral)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                        <div><strong>Target:</strong> {ex.target_name}{ex.target_url && <> — <code style={{ fontSize: 11 }}>{ex.target_url}</code></>}</div>
                        <div><strong>Event:</strong> <code style={{ color: g.color }}>{ex.event_type}</code></div>
                        <div><strong>Mode:</strong> {ex.mode}</div>
                        {getEventHint(ex.event_type) && <div style={{ fontStyle: 'italic' }}>{getEventHint(ex.event_type)}</div>}
                        <div><strong>Created:</strong> {new Date(ex.created_at).toLocaleString()}</div>
                      </div>
                    )}

                    {isEditing && (
                      <div style={S.divider}>
                        <ExecutionForm initial={execToForm(ex)} targets={targets}
                          onSave={f => updateExec.mutate({ id: ex.id, body: f })}
                          onCancel={() => setExecFormId(null)} pending={updateExec.isPending} isEdit />
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </>
      )}
    </div>
  )
}
