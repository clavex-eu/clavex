import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  Plus, Trash2, GripVertical, ChevronDown, ChevronRight,
  ShieldOff, Shield, KeyRound, Globe, Tag,
  TriangleAlert, CheckCircle2, Zap, ArrowDown, Play, Pause,
  FlaskConical, Eye, EyeOff, RefreshCw, X, Sparkles, ScanFace,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────

interface LoginFlow {
  id: string
  name: string
  description?: string
  is_default: boolean
  is_active: boolean
  steps?: LoginFlowStep[]
}

interface LoginFlowStep {
  id?: string
  step_type: string
  position: number
  config: Record<string, unknown>
  is_active: boolean
}

// ─── Step catalogue ───────────────────────────────────────────────────

interface StepDef {
  type: string
  label: string
  description: string
  icon: React.ReactNode
  accent: string
  bg: string
  defaultConfig: Record<string, unknown>
}

const STEP_DEFS: StepDef[] = [
  {
    type: 'check_breach',
    label: 'Check Breach',
    description: 'Deny or force MFA if credentials were found in a data breach (HIBP)',
    icon: <TriangleAlert size={15} />,
    accent: '#dc2626', bg: '#fff1f2',
    defaultConfig: { action: 'deny', message: '' },
  },
  {
    type: 'require_mfa',
    label: 'Require MFA',
    description: 'Force step-up authentication; deny if no MFA enrolled',
    icon: <Shield size={15} />,
    accent: '#2563eb', bg: '#eff6ff',
    defaultConfig: {},
  },
  {
    type: 'block_if_no_mfa',
    label: 'Block if No MFA',
    description: 'Deny login when the user has no MFA method enrolled',
    icon: <ShieldOff size={15} />,
    accent: '#7c3aed', bg: '#f5f3ff',
    defaultConfig: { message: '' },
  },
  {
    type: 'require_email_verified',
    label: 'Email Verified',
    description: 'Deny login if the user email is not verified',
    icon: <CheckCircle2 size={15} />,
    accent: '#059669', bg: '#ecfdf5',
    defaultConfig: {},
  },
  {
    type: 'check_ip_risk',
    label: 'Check IP Risk',
    description: 'Deny or require MFA based on threat intelligence score',
    icon: <Globe size={15} />,
    accent: '#ea580c', bg: '#fff7ed',
    defaultConfig: { threshold: 70, action: 'deny' },
  },
  {
    type: 'check_attribute',
    label: 'Check Attribute',
    description: 'Allow or deny based on user profile field value',
    icon: <FlaskConical size={15} />,
    accent: '#7c3aed', bg: '#faf5ff',
    defaultConfig: { field: '', op: 'eq', value: '', action: 'deny' },
  },
  {
    type: 'enrich_claims',
    label: 'Enrich Claims',
    description: 'Call an external API and map its response into the token',
    icon: <Zap size={15} />,
    accent: '#0891b2', bg: '#ecfeff',
    defaultConfig: { url: '', method: 'POST', headers: {}, body_template: '', claim_mappings: [], timeout_ms: 3000, on_error: 'continue' },
  },
  {
    type: 'set_claim',
    label: 'Set Claim',
    description: 'Inject a static or profile-sourced claim into the token',
    icon: <Tag size={15} />,
    accent: '#16a34a', bg: '#f0fdf4',
    defaultConfig: { claim: '', value: '' },
  },
  {
    type: 'webhook',
    label: 'Webhook (async)',
    description: 'Fire-and-forget POST to an external URL after login',
    icon: <ArrowDown size={15} />,
    accent: '#db2777', bg: '#fdf2f8',
    defaultConfig: { url: '', method: 'POST', secret: '' },
  },
  {
    type: 'check_verified',
    label: 'Check Verified (IDA)',
    description: 'Deny if IDA assurance level is below the required minimum (eIDAS low/substantial/high)',
    icon: <KeyRound size={15} />,
    accent: '#0d9488', bg: '#f0fdfa',
    defaultConfig: { min_level: 'substantial', step_up_url: '', message: '' },
  },
  {
    type: 'ai_decision',
    label: 'AI Decision',
    description: 'Call Claude to evaluate the login context (user, IP, risk score, IDA level) and allow / deny / step-up with NIS2-ready audit reasoning',
    icon: <Sparkles size={15} />,
    accent: '#7c3aed', bg: '#faf5ff',
    defaultConfig: { prompt: '', timeout_action: 'allow' },
  },
  {
    type: 'oid4vp_challenge',
    label: 'OID4VP Credential Challenge',
    description: 'Require the user to present a verifiable credential (DCQL / Presentation Exchange) via their IT-Wallet or mdoc wallet before login completes',
    icon: <ScanFace size={15} />,
    accent: '#0369a1', bg: '#f0f9ff',
    defaultConfig: { message: 'Please present your credential to continue.', dcql_query: '', presentation_definition: '' },
  },
]

const stepDef = (t: string) => STEP_DEFS.find((d) => d.type === t)

// ─── Shared style tokens ──────────────────────────────────────────────

const inp: React.CSSProperties = {
  background: 'white', color: 'var(--clavex-ink)',
  border: '0.5px solid var(--clavex-border)', borderRadius: 6,
  padding: '6px 10px', fontSize: 12, outline: 'none',
  width: '100%', boxSizing: 'border-box',
}
const sel: React.CSSProperties = { ...inp, cursor: 'pointer' }
const lbl: React.CSSProperties = {
  display: 'block', fontSize: 10, fontWeight: 700,
  color: '#64748b', marginBottom: 4,
  textTransform: 'uppercase', letterSpacing: '0.06em',
}

// ─── API base ─────────────────────────────────────────────────────────

const flowBase = (orgId: string) => `/organizations/${orgId}/login-flows`

// ─── Main component ───────────────────────────────────────────────────

export default function LoginFlowsPage({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [selectedFlow, setSelectedFlow] = useState<LoginFlow | null>(null)
  const [steps, setSteps] = useState<LoginFlowStep[]>([])
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [dirty, setDirty] = useState(false)
  const dragIdx = useRef<number | null>(null)

  // ── Queries ───────────────────────────────────────────────────────

  const { data: flows = [], isLoading } = useQuery<LoginFlow[]>({
    queryKey: ['login-flows', orgId],
    queryFn: () => api.get(flowBase(orgId)).then((r) => r.data),
  })

  // ── Mutations ─────────────────────────────────────────────────────

  const createFlow = useMutation({
    mutationFn: (d: { name: string; description?: string; is_default: boolean }) =>
      api.post(flowBase(orgId), d).then((r) => r.data),
    onSuccess: (f: LoginFlow) => {
      qc.invalidateQueries({ queryKey: ['login-flows', orgId] })
      toast.success('Flow created')
      setShowCreate(false)
      openFlow(f)
    },
  })

  const deleteFlow = useMutation({
    mutationFn: (id: string) => api.delete(`${flowBase(orgId)}/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['login-flows', orgId] })
      toast.success('Flow deleted')
      setSelectedFlow(null)
      setSteps([])
    },
  })

  const toggleActive = useMutation({
    mutationFn: (f: LoginFlow) =>
      api.put(`${flowBase(orgId)}/${f.id}`, { ...f, is_active: !f.is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['login-flows', orgId] }),
  })

  const saveSteps = useMutation({
    mutationFn: ({ flowId, s }: { flowId: string; s: LoginFlowStep[] }) =>
      api.put(`${flowBase(orgId)}/${flowId}/steps`, s),
    onSuccess: () => {
      toast.success('Flow saved')
      setDirty(false)
      qc.invalidateQueries({ queryKey: ['login-flows', orgId] })
    },
    onError: () => toast.error('Failed to save flow'),
  })

  // ── Flow helpers ──────────────────────────────────────────────────

  function openFlow(f: LoginFlow) {
    setSelectedFlow(f)
    setSteps((f.steps ?? []).map((s, i) => ({ ...s, position: i })))
    setSelectedIdx(null)
    setDirty(false)
  }

  // ── Drag & drop: reorder ──────────────────────────────────────────

  function onDragStart(i: number) { dragIdx.current = i }
  function onDragOver(e: React.DragEvent, i: number) {
    e.preventDefault()
    if (dragIdx.current === null || dragIdx.current === i) return
    const arr = [...steps]
    const [m] = arr.splice(dragIdx.current, 1)
    arr.splice(i, 0, m)
    dragIdx.current = i
    setSteps(arr.map((s, j) => ({ ...s, position: j })))
    setDirty(true)
  }
  function onDragEnd() { dragIdx.current = null }

  // ── Drop from palette ─────────────────────────────────────────────

  function onDropPalette(e: React.DragEvent) {
    e.preventDefault()
    const type = e.dataTransfer.getData('step_type')
    if (!type) return
    const def = stepDef(type)
    const newIdx = steps.length
    setSteps((prev) => [
      ...prev,
      { step_type: type, position: newIdx, config: { ...(def?.defaultConfig ?? {}) }, is_active: true },
    ])
    setSelectedIdx(newIdx)
    setDirty(true)
  }

  // ── Step ops ──────────────────────────────────────────────────────

  function removeStep(i: number) {
    setSteps((prev) => prev.filter((_, j) => j !== i).map((s, j) => ({ ...s, position: j })))
    if (selectedIdx === i) setSelectedIdx(null)
    else if (selectedIdx !== null && selectedIdx > i) setSelectedIdx(selectedIdx - 1)
    setDirty(true)
  }

  function setCfg(i: number, cfg: Record<string, unknown>) {
    setSteps((prev) => prev.map((s, j) => (j === i ? { ...s, config: cfg } : s)))
    setDirty(true)
  }

  function toggleStep(i: number) {
    setSteps((prev) => prev.map((s, j) => (j === i ? { ...s, is_active: !s.is_active } : s)))
    setDirty(true)
  }

  // ── Render ────────────────────────────────────────────────────────

  return (
    <div style={{ display: 'flex', height: '100%', minHeight: 0, background: '#f8fafc' }}>

      {/* ── Sidebar ── */}
      <aside style={{
        width: 236, flexShrink: 0, display: 'flex', flexDirection: 'column',
        background: 'white', borderRight: '0.5px solid var(--clavex-border)',
      }}>
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '11px 13px', borderBottom: '0.5px solid var(--clavex-border)',
        }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--clavex-ink)' }}>Login Flows</span>
          <button onClick={() => setShowCreate(true)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--clavex-accent)', display: 'flex', padding: 2 }}>
            <Plus size={15} />
          </button>
        </div>

        {/* Flow list */}
        <ul style={{ flex: 1, overflowY: 'auto', listStyle: 'none', padding: 0, margin: 0 }}>
          {isLoading && (
            <li style={{ padding: '16px', textAlign: 'center', color: '#94a3b8' }}>
              <RefreshCw size={14} style={{ animation: 'spin 1s linear infinite', margin: '0 auto' }} />
            </li>
          )}
          {flows.map((f) => (
            <li key={f.id} onClick={() => openFlow(f)} style={{
              padding: '9px 13px', cursor: 'pointer',
              borderBottom: '0.5px solid #f1f5f9',
              borderLeft: selectedFlow?.id === f.id ? '3px solid var(--clavex-accent)' : '3px solid transparent',
              background: selectedFlow?.id === f.id ? '#f0fdf4' : 'white',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ minWidth: 0 }}>
                  <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)', margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.name}
                  </p>
                  <div style={{ display: 'flex', gap: 4, marginTop: 2 }}>
                    {f.is_default && <Badge color="#1d4ed8" bg="#dbeafe">DEFAULT</Badge>}
                    <Badge color={f.is_active ? '#16a34a' : '#64748b'} bg={f.is_active ? '#dcfce7' : '#f1f5f9'}>
                      {f.is_active ? 'ACTIVE' : 'PAUSED'}
                    </Badge>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 1, marginLeft: 4, flexShrink: 0 }} onClick={(e) => e.stopPropagation()}>
                  <IBtn title={f.is_active ? 'Pause' : 'Activate'} color={f.is_active ? '#16a34a' : '#94a3b8'} onClick={() => toggleActive.mutate(f)}>
                    {f.is_active ? <Pause size={11} /> : <Play size={11} />}
                  </IBtn>
                  <IBtn title="Delete" color="#94a3b8" onClick={() => { if (confirm(`Delete "${f.name}"?`)) deleteFlow.mutate(f.id) }}>
                    <Trash2 size={11} />
                  </IBtn>
                </div>
              </div>
            </li>
          ))}
          {!isLoading && flows.length === 0 && (
            <li style={{ padding: '20px 13px', textAlign: 'center', fontSize: 12, color: '#94a3b8' }}>
              No flows yet.{' '}
              <button onClick={() => setShowCreate(true)} style={{ color: 'var(--clavex-accent)', background: 'none', border: 'none', cursor: 'pointer', fontSize: 12 }}>
                Create one →
              </button>
            </li>
          )}
        </ul>

        {/* Block palette */}
        <div style={{ borderTop: '0.5px solid var(--clavex-border)', flexShrink: 0 }}>
          <div style={{ padding: '7px 13px 3px', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: '#94a3b8' }}>
            Block palette · drag to canvas
          </div>
          <div style={{ padding: '0 8px 10px', display: 'flex', flexDirection: 'column', gap: 3 }}>
            {STEP_DEFS.map((d) => (
              <div key={d.type} draggable onDragStart={(e) => e.dataTransfer.setData('step_type', d.type)}
                title={d.description}
                style={{
                  display: 'flex', alignItems: 'center', gap: 7,
                  padding: '5px 8px',
                  background: d.bg, border: `0.5px solid ${d.accent}25`,
                  borderLeft: `3px solid ${d.accent}`, borderRadius: 6,
                  cursor: 'grab', userSelect: 'none', fontSize: 11,
                  color: 'var(--clavex-ink)',
                }}>
                <span style={{ color: d.accent, flexShrink: 0, lineHeight: 1 }}>{d.icon}</span>
                <span style={{ fontWeight: 500 }}>{d.label}</span>
              </div>
            ))}
          </div>
        </div>
      </aside>

      {/* ── Canvas ── */}
      {selectedFlow ? (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          {/* Toolbar */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '11px 20px', background: 'white', borderBottom: '0.5px solid var(--clavex-border)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div>
                <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--clavex-ink)' }}>{selectedFlow.name}</h2>
                {selectedFlow.description && <p style={{ margin: 0, fontSize: 11, color: '#64748b' }}>{selectedFlow.description}</p>}
              </div>
              <Badge color={selectedFlow.is_active ? '#16a34a' : '#64748b'} bg={selectedFlow.is_active ? '#dcfce7' : '#f1f5f9'}>
                {selectedFlow.is_active ? 'ACTIVE' : 'PAUSED'}
              </Badge>
              {dirty && <span style={{ fontSize: 11, color: '#f59e0b', fontWeight: 600 }}>● Unsaved</span>}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              {dirty && (
                <button onClick={() => openFlow(selectedFlow)} style={{
                  background: 'none', border: '0.5px solid var(--clavex-border)', borderRadius: 7,
                  padding: '5px 12px', fontSize: 12, cursor: 'pointer', color: '#64748b',
                }}>Discard</button>
              )}
              <button disabled={!dirty || saveSteps.isPending}
                onClick={() => saveSteps.mutate({ flowId: selectedFlow.id, s: steps })}
                style={{
                  background: dirty ? 'var(--clavex-accent)' : '#e2e8f0',
                  color: dirty ? 'white' : '#94a3b8',
                  border: 'none', borderRadius: 7, padding: '5px 16px',
                  fontSize: 12, fontWeight: 600, cursor: dirty ? 'pointer' : 'default',
                  display: 'flex', alignItems: 'center', gap: 6,
                }}>
                {saveSteps.isPending && <RefreshCw size={11} style={{ animation: 'spin 1s linear infinite' }} />}
                Save flow
              </button>
            </div>
          </div>

          {/* Drop zone */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '24px 20px' }}
            onDragOver={(e) => e.preventDefault()} onDrop={onDropPalette}>

            {steps.length === 0 && (
              <div style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                minHeight: 200, border: '2px dashed #cbd5e1', borderRadius: 12,
                color: '#94a3b8', textAlign: 'center', padding: 40,
              }}>
                <KeyRound size={30} style={{ marginBottom: 12, opacity: 0.3 }} />
                <p style={{ margin: 0, fontSize: 14, fontWeight: 500 }}>Drag blocks from the palette to build your flow</p>
                <p style={{ margin: '4px 0 0', fontSize: 12 }}>Steps run in order for every login</p>
              </div>
            )}

            <div style={{ maxWidth: 560, margin: '0 auto' }}>
              {steps.length > 0 && <TriggerBadge />}

              {steps.map((step, i) => {
                const def = stepDef(step.step_type)
                const sel2 = selectedIdx === i
                return (
                  <div key={i}>
                    <div
                      draggable
                      onDragStart={() => onDragStart(i)}
                      onDragOver={(e) => onDragOver(e, i)}
                      onDragEnd={onDragEnd}
                      onClick={() => setSelectedIdx(sel2 ? null : i)}
                      style={{
                        background: 'white',
                        border: `0.5px solid ${sel2 ? (def?.accent ?? '#94a3b8') : '#e2e8f0'}`,
                        borderLeft: `4px solid ${def?.accent ?? '#94a3b8'}`,
                        borderRadius: 10, padding: '11px 13px',
                        cursor: 'pointer',
                        opacity: step.is_active ? 1 : 0.42,
                        boxShadow: sel2 ? `0 0 0 3px ${def?.accent ?? '#94a3b8'}20` : '0 1px 3px rgba(0,0,0,0.04)',
                        transition: 'all 0.12s', userSelect: 'none',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                        <GripVertical size={13} style={{ color: '#cbd5e1', flexShrink: 0, cursor: 'grab' }} />
                        <div style={{
                          width: 28, height: 28, borderRadius: 7, background: def?.bg ?? '#f8fafc',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          color: def?.accent ?? '#64748b', flexShrink: 0,
                        }}>
                          {def?.icon ?? <KeyRound size={13} />}
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)' }}>{def?.label ?? step.step_type}</span>
                            <span style={{ fontSize: 10, color: '#94a3b8', fontFamily: 'monospace', background: '#f8fafc', borderRadius: 3, padding: '0 4px' }}>
                              {step.step_type}
                            </span>
                          </div>
                          <StepSummary step={step} />
                        </div>
                        <div style={{ display: 'flex', gap: 1, flexShrink: 0 }} onClick={(e) => e.stopPropagation()}>
                          <IBtn title={step.is_active ? 'Disable' : 'Enable'} color={step.is_active ? '#16a34a' : '#94a3b8'} onClick={() => toggleStep(i)}>
                            {step.is_active ? <Eye size={12} /> : <EyeOff size={12} />}
                          </IBtn>
                          <IBtn title="Remove" color="#94a3b8" onClick={() => removeStep(i)}>
                            <X size={12} />
                          </IBtn>
                          {sel2 ? <ChevronDown size={13} style={{ color: '#94a3b8' }} /> : <ChevronRight size={13} style={{ color: '#94a3b8' }} />}
                        </div>
                      </div>

                      {/* Inline config */}
                      {sel2 && (
                        <div style={{
                          marginTop: 11, padding: 13,
                          background: def?.bg ?? '#f8fafc',
                          borderRadius: 8, border: `0.5px solid ${def?.accent ?? '#e2e8f0'}20`,
                        }} onClick={(e) => e.stopPropagation()}>
                          <p style={{ margin: '0 0 9px', fontSize: 10, fontWeight: 700, color: def?.accent, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                            Configure · {def?.label}
                          </p>
                          <StepConfigForm step={step} onChange={(c) => setCfg(i, c)} />
                        </div>
                      )}
                    </div>

                    {i < steps.length - 1 && <ConnectorArrow />}
                  </div>
                )
              })}

              {steps.length > 0 && (
                <>
                  <ConnectorArrow />
                  <div style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7,
                    padding: '7px 14px', background: '#f0fdf4', border: '0.5px solid #86efac',
                    borderRadius: 10, color: '#16a34a', fontSize: 12, fontWeight: 600,
                  }}>
                    <CheckCircle2 size={13} /> Token issued — login successful
                  </div>
                </>
              )}
            </div>

            {steps.length > 0 && (
              <p style={{ textAlign: 'center', fontSize: 11, color: '#cbd5e1', marginTop: 14 }}>
                Drop more blocks here to extend the flow
              </p>
            )}
          </div>
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12, color: '#94a3b8' }}>
          <KeyRound size={38} style={{ opacity: 0.2 }} />
          <div style={{ textAlign: 'center' }}>
            <p style={{ margin: 0, fontSize: 13, fontWeight: 500 }}>Select a flow to edit</p>
            <p style={{ margin: '3px 0 0', fontSize: 12 }}>or create a new one</p>
          </div>
          <button onClick={() => setShowCreate(true)} style={{
            marginTop: 6, display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '7px 16px', borderRadius: 8, fontSize: 12, fontWeight: 600,
            background: 'var(--clavex-accent)', color: 'white', border: 'none', cursor: 'pointer',
          }}>
            <Plus size={13} /> New flow
          </button>
        </div>
      )}

      {showCreate && <CreateModal onClose={() => setShowCreate(false)} onCreate={(d) => createFlow.mutate(d)} />}
    </div>
  )
}

// ─── Diagram elements ─────────────────────────────────────────────────

function TriggerBadge() {
  return (
    <>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7,
        padding: '7px 14px', background: '#1e293b', borderRadius: 10,
        color: 'white', fontSize: 12, fontWeight: 600,
      }}>
        <Play size={11} fill="white" /> User login triggered
      </div>
      <ConnectorArrow />
    </>
  )
}

function ConnectorArrow() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: '3px 0' }}>
      <ArrowDown size={15} style={{ color: '#cbd5e1' }} />
    </div>
  )
}

// ─── Step summary ─────────────────────────────────────────────────────

function StepSummary({ step }: { step: LoginFlowStep }) {
  const c = step.config as Record<string, unknown>
  let t = ''
  switch (step.step_type) {
    case 'check_attribute': t = `${c.field || '…'} ${c.op || 'eq'} "${c.value || ''}" → ${c.action || 'deny'}`; break
    case 'check_breach':    t = `Action: ${c.action || 'deny'}`; break
    case 'check_ip_risk':   t = `Risk ≥ ${c.threshold ?? 70} → ${c.action || 'deny'}`; break
    case 'enrich_claims':   t = String(c.url || 'No URL configured'); break
    case 'set_claim':       t = `${c.claim || '…'} = ${c.value || c.source_field || '…'}`; break
    case 'webhook':         t = String(c.url || 'No URL configured'); break
    case 'block_if_no_mfa': t = c.message ? String(c.message) : 'Default message'; break
    case 'check_verified':  t = `Min level: ${c.min_level || 'substantial'}`; break
    case 'ai_decision':     t = `Fallback: ${c.timeout_action || 'allow'}${c.prompt ? ' · custom prompt' : ''}`; break
    case 'oid4vp_challenge': t = c.message ? String(c.message) : 'No message configured'; break
    default: return null
  }
  return <p style={{ margin: '2px 0 0', fontSize: 11, color: '#64748b', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t}</p>
}

// ─── Step config forms ────────────────────────────────────────────────

function StepConfigForm({ step, onChange }: { step: LoginFlowStep; onChange: (c: Record<string, unknown>) => void }) {
  const c = step.config as Record<string, unknown>
  const set = (k: string, v: unknown) => onChange({ ...c, [k]: v })

  switch (step.step_type) {
    case 'check_breach':
      return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div>
            <label style={lbl}>Action when breach detected</label>
            <select style={sel} value={String(c.action ?? 'deny')} onChange={(e) => set('action', e.target.value)}>
              <option value="deny">Deny login</option>
              <option value="require_mfa">Require MFA step-up</option>
            </select>
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Custom message (optional)</label>
            <input style={inp} value={String(c.message ?? '')} onChange={(e) => set('message', e.target.value)} placeholder="Your credentials were found in a data breach…" />
          </div>
          <div style={{ gridColumn: '1 / -1', padding: '8px 10px', background: '#fef3c7', borderRadius: 6, fontSize: 11, color: '#92400e', lineHeight: 1.5 }}>
            ⚠ Reads the <code>is_breached</code> metadata flag. Enable "Breached password action" in the org password policy to populate it at login.
          </div>
        </div>
      )

    case 'check_attribute':
      return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <F label="Field" value={String(c.field ?? '')} set={(v) => set('field', v)} ph="e.g. department" />
          <div>
            <label style={lbl}>Operator</label>
            <select style={sel} value={String(c.op ?? 'eq')} onChange={(e) => set('op', e.target.value)}>
              {['eq', 'neq', 'contains', 'starts_with', 'ends_with', 'exists', 'not_exists'].map((o) => <option key={o}>{o}</option>)}
            </select>
          </div>
          <F label="Value" value={String(c.value ?? '')} set={(v) => set('value', v)} ph="e.g. blocked" />
          <div>
            <label style={lbl}>Action</label>
            <select style={sel} value={String(c.action ?? 'deny')} onChange={(e) => set('action', e.target.value)}>
              <option value="deny">Deny if matches</option>
              <option value="allow_only">Allow only if matches</option>
            </select>
          </div>
        </div>
      )

    case 'block_if_no_mfa':
      return <F label="Custom message (optional)" value={String(c.message ?? '')} set={(v) => set('message', v)} ph="Login requires MFA enrollment…" />

    case 'check_ip_risk':
      return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div>
            <label style={lbl}>Risk threshold: {String(c.threshold ?? 70)}</label>
            <input type="range" min={0} max={100} value={Number(c.threshold ?? 70)} onChange={(e) => set('threshold', Number(e.target.value))} style={{ width: '100%' }} />
          </div>
          <div>
            <label style={lbl}>Action</label>
            <select style={sel} value={String(c.action ?? 'deny')} onChange={(e) => set('action', e.target.value)}>
              <option value="deny">Deny login</option>
              <option value="require_mfa">Require MFA</option>
            </select>
          </div>
        </div>
      )

    case 'set_claim':
      return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <F label="Claim name" value={String(c.claim ?? '')} set={(v) => set('claim', v)} ph="e.g. department" />
          <F label="Static value" value={String(c.value ?? '')} set={(v) => set('value', v)} ph="e.g. engineering" />
          <F label="Source field (overrides static)" value={String(c.source_field ?? '')} set={(v) => set('source_field', v || undefined)} ph="e.g. metadata.department" />
        </div>
      )

    case 'webhook':
      return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <F label="URL" value={String(c.url ?? '')} set={(v) => set('url', v)} ph="https://…" />
          <div>
            <label style={lbl}>Method</label>
            <select style={sel} value={String(c.method ?? 'POST')} onChange={(e) => set('method', e.target.value)}>
              <option>POST</option><option>GET</option><option>PUT</option>
            </select>
          </div>
          <F label="HMAC secret (optional)" value={String(c.secret ?? '')} set={(v) => set('secret', v)} ph="signing secret" />
        </div>
      )

    case 'enrich_claims':
      return <EnrichForm c={c} onChange={onChange} />

    case 'require_mfa':
    case 'require_email_verified':
      return <p style={{ margin: 0, fontSize: 12, color: '#64748b', fontStyle: 'italic' }}>No configuration needed.</p>

    case 'ai_decision':
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div>
            <label style={lbl}>Additional instructions for Claude (optional)</label>
            <textarea
              style={{ ...inp, height: 72, resize: 'vertical', fontFamily: 'monospace', fontSize: 12 }}
              value={String(c.prompt ?? '')}
              onChange={(e) => set('prompt', e.target.value)}
              placeholder={'Deny if the IP is outside the EU.\nRequire MFA for any admin user.'}
            />
            <p style={{ margin: '3px 0 0', fontSize: 11, color: '#64748b' }}>
              Claude always receives: user email, user ID, client ID, IP address, risk score, org slug. Add org-specific rules here.
            </p>
          </div>
          <div>
            <label style={lbl}>Fallback action if AI is unavailable (no API key, timeout, API error)</label>
            <select style={sel} value={String(c.timeout_action ?? 'allow')} onChange={(e) => set('timeout_action', e.target.value)}>
              <option value="allow">Allow login (fail-open)</option>
              <option value="require_mfa">Require MFA</option>
              <option value="deny">Deny login (fail-closed)</option>
            </select>
          </div>
          <div style={{ padding: '8px 10px', background: '#f5f3ff', borderRadius: 6, fontSize: 11, color: '#4c1d95', lineHeight: 1.5 }}>
            ✦ Requires an Anthropic API key configured under <strong>AI Assistant → API key</strong>.
            The AI decision and its reasoning are written to the audit log for NIS2 Art.21 traceability.
          </div>
        </div>
      )

    case 'check_verified':
      return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div>
            <label style={lbl}>Minimum assurance level</label>
            <select style={sel} value={String(c.min_level ?? 'substantial')} onChange={(e) => set('min_level', e.target.value)}>
              <option value="low">Low</option>
              <option value="substantial">Substantial (eIDAS / SPID L2)</option>
              <option value="high">High (eIDAS / SPID L3)</option>
            </select>
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Step-up IdP URL (optional — redirect instead of deny)</label>
            <input style={inp} value={String(c.step_up_url ?? '')} onChange={(e) => set('step_up_url', e.target.value)} placeholder="/acme/spid/sso/arubaid-l3  or  /acme/cie/cie-high" />
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <label style={lbl}>Custom message (optional)</label>
            <input style={inp} value={String(c.message ?? '')} onChange={(e) => set('message', e.target.value)} placeholder="This service requires a higher identity assurance level…" />
          </div>
          <div style={{ gridColumn: '1 / -1', padding: '8px 10px', background: '#ccfbf1', borderRadius: 6, fontSize: 11, color: '#134e4a', lineHeight: 1.5 }}>
            ℹ️ Reads the <code>assurance_level</code> from user metadata. Set by Clavex EuroID, SPID, and eIDAS identity providers at login.
            {c.step_up_url ? ' When the level is insufficient the user is redirected to the step-up IdP; after re-authentication the flow resumes.' : ''}
          </div>
        </div>
      )

    case 'oid4vp_challenge':
      return <OID4VPChallengeForm c={c} onChange={onChange} />

    default:
      return <p style={{ margin: 0, fontSize: 12, color: '#94a3b8' }}>Unknown step type.</p>
  }
}

function OID4VPChallengeForm({ c, onChange }: { c: Record<string, unknown>; onChange: (x: Record<string, unknown>) => void }) {
  const set = (k: string, v: unknown) => onChange({ ...c, [k]: v })
  const hasDCQL = Boolean(c.dcql_query)
  const hasPD   = Boolean(c.presentation_definition)
  // Prefer DCQL; only show PD tab when dcql_query is empty and pd is set
  const [tab, setTab] = useState<'dcql' | 'pd'>(hasPD && !hasDCQL ? 'pd' : 'dcql')

  function tryPretty(raw: unknown): string {
    if (!raw) return ''
    if (typeof raw === 'object') {
      try { return JSON.stringify(raw, null, 2) } catch { return '' }
    }
    return String(raw)
  }
  function parseJSON(s: string): unknown {
    try { return JSON.parse(s) } catch { return s }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <F label="Message shown to user" value={String(c.message ?? '')} set={(v) => set('message', v)}
        ph="Please present your company badge to access this resource." />

      {/* Tab selector */}
      <div style={{ display: 'flex', gap: 0, borderRadius: 6, overflow: 'hidden', border: '0.5px solid #bae6fd' }}>
        {(['dcql', 'pd'] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            style={{
              flex: 1, padding: '5px 0', fontSize: 11, fontWeight: 700, cursor: 'pointer', border: 'none',
              background: tab === t ? '#0369a1' : 'white',
              color: tab === t ? 'white' : '#0369a1',
              textTransform: 'uppercase', letterSpacing: '0.06em',
            }}>
            {t === 'dcql' ? 'DCQL Query' : 'Presentation Definition'}
          </button>
        ))}
      </div>

      {tab === 'dcql' ? (
        <div>
          <label style={lbl}>DCQL query (JSON) — recommended for ISO 18013-5 mdoc &amp; SD-JWT</label>
          <textarea
            style={{ ...inp, height: 120, resize: 'vertical', fontFamily: 'monospace', fontSize: 11 }}
            value={tryPretty(c.dcql_query)}
            onChange={(e) => set('dcql_query', parseJSON(e.target.value))}
            placeholder={'{\n  "credentials": {\n    "badge": {\n      "format": "mso_mdoc",\n      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" }\n    }\n  }\n}'}
          />
        </div>
      ) : (
        <div>
          <label style={lbl}>Presentation definition (JSON) — OID4VP §8 / DIF PE</label>
          <textarea
            style={{ ...inp, height: 120, resize: 'vertical', fontFamily: 'monospace', fontSize: 11 }}
            value={tryPretty(c.presentation_definition)}
            onChange={(e) => set('presentation_definition', parseJSON(e.target.value))}
            placeholder={'{\n  "id": "badge-check",\n  "input_descriptors": [...]\n}'}
          />
        </div>
      )}

      <div style={{ padding: '8px 10px', background: '#e0f2fe', borderRadius: 6, fontSize: 11, color: '#0c4a6e', lineHeight: 1.5 }}>
        🪪 When this step runs the login is paused and the browser shows a QR code / deep-link.
        The user scans it with their IT-Wallet or mdoc app. On successful presentation the flow
        resumes and the credential claims are merged into the token as <code>extra_claims</code>.
      </div>
    </div>
  )
}

function EnrichForm({ c, onChange }: { c: Record<string, unknown>; onChange: (x: Record<string, unknown>) => void }) {
  const set = (k: string, v: unknown) => onChange({ ...c, [k]: v })
  const maps = (c.claim_mappings as { source: string; target: string }[]) ?? []
  const addMap = () => onChange({ ...c, claim_mappings: [...maps, { source: '', target: '' }] })
  const delMap = (i: number) => onChange({ ...c, claim_mappings: maps.filter((_, j) => j !== i) })
  const updMap = (i: number, k: 'source' | 'target', v: string) =>
    onChange({ ...c, claim_mappings: maps.map((m, j) => (j === i ? { ...m, [k]: v } : m)) })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <F label="URL" value={String(c.url ?? '')} set={(v) => set('url', v)} ph="https://api.example.com/enrich" />
        <div>
          <label style={lbl}>Method</label>
          <select style={sel} value={String(c.method ?? 'POST')} onChange={(e) => set('method', e.target.value)}>
            <option>POST</option><option>GET</option>
          </select>
        </div>
        <F label='Body template ({{.Sub}}, {{.Email}})' value={String(c.body_template ?? '')} set={(v) => set('body_template', v)} ph='{"sub":"{{.Sub}}"}' />
        <div>
          <label style={lbl}>On error</label>
          <select style={sel} value={String(c.on_error ?? 'continue')} onChange={(e) => set('on_error', e.target.value)}>
            <option value="continue">Continue (fail-open)</option>
            <option value="deny">Deny login</option>
          </select>
        </div>
        <F label="Timeout (ms)" value={String(c.timeout_ms ?? 3000)} set={(v) => set('timeout_ms', Number(v) || 3000)} ph="3000" />
      </div>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 5 }}>
          <label style={{ ...lbl, marginBottom: 0 }}>Claim mappings ($.key → claim)</label>
          <button onClick={addMap} style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 11, color: 'var(--clavex-accent)', fontWeight: 700 }}>+ Add</button>
        </div>
        {maps.map((m, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 5 }}>
            <input style={{ ...inp, flex: 1 }} placeholder="$.department" value={m.source} onChange={(e) => updMap(i, 'source', e.target.value)} />
            <span style={{ fontSize: 11, color: '#94a3b8' }}>→</span>
            <input style={{ ...inp, flex: 1 }} placeholder="department" value={m.target} onChange={(e) => updMap(i, 'target', e.target.value)} />
            <button onClick={() => delMap(i)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8' }}><X size={11} /></button>
          </div>
        ))}
        {maps.length === 0 && <p style={{ margin: 0, fontSize: 11, color: '#94a3b8', fontStyle: 'italic' }}>All response keys merged (excluding reserved claims)</p>}
      </div>
    </div>
  )
}

// ─── Micro helpers ────────────────────────────────────────────────────

function F({ label, value, set, ph }: { label: string; value: string; set: (v: string) => void; ph?: string }) {
  return (
    <div>
      <label style={lbl}>{label}</label>
      <input style={inp} value={value} onChange={(e) => set(e.target.value)} placeholder={ph} />
    </div>
  )
}

function Badge({ color, bg, children }: { color: string; bg: string; children: React.ReactNode }) {
  return (
    <span style={{ fontSize: 10, fontWeight: 700, background: bg, color, borderRadius: 3, padding: '1px 5px' }}>
      {children}
    </span>
  )
}

function IBtn({ children, onClick, title, color }: { children: React.ReactNode; onClick: () => void; title?: string; color: string }) {
  return (
    <button onClick={onClick} title={title} style={{ background: 'none', border: 'none', cursor: 'pointer', color, padding: 3, display: 'flex' }}>
      {children}
    </button>
  )
}

// ─── Create flow modal ────────────────────────────────────────────────

function CreateModal({ onClose, onCreate }: { onClose: () => void; onCreate: (d: { name: string; description?: string; is_default: boolean }) => void }) {
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [isDefault, setIsDefault] = useState(false)

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
      <div style={{ background: 'white', borderRadius: 14, width: 420, padding: 26, boxShadow: '0 20px 60px rgba(0,0,0,0.2)' }}>
        <h2 style={{ margin: '0 0 18px', fontSize: 15, fontWeight: 700, color: 'var(--clavex-ink)' }}>New Login Flow</h2>

        <div style={{ marginBottom: 12 }}>
          <label style={lbl}>Flow name</label>
          <input style={inp} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. High-security login" autoFocus />
        </div>
        <div style={{ marginBottom: 12 }}>
          <label style={lbl}>Description (optional)</label>
          <input style={inp} value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="What does this flow do?" />
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', marginBottom: 20, fontSize: 13, color: 'var(--clavex-ink)' }}>
          <input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />
          Set as default flow for this organization
        </label>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ background: 'none', border: '0.5px solid var(--clavex-border)', borderRadius: 8, padding: '6px 14px', fontSize: 12, cursor: 'pointer', color: '#64748b' }}>
            Cancel
          </button>
          <button
            disabled={!name.trim()}
            onClick={() => onCreate({ name: name.trim(), description: desc || undefined, is_default: isDefault })}
            style={{
              background: name.trim() ? 'var(--clavex-accent)' : '#e2e8f0',
              color: name.trim() ? 'white' : '#94a3b8',
              border: 'none', borderRadius: 8, padding: '6px 18px',
              fontSize: 12, fontWeight: 600, cursor: name.trim() ? 'pointer' : 'default',
            }}
          >
            Create flow
          </button>
        </div>
      </div>
    </div>
  )
}
