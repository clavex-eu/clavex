import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { toArr } from '@/lib/api'
import { useAuthStore } from '@/stores/auth'
import toast from 'react-hot-toast'
import { Plus, Edit2, Trash2, FileText } from 'lucide-react'

const card = {
  background: 'var(--clavex-surface-card)',
  border: '0.5px solid rgba(93,202,165,0.2)',
  boxShadow: '0 1px 4px rgba(0,0,0,0.06)',
  borderRadius: 12,
  padding: '24px',
}
const inp = {
  width: '100%',
  background: 'var(--clavex-surface)',
  border: '0.5px solid rgba(93,202,165,0.2)',
  borderRadius: 8,
  padding: '8px 12px',
  color: 'var(--clavex-text)',
  fontSize: 14,
  outline: 'none',
}
const lbl = { fontSize: 12, fontWeight: 600, color: 'var(--clavex-400)', marginBottom: 4 }
const btn = (variant: 'primary' | 'danger' | 'ghost' = 'primary') => ({
  display: 'inline-flex', alignItems: 'center', gap: 6,
  padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600,
  cursor: 'pointer', border: 'none', transition: 'opacity 0.15s',
  ...(variant === 'primary' ? {
    background: 'var(--clavex-primary)', color: '#0f1923',
  } : variant === 'danger' ? {
    background: 'rgba(239,68,68,0.12)', color: '#f87171',
    border: '0.5px solid rgba(239,68,68,0.3)',
  } : {
    background: 'transparent', color: 'var(--clavex-400)',
    border: '0.5px solid rgba(93,202,165,0.2)',
  }),
})

const LEGAL_BASIS_OPTIONS = [
  'Consent', 'Contract', 'Legal Obligation', 'Vital Interests',
  'Public Task', 'Legitimate Interests',
]

const DATA_CATEGORY_OPTIONS = [
  'basic identity', 'contact', 'financial', 'health', 'biometric',
  'location', 'behavioral', 'special category', 'criminal',
]

interface ProcessingRecord {
  id: string
  org_id: string
  activity_name: string
  purpose: string
  legal_basis: string
  data_categories: string[]
  data_subjects: string
  retention_period: string
  recipients: unknown
  processors: unknown
  is_active: boolean
  created_at: string
  updated_at: string
}

type FormData = {
  activity_name: string
  purpose: string
  legal_basis: string
  data_categories: string[]
  data_subjects: string
  retention_period: string
  recipients: string
  processors: string
  is_active: boolean
}

const emptyForm = (): FormData => ({
  activity_name: '',
  purpose: '',
  legal_basis: 'Consent',
  data_categories: [],
  data_subjects: '',
  retention_period: '',
  recipients: '',
  processors: '',
  is_active: true,
})

function RecordForm({
  initial,
  onSave,
  onCancel,
  isPending,
}: {
  initial: FormData
  onSave: (f: FormData) => void
  onCancel: () => void
  isPending: boolean
}) {
  const [form, setForm] = useState<FormData>(initial)
  const set = (k: keyof FormData, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  const toggleCategory = (cat: string) => {
    set('data_categories', form.data_categories.includes(cat)
      ? form.data_categories.filter(c => c !== cat)
      : [...form.data_categories, cat])
  }

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div>
        <p style={lbl}>Activity Name *</p>
        <input style={inp} value={form.activity_name} onChange={e => set('activity_name', e.target.value)} placeholder="e.g. User Authentication" />
      </div>
      <div>
        <p style={lbl}>Purpose *</p>
        <textarea style={{ ...inp, minHeight: 72, resize: 'vertical' }} value={form.purpose} onChange={e => set('purpose', e.target.value)} placeholder="Describe the processing purpose…" />
      </div>
      <div>
        <p style={lbl}>Legal Basis *</p>
        <select style={inp} value={form.legal_basis} onChange={e => set('legal_basis', e.target.value)}>
          {LEGAL_BASIS_OPTIONS.map(o => <option key={o}>{o}</option>)}
        </select>
      </div>
      <div>
        <p style={lbl}>Data Categories</p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {DATA_CATEGORY_OPTIONS.map(cat => (
            <button key={cat} onClick={() => toggleCategory(cat)} style={{
              padding: '4px 10px', borderRadius: 20, fontSize: 12, cursor: 'pointer',
              border: '0.5px solid ' + (form.data_categories.includes(cat) ? 'var(--clavex-primary)' : 'rgba(93,202,165,0.2)'),
              background: form.data_categories.includes(cat) ? 'rgba(93,202,165,0.15)' : 'transparent',
              color: form.data_categories.includes(cat) ? 'var(--clavex-primary)' : 'var(--clavex-400)',
            }}>
              {cat}
            </button>
          ))}
        </div>
      </div>
      <div>
        <p style={lbl}>Data Subjects</p>
        <input style={inp} value={form.data_subjects} onChange={e => set('data_subjects', e.target.value)} placeholder="e.g. customers, employees" />
      </div>
      <div>
        <p style={lbl}>Retention Period</p>
        <input style={inp} value={form.retention_period} onChange={e => set('retention_period', e.target.value)} placeholder="e.g. 2 years, 90 days" />
      </div>
      <div>
        <p style={lbl}>Recipients (JSON or plain text)</p>
        <textarea style={{ ...inp, minHeight: 60, resize: 'vertical' }} value={form.recipients} onChange={e => set('recipients', e.target.value)} placeholder='["Marketing dept", "Analytics vendor"]' />
      </div>
      <div>
        <p style={lbl}>Processors (JSON or plain text)</p>
        <textarea style={{ ...inp, minHeight: 60, resize: 'vertical' }} value={form.processors} onChange={e => set('processors', e.target.value)} placeholder='["AWS EU", "Stripe"]' />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input type="checkbox" id="is_active" checked={form.is_active} onChange={e => set('is_active', e.target.checked)} />
        <label htmlFor="is_active" style={{ fontSize: 13, color: 'var(--clavex-text)', cursor: 'pointer' }}>Active</label>
      </div>
      <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
        <button onClick={() => onSave(form)} disabled={!form.activity_name || !form.purpose || isPending} style={btn()}>
          {isPending ? 'Saving…' : 'Save Record'}
        </button>
        <button onClick={onCancel} style={btn('ghost')}>Cancel</button>
      </div>
    </div>
  )
}

function parseJson(v: unknown): string {
  if (!v) return ''
  if (typeof v === 'string') return v
  return JSON.stringify(v)
}

function toPayload(form: FormData) {
  let recipients: unknown = form.recipients
  let processors: unknown = form.processors
  try { recipients = JSON.parse(form.recipients) } catch { /* keep string */ }
  try { processors = JSON.parse(form.processors) } catch { /* keep string */ }
  return { ...form, recipients, processors }
}

export default function CompliancePage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState<ProcessingRecord | null>(null)

  const base = `/organizations/${orgId}/compliance/processing-records`

  const recordsQ = useQuery<ProcessingRecord[]>({
    queryKey: ['processing-records', orgId],
    queryFn: () => api.get(base).then(r => toArr<ProcessingRecord>(r.data)),
    enabled: !!orgId,
  })

  const createM = useMutation({
    mutationFn: (form: FormData) => api.post(base, toPayload(form)),
    onSuccess: () => {
      toast.success('Record created')
      qc.invalidateQueries({ queryKey: ['processing-records', orgId] })
      setShowCreate(false)
    },
    onError: () => toast.error('Failed to create record'),
  })

  const updateM = useMutation({
    mutationFn: ({ id, form }: { id: string; form: FormData }) => api.put(`${base}/${id}`, toPayload(form)),
    onSuccess: () => {
      toast.success('Record updated')
      qc.invalidateQueries({ queryKey: ['processing-records', orgId] })
      setEditing(null)
    },
    onError: () => toast.error('Failed to update record'),
  })

  const deleteM = useMutation({
    mutationFn: (id: string) => api.delete(`${base}/${id}`),
    onSuccess: () => {
      toast.success('Record deleted')
      qc.invalidateQueries({ queryKey: ['processing-records', orgId] })
    },
    onError: () => toast.error('Failed to delete record'),
  })

  const records = recordsQ.data ?? []

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <FileText style={{ color: 'var(--clavex-primary)' }} className="h-5 w-5" />
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--clavex-text)' }}>GDPR Compliance</h1>
        </div>
        <p style={{ fontSize: 14, color: 'var(--clavex-400)' }}>
          Manage Article 30 Records of Processing Activities (RoPA) required by GDPR.
        </p>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 24 }}>
        {[
          { label: 'Total Records', value: records.length },
          { label: 'Active', value: records.filter(r => r.is_active).length },
          { label: 'Inactive', value: records.filter(r => !r.is_active).length },
        ].map(s => (
          <div key={s.label} style={{ ...card, padding: '16px 20px' }}>
            <p style={{ fontSize: 24, fontWeight: 700, color: 'var(--clavex-primary)' }}>{s.value}</p>
            <p style={{ fontSize: 12, color: 'var(--clavex-400)' }}>{s.label}</p>
          </div>
        ))}
      </div>

      {/* Create button + form */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
        <button onClick={() => setShowCreate(v => !v)} style={btn()}>
          <Plus className="h-4 w-4" />
          New Record
        </button>
      </div>

      {showCreate && (
        <div style={{ ...card, marginBottom: 20 }}>
          <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--clavex-text)', marginBottom: 16 }}>New Processing Record</h3>
          <RecordForm
            initial={emptyForm()}
            onSave={f => createM.mutate(f)}
            onCancel={() => setShowCreate(false)}
            isPending={createM.isPending}
          />
        </div>
      )}

      {/* Records list */}
      {recordsQ.isLoading ? (
        <p style={{ color: 'var(--clavex-400)', fontSize: 14 }}>Loading…</p>
      ) : records.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', padding: '40px' }}>
          <FileText className="h-8 w-8 mx-auto mb-3" style={{ color: 'rgba(93,202,165,0.3)' }} />
          <p style={{ color: 'var(--clavex-400)', fontSize: 14 }}>No processing records yet</p>
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 12 }}>
          {records.map(r => (
            <div key={r.id} style={card}>
              {editing?.id === r.id ? (
                <div>
                  <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--clavex-text)', marginBottom: 14 }}>Edit Record</h3>
                  <RecordForm
                    initial={{
                      activity_name: r.activity_name,
                      purpose: r.purpose,
                      legal_basis: r.legal_basis,
                      data_categories: r.data_categories ?? [],
                      data_subjects: r.data_subjects ?? '',
                      retention_period: r.retention_period ?? '',
                      recipients: parseJson(r.recipients),
                      processors: parseJson(r.processors),
                      is_active: r.is_active,
                    }}
                    onSave={f => updateM.mutate({ id: r.id, form: f })}
                    onCancel={() => setEditing(null)}
                    isPending={updateM.isPending}
                  />
                </div>
              ) : (
                <div>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 10 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--clavex-text)' }}>{r.activity_name}</span>
                        {r.is_active
                          ? <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 20, background: 'rgba(93,202,165,0.12)', color: 'var(--clavex-primary)' }}>ACTIVE</span>
                          : <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 20, background: 'rgba(239,68,68,0.1)', color: '#f87171' }}>INACTIVE</span>
                        }
                      </div>
                      <p style={{ fontSize: 13, color: 'var(--clavex-400)', marginTop: 4 }}>{r.purpose}</p>
                    </div>
                    <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                      <button onClick={() => setEditing(r)} style={btn('ghost')}>
                        <Edit2 className="h-3.5 w-3.5" /> Edit
                      </button>
                      <button onClick={() => { if (confirm('Delete this record?')) deleteM.mutate(r.id) }} style={btn('danger')}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10 }}>
                    {[
                      { label: 'Legal Basis', value: r.legal_basis },
                      { label: 'Data Subjects', value: r.data_subjects },
                      { label: 'Retention', value: r.retention_period },
                      { label: 'Data Categories', value: (r.data_categories ?? []).join(', ') || '—' },
                    ].map(f => (
                      <div key={f.label}>
                        <p style={{ fontSize: 10, fontWeight: 700, color: 'rgba(196,223,240,0.35)', letterSpacing: '1px', marginBottom: 2 }}>{f.label.toUpperCase()}</p>
                        <p style={{ fontSize: 12, color: 'var(--clavex-text)' }}>{f.value || '—'}</p>
                      </div>
                    ))}
                  </div>
                  {(Boolean(r.recipients) || Boolean(r.processors)) && (
                    <div style={{ marginTop: 10, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                      {Boolean(r.recipients) && (
                        <div>
                          <p style={{ fontSize: 10, fontWeight: 700, color: 'rgba(196,223,240,0.35)', letterSpacing: '1px', marginBottom: 2 }}>RECIPIENTS</p>
                          <p style={{ fontSize: 12, color: 'var(--clavex-text)' }}>{String(parseJson(r.recipients))}</p>
                        </div>
                      )}
                      {Boolean(r.processors) && (
                        <div>
                          <p style={{ fontSize: 10, fontWeight: 700, color: 'rgba(196,223,240,0.35)', letterSpacing: '1px', marginBottom: 2 }}>PROCESSORS</p>
                          <p style={{ fontSize: 12, color: 'var(--clavex-text)' }}>{String(parseJson(r.processors))}</p>
                        </div>
                      )}
                    </div>
                  )}
                  <p style={{ fontSize: 11, color: 'rgba(196,223,240,0.3)', marginTop: 10 }}>
                    Updated: {new Date(r.updated_at).toLocaleDateString()}
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
