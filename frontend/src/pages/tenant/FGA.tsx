import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  GitBranch, Plus, Trash2, CheckCircle, XCircle, AlertCircle,
  Play, RefreshCw, Download, Upload, Eye, ChevronRight, Loader2,
  Database,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface StoreInfo {
  store_id: string
  model_id: string | null
  created_at: string
  updated_at: string
}

interface TupleKey {
  user: string
  relation: string
  object: string
}

interface ReadResponse {
  tuples: TupleKey[]
  continuation_token: string | null
}

interface FGATemplate {
  id: string
  name: string
  description: string
  use_cases: string[]
  model: unknown
}

// ── Shared styles ─────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}
const inp: React.CSSProperties = {
  background: 'white',
  color: 'var(--clavex-ink)',
  border: '0.5px solid var(--clavex-border-subtle)',
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
  textTransform: 'uppercase' as const,
  letterSpacing: '0.06em',
  color: 'var(--clavex-ink-muted)',
  marginBottom: 4,
}
const btn = (variant: 'primary' | 'ghost' | 'danger' = 'primary'): React.CSSProperties => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  padding: '7px 14px',
  borderRadius: 8,
  fontSize: 13,
  fontWeight: 600,
  cursor: 'pointer',
  border: variant === 'ghost' ? '0.5px solid var(--clavex-border-subtle)' : 'none',
  background:
    variant === 'primary' ? 'var(--clavex-primary)'
    : variant === 'danger'  ? '#ef4444'
    : 'white',
  color: variant === 'ghost' ? 'var(--clavex-ink)' : 'white',
})

// ── Tab nav ───────────────────────────────────────────────────────────────────

type Tab = 'store' | 'model' | 'templates' | 'tuples' | 'check'

const TABS: { id: Tab; label: string }[] = [
  { id: 'store',     label: 'Store'              },
  { id: 'model',     label: 'Auth Model'         },
  { id: 'templates', label: 'Templates'          },
  { id: 'tuples',    label: 'Relationship Tuples'},
  { id: 'check',     label: 'Check'              },
]

// ── Store Tab ─────────────────────────────────────────────────────────────────

function StoreTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()

  const { data: store, isLoading, isError, error } = useQuery<StoreInfo>({
    queryKey: ['fga-store', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/fga/stores`).then(r => r.data),
    retry: (count, err: unknown) => {
      if ((err as { response?: { status: number } })?.response?.status === 404) return false
      return count < 2
    },
  })

  const init = useMutation({
    mutationFn: () => api.post(`/organizations/${orgId}/fga/stores`),
    onSuccess: () => {
      toast.success('FGA store provisioned')
      qc.invalidateQueries({ queryKey: ['fga-store', orgId] })
    },
    onError: () => toast.error('Could not provision FGA store'),
  })

  if (isLoading) return <p style={{ color: 'var(--clavex-ink-muted)', fontSize: 13 }}>Loading…</p>

  const notFound = (isError && (error as { response?: { status: number } })?.response?.status === 404)

  if (notFound || !store) {
    return (
      <div style={{ ...card, borderStyle: 'dashed', textAlign: 'center', padding: '48px 24px' }}>
        <Database size={36} style={{ color: 'var(--clavex-ink-muted)', margin: '0 auto 12px' }} />
        <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6 }}>No FGA store provisioned</p>
        <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', marginBottom: 20, maxWidth: 400, margin: '0 auto 20px' }}>
          Initialize an OpenFGA store for this organization to enable fine-grained authorization (Zanzibar ReBAC model).
        </p>
        <button style={btn('primary')} onClick={() => init.mutate()} disabled={init.isPending}>
          {init.isPending ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
          Initialize FGA Store
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div style={{ ...card }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <CheckCircle size={18} style={{ color: 'var(--clavex-primary)' }} />
          <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--clavex-ink)' }}>Store Active</span>
        </div>
        <div className="grid grid-cols-2 gap-4">
          {[
            { label: 'Store ID',       value: store.store_id },
            { label: 'Active Model ID', value: store.model_id ?? '—' },
            { label: 'Provisioned',    value: new Date(store.created_at).toLocaleString() },
            { label: 'Last Updated',   value: new Date(store.updated_at).toLocaleString() },
          ].map(({ label, value }) => (
            <div key={label}>
              <span style={lbl}>{label}</span>
              <code style={{ fontSize: 12, color: 'var(--clavex-ink)', wordBreak: 'break-all' }}>{value}</code>
            </div>
          ))}
        </div>
      </div>

      <div style={{ ...card, background: '#f0fdf4', borderColor: '#86efac' }}>
        <p style={{ fontSize: 13, color: '#166534', lineHeight: 1.6 }}>
          <strong>Next steps:</strong> Upload an authorization model in the <em>Auth Model</em> tab,
          or import a pre-built template from the <em>Templates</em> tab.
          Then write relationship tuples to model user–object permissions.
        </p>
      </div>
    </div>
  )
}

// ── Model Tab ─────────────────────────────────────────────────────────────────

function ModelTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [editJson, setEditJson] = useState<string>('')
  const [editing, setEditing] = useState(false)

  const { data: rawModel, isLoading, isError, error } = useQuery<unknown>({
    queryKey: ['fga-model', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/fga/model`).then(r => r.data),
    retry: (count, err: unknown) => {
      const status = (err as { response?: { status: number } })?.response?.status
      if (status === 404 || status === 409) return false
      return count < 2
    },
  })

  const saveModel = useMutation({
    mutationFn: (body: unknown) => api.put(`/organizations/${orgId}/fga/model`, body),
    onSuccess: () => {
      toast.success('Authorization model updated')
      setEditing(false)
      qc.invalidateQueries({ queryKey: ['fga-model', orgId] })
      qc.invalidateQueries({ queryKey: ['fga-store', orgId] })
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg ?? 'Failed to save model')
    },
  })

  const startEdit = () => {
    setEditJson(rawModel ? JSON.stringify(rawModel, null, 2) : '')
    setEditing(true)
  }

  const handleSave = () => {
    let parsed: unknown
    try {
      parsed = JSON.parse(editJson)
    } catch {
      toast.error('Invalid JSON — fix syntax errors before saving')
      return
    }
    saveModel.mutate(parsed)
  }

  const noStore = (isError && (error as { response?: { status: number } })?.response?.status === 409)
  const noModel = (isError && (error as { response?: { status: number } })?.response?.status === 404)

  if (isLoading) return <p style={{ color: 'var(--clavex-ink-muted)', fontSize: 13 }}>Loading…</p>

  if (noStore) {
    return (
      <div style={{ ...card, textAlign: 'center', padding: '40px 24px' }}>
        <AlertCircle size={32} style={{ color: '#f59e0b', margin: '0 auto 10px' }} />
        <p style={{ color: 'var(--clavex-ink)', fontWeight: 600 }}>FGA store not provisioned</p>
        <p style={{ color: 'var(--clavex-ink-muted)', fontSize: 13, marginTop: 6 }}>Go to the Store tab to initialize it first.</p>
      </div>
    )
  }

  if (noModel && !editing) {
    return (
      <div style={{ ...card, borderStyle: 'dashed', textAlign: 'center', padding: '40px 24px' }}>
        <p style={{ color: 'var(--clavex-ink)', fontWeight: 600, marginBottom: 6 }}>No authorization model yet</p>
        <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', marginBottom: 20 }}>
          Import a template or paste a custom OpenFGA 1.1 schema JSON below.
        </p>
        <button style={btn('primary')} onClick={startEdit}>
          <Upload size={14} /> Write Custom Model
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {!editing && (
        <>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button style={btn('ghost')} onClick={startEdit}>
              <Eye size={14} /> Edit Model
            </button>
          </div>
          <div style={{ ...card, padding: 0, overflow: 'hidden' }}>
            <div style={{ background: '#1e293b', borderRadius: 12 }}>
              <div style={{ padding: '10px 16px', borderBottom: '0.5px solid rgba(255,255,255,0.06)', fontSize: 11, color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                authorization_model.json — OpenFGA 1.1
              </div>
              <pre style={{ margin: 0, padding: '16px', fontSize: 12, color: '#e2e8f0', lineHeight: 1.6, overflowX: 'auto', maxHeight: 520 }}>
                {JSON.stringify(rawModel, null, 2)}
              </pre>
            </div>
          </div>
        </>
      )}

      {editing && (
        <div className="space-y-3">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontWeight: 600, color: 'var(--clavex-ink)', fontSize: 14 }}>Edit Authorization Model</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button style={btn('ghost')} onClick={() => setEditing(false)}>Cancel</button>
              <button style={btn('primary')} onClick={handleSave} disabled={saveModel.isPending}>
                {saveModel.isPending ? <Loader2 size={14} className="animate-spin" /> : <Upload size={14} />}
                Save Model
              </button>
            </div>
          </div>
          <div style={{ background: '#1e293b', borderRadius: 12, overflow: 'hidden' }}>
            <div style={{ padding: '8px 14px', borderBottom: '0.5px solid rgba(255,255,255,0.06)', fontSize: 11, color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', letterSpacing: '0.08em' }}>
              OpenFGA schema_version 1.1 JSON
            </div>
            <textarea
              value={editJson}
              onChange={e => setEditJson(e.target.value)}
              style={{
                width: '100%', minHeight: 480, padding: '14px 16px',
                background: 'transparent', color: '#e2e8f0', fontSize: 12,
                fontFamily: 'monospace', lineHeight: 1.6, border: 'none',
                outline: 'none', resize: 'vertical', boxSizing: 'border-box',
              }}
              spellCheck={false}
              placeholder='{ "schema_version": "1.1", "type_definitions": [...] }'
            />
          </div>
        </div>
      )}
    </div>
  )
}

// ── Templates Tab ─────────────────────────────────────────────────────────────

function TemplatesTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [preview, setPreview] = useState<FGATemplate | null>(null)

  const { data, isLoading } = useQuery<{ templates: FGATemplate[] }>({
    queryKey: ['fga-templates', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/fga/templates`).then(r => r.data),
  })

  const importTpl = useMutation({
    mutationFn: (templateId: string) =>
      api.post(`/organizations/${orgId}/fga/templates/${templateId}/import`),
    onSuccess: (_, templateId) => {
      toast.success('Template imported as active model')
      setPreview(null)
      qc.invalidateQueries({ queryKey: ['fga-model', orgId] })
      qc.invalidateQueries({ queryKey: ['fga-store', orgId] })
      void templateId
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg ?? 'Import failed')
    },
  })

  if (isLoading) return <p style={{ color: 'var(--clavex-ink-muted)', fontSize: 13 }}>Loading…</p>

  const templates = data?.templates ?? []

  return (
    <div className="space-y-4">
      {preview && (
        <div style={{ ...card, borderColor: 'var(--clavex-primary)' }} className="space-y-4">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <p style={{ fontWeight: 700, fontSize: 15, color: 'var(--clavex-ink)', marginBottom: 4 }}>{preview.name}</p>
              <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)' }}>{preview.description}</p>
              {preview.use_cases?.length > 0 && (
                <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {preview.use_cases.map(uc => (
                    <span key={uc} style={{ fontSize: 11, padding: '2px 8px', borderRadius: 20, background: '#f0fdf4', color: '#166534', border: '0.5px solid #86efac' }}>{uc}</span>
                  ))}
                </div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button style={btn('ghost')} onClick={() => setPreview(null)}>Close</button>
              <button style={btn('primary')} onClick={() => importTpl.mutate(preview.id)} disabled={importTpl.isPending}>
                {importTpl.isPending ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
                Import as Active Model
              </button>
            </div>
          </div>
          <div style={{ background: '#1e293b', borderRadius: 10, overflow: 'hidden' }}>
            <div style={{ padding: '8px 14px', borderBottom: '0.5px solid rgba(255,255,255,0.06)', fontSize: 11, color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace' }}>
              model preview
            </div>
            <pre style={{ margin: 0, padding: '14px 16px', fontSize: 12, color: '#e2e8f0', lineHeight: 1.6, overflowX: 'auto', maxHeight: 360 }}>
              {JSON.stringify(preview.model, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {!preview && (
        <div className="grid grid-cols-2 gap-4">
          {templates.length === 0 && (
            <p style={{ color: 'var(--clavex-ink-muted)', fontSize: 13, gridColumn: 'span 2' }}>No templates available.</p>
          )}
          {templates.map(t => (
            <div
              key={t.id}
              style={{ ...card, cursor: 'pointer', transition: 'border-color .15s' }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--clavex-primary)')}
              onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--clavex-border)')}
              onClick={() => setPreview(t)}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <span style={{ fontWeight: 700, color: 'var(--clavex-ink)', fontSize: 14 }}>{t.name}</span>
                <ChevronRight size={14} style={{ color: 'var(--clavex-ink-muted)', marginTop: 2 }} />
              </div>
              <p style={{ fontSize: 12, color: 'var(--clavex-ink-muted)', lineHeight: 1.5, marginBottom: 10 }}>{t.description}</p>
              {t.use_cases?.slice(0, 3).map(uc => (
                <span key={uc} style={{ fontSize: 11, padding: '2px 8px', borderRadius: 20, background: '#f8fafc', color: 'var(--clavex-ink-muted)', border: '0.5px solid var(--clavex-border-subtle)', marginRight: 4, display: 'inline-block', marginBottom: 4 }}>{uc}</span>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Tuples Tab ────────────────────────────────────────────────────────────────

function TuplesTab({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [filter, setFilter] = useState<TupleKey>({ user: '', relation: '', object: '' })
  const [applied, setApplied] = useState<TupleKey>({ user: '', relation: '', object: '' })
  const [contToken, setContToken] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const [newTuple, setNewTuple] = useState<TupleKey>({ user: '', relation: '', object: '' })

  const params = new URLSearchParams()
  if (applied.user)     params.set('user',     applied.user)
  if (applied.relation) params.set('relation', applied.relation)
  if (applied.object)   params.set('object',   applied.object)
  if (contToken)        params.set('continuation_token', contToken)
  params.set('page_size', '50')

  const { data, isLoading, refetch } = useQuery<ReadResponse>({
    queryKey: ['fga-tuples', orgId, applied, contToken],
    queryFn: () => api.get(`/organizations/${orgId}/fga/read?${params}`).then(r => r.data),
    retry: (count, err: unknown) => {
      const status = (err as { response?: { status: number } })?.response?.status
      if (status === 404 || status === 409) return false
      return count < 2
    },
  })

  const writeTuples = useMutation({
    mutationFn: (payload: { writes?: TupleKey[]; deletes?: TupleKey[] }) =>
      api.post(`/organizations/${orgId}/fga/write`, payload),
    onSuccess: () => {
      toast.success('Tuples updated')
      setAdding(false)
      setNewTuple({ user: '', relation: '', object: '' })
      qc.invalidateQueries({ queryKey: ['fga-tuples', orgId] })
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg ?? 'Write failed')
    },
  })

  const handleAdd = () => {
    if (!newTuple.user || !newTuple.relation || !newTuple.object) {
      toast.error('All three fields are required')
      return
    }
    writeTuples.mutate({ writes: [newTuple] })
  }

  const handleDelete = (t: TupleKey) => {
    if (!confirm(`Delete tuple?\n${t.user} → ${t.relation} → ${t.object}`)) return
    writeTuples.mutate({ deletes: [t] })
  }

  const tuples = data?.tuples ?? []

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div style={{ ...card }}>
        <p style={{ fontWeight: 600, fontSize: 13, color: 'var(--clavex-ink)', marginBottom: 12 }}>Filter</p>
        <div className="grid grid-cols-3 gap-3">
          {(['user', 'relation', 'object'] as const).map(field => (
            <div key={field}>
              <label style={lbl}>{field}</label>
              <input
                style={inp}
                placeholder={field === 'user' ? 'user:01925f3a-…' : field === 'object' ? 'document:budget-Q1' : 'can_read'}
                value={filter[field]}
                onChange={e => setFilter(f => ({ ...f, [field]: e.target.value }))}
                onKeyDown={e => { if (e.key === 'Enter') { setApplied(filter); setContToken(null) } }}
              />
            </div>
          ))}
        </div>
        <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
          <button style={btn('primary')} onClick={() => { setApplied(filter); setContToken(null) }}>
            <Play size={13} /> Apply Filter
          </button>
          <button style={btn('ghost')} onClick={() => { const e = { user: '', relation: '', object: '' }; setFilter(e); setApplied(e); setContToken(null) }}>
            Clear
          </button>
          <button style={{ ...btn('ghost'), marginLeft: 'auto' }} onClick={() => { void refetch() }}>
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {/* Add tuple */}
      {adding ? (
        <div style={{ ...card, borderColor: 'var(--clavex-primary)' }} className="space-y-3">
          <p style={{ fontWeight: 600, fontSize: 13, color: 'var(--clavex-ink)' }}>Add Relationship Tuple</p>
          <div className="grid grid-cols-3 gap-3">
            {(['user', 'relation', 'object'] as const).map(field => (
              <div key={field}>
                <label style={lbl}>{field}</label>
                <input
                  style={inp}
                  placeholder={field === 'user' ? 'user:uuid' : field === 'object' ? 'document:name' : 'relation_name'}
                  value={newTuple[field]}
                  onChange={e => setNewTuple(t => ({ ...t, [field]: e.target.value }))}
                />
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button style={btn('ghost')} onClick={() => setAdding(false)}>Cancel</button>
            <button style={btn('primary')} onClick={handleAdd} disabled={writeTuples.isPending}>
              {writeTuples.isPending ? <Loader2 size={14} className="animate-spin" /> : <Plus size={13} />}
              Write Tuple
            </button>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button style={btn('primary')} onClick={() => setAdding(true)}>
            <Plus size={13} /> Add Tuple
          </button>
        </div>
      )}

      {/* Tuples table */}
      <div style={{ ...card, padding: 0, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: 'var(--clavex-surface)' }}>
              {['User', 'Relation', 'Object', ''].map(h => (
                <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--clavex-ink-muted)', borderBottom: '0.5px solid var(--clavex-border)' }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={4} style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--clavex-ink-muted)' }}>Loading…</td></tr>
            )}
            {!isLoading && tuples.length === 0 && (
              <tr><td colSpan={4} style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--clavex-ink-muted)' }}>No tuples found.</td></tr>
            )}
            {tuples.map((t, i) => (
              <tr key={i} style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 12, color: 'var(--clavex-ink)' }}>{t.user}</td>
                <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 12, color: '#0369a1' }}>{t.relation}</td>
                <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 12, color: 'var(--clavex-ink)' }}>{t.object}</td>
                <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                  <button
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444', padding: 4 }}
                    onClick={() => handleDelete(t)}
                    title="Delete tuple"
                  >
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {(data?.continuation_token || contToken) && (
          <div style={{ padding: '10px 16px', borderTop: '0.5px solid var(--clavex-border)', display: 'flex', gap: 8 }}>
            {contToken && (
              <button style={btn('ghost')} onClick={() => setContToken(null)}>← First page</button>
            )}
            {data?.continuation_token && (
              <button style={{ ...btn('ghost'), marginLeft: 'auto' }} onClick={() => setContToken(data.continuation_token)}>
                Next page →
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Check Tab ─────────────────────────────────────────────────────────────────

function CheckTab({ orgId }: { orgId: string }) {
  const [form, setForm] = useState<TupleKey>({ user: '', relation: '', object: '' })
  const [result, setResult] = useState<boolean | null>(null)
  const [checking, setChecking] = useState(false)

  const check = async () => {
    if (!form.user || !form.relation || !form.object) {
      toast.error('All three fields are required')
      return
    }
    setChecking(true)
    setResult(null)
    try {
      const res = await api.post<{ allowed: boolean }>(`/organizations/${orgId}/fga/check`, form)
      setResult(res.data.allowed)
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg ?? 'Check failed')
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className="space-y-4" style={{ maxWidth: 560 }}>
      <div style={card} className="space-y-4">
        <p style={{ fontWeight: 600, fontSize: 14, color: 'var(--clavex-ink)', marginBottom: 4 }}>
          Relationship Check
        </p>
        <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', lineHeight: 1.6 }}>
          Ask: <em>Does <strong>user</strong> have <strong>relation</strong> on <strong>object</strong>?</em>
        </p>
        {(['user', 'relation', 'object'] as const).map(field => (
          <div key={field}>
            <label style={lbl}>{field}</label>
            <input
              style={inp}
              placeholder={field === 'user' ? 'user:01925f3a-…' : field === 'object' ? 'document:budget-Q1' : 'can_read'}
              value={form[field]}
              onChange={e => setForm(f => ({ ...f, [field]: e.target.value }))}
            />
          </div>
        ))}
        <button style={btn('primary')} onClick={check} disabled={checking}>
          {checking ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
          Run Check
        </button>
      </div>

      {result !== null && (
        <div style={{
          ...card,
          borderColor: result ? '#22c55e' : '#ef4444',
          background: result ? '#f0fdf4' : '#fef2f2',
          textAlign: 'center',
          padding: '28px 24px',
        }}>
          {result
            ? <CheckCircle size={36} style={{ color: '#22c55e', margin: '0 auto 10px' }} />
            : <XCircle    size={36} style={{ color: '#ef4444', margin: '0 auto 10px' }} />
          }
          <p style={{ fontWeight: 700, fontSize: 18, color: result ? '#166534' : '#991b1b' }}>
            {result ? 'ALLOWED' : 'DENIED'}
          </p>
          <p style={{ fontSize: 13, color: result ? '#15803d' : '#b91c1c', marginTop: 6 }}>
            {form.user} <strong>{result ? 'has' : 'does not have'}</strong> {form.relation} on {form.object}
          </p>
        </div>
      )}

      <div style={{ ...card, background: '#f8fafc' }}>
        <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
          Format reference
        </p>
        {[
          { field: 'user',     example: 'user:01925f3a-4e2b-7000-b8c0-123456789abc' },
          { field: 'relation', example: 'can_read  |  editor  |  member' },
          { field: 'object',   example: 'document:budget-Q1  |  folder:home' },
        ].map(({ field, example }) => (
          <div key={field} style={{ marginBottom: 6 }}>
            <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--clavex-ink)', fontWeight: 600 }}>{field}:</span>
            <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--clavex-ink-muted)', marginLeft: 8 }}>{example}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function FGAPage() {
  const { orgId } = useAuthStore()
  const [tab, setTab] = useState<Tab>('store')

  if (!orgId) return null

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <GitBranch size={20} style={{ color: 'var(--clavex-primary)' }} />
          <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--clavex-ink)', margin: 0 }}>
            Fine-Grained Authorization
          </h1>
        </div>
        <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', margin: 0, lineHeight: 1.6 }}>
          Zanzibar-style ReBAC (OpenFGA) — one isolated store per organization.
          Define a type system, write relationship tuples, and evaluate authorization checks.
        </p>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 24, borderBottom: '0.5px solid var(--clavex-border)', paddingBottom: 0 }}>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              padding: '8px 16px',
              fontSize: 13,
              fontWeight: tab === t.id ? 700 : 500,
              color: tab === t.id ? 'var(--clavex-primary)' : 'var(--clavex-ink-muted)',
              background: 'none',
              border: 'none',
              borderBottom: tab === t.id ? '2px solid var(--clavex-primary)' : '2px solid transparent',
              cursor: 'pointer',
              marginBottom: -1,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'store'     && <StoreTab     orgId={orgId} />}
      {tab === 'model'     && <ModelTab     orgId={orgId} />}
      {tab === 'templates' && <TemplatesTab orgId={orgId} />}
      {tab === 'tuples'    && <TuplesTab    orgId={orgId} />}
      {tab === 'check'     && <CheckTab     orgId={orgId} />}
    </div>
  )
}
