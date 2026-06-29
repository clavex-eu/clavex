import { useState, CSSProperties } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  Sparkles, Loader2, Plus, Trash2, Copy, CheckCircle2,
  ChevronDown, ChevronUp, ArrowRight, ExternalLink,
  Shield, AlertTriangle, FileCode, BookOpen, Cpu,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SchemaField {
  name: string
  label: string
  type: 'string' | 'date' | 'number' | 'url'
  mandatory: boolean
}

interface GeneratedSchema {
  vct: string
  display_name: string
  description: string
  category: 'identity' | 'training' | 'qualification' | 'badge'
  credential_format: 'vc+sd-jwt' | 'mso_mdoc'
  ttl_seconds: number
  selective_disclosure: boolean
  source_idp_type: string | null
  schema_fields: SchemaField[]
  claims_mapping: Record<string, string>
  adaptive_ttl: boolean
  min_ttl_seconds: number
  max_ttl_seconds: number
  renewal_threshold: number
  inactivity_revoke_days: number
  dcql_query: unknown
  sd_policy: string
  gdpr_notes: string
  wallet_dev_docs: string
  rationale: string
  raw?: string
  error?: string
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const mono: CSSProperties = { fontFamily: "'IBM Plex Mono', monospace" }

const card = (extra?: CSSProperties): CSSProperties => ({
  background: 'var(--clavex-panel)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: 20,
  ...extra,
})

const fieldLabel: CSSProperties = {
  display: 'block', fontSize: 11, fontWeight: 700,
  letterSpacing: '0.08em', textTransform: 'uppercase',
  color: 'var(--clavex-neutral)', marginBottom: 6,
}

const inp: CSSProperties = {
  width: '100%', fontSize: 13, padding: '8px 12px',
  border: '0.5px solid var(--clavex-border)', borderRadius: 8,
  outline: 'none', boxSizing: 'border-box',
  color: 'var(--clavex-text)', background: 'var(--clavex-surface)',
}

const selectStyle: CSSProperties = { ...inp, cursor: 'pointer' }

// ── Helpers ───────────────────────────────────────────────────────────────────

function ttlLabel(secs: number): string {
  if (secs <= 0) return '—'
  const days = Math.round(secs / 86400)
  if (days < 30) return `${days} giorni`
  const months = Math.round(days / 30)
  if (months < 12) return `${months} mesi`
  const years = Math.round(days / 365)
  return `${years} ann${years === 1 ? 'o' : 'i'}`
}

function categoryColor(cat: string) {
  const map: Record<string, { bg: string; color: string }> = {
    identity:      { bg: '#5dcaa518', color: 'var(--clavex-primary)' },
    training:      { bg: '#3b82f618', color: '#3b82f6' },
    qualification: { bg: '#8b5cf618', color: '#8b5cf6' },
    badge:         { bg: '#f59e0b18', color: '#d97706' },
  }
  return map[cat] ?? { bg: '#6b728018', color: '#6b7280' }
}

// ── Section accordion ─────────────────────────────────────────────────────────

function Section({ title, icon: Icon, accent, children, defaultOpen = true }: {
  title: string
  icon: React.ElementType
  accent?: string
  children: React.ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div style={card()}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 10, width: '100%',
          background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginBottom: open ? 16 : 0,
        }}
      >
        <div style={{
          width: 32, height: 32, borderRadius: 8, flexShrink: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: accent ? `${accent}18` : 'var(--clavex-surface)',
        }}>
          <Icon size={15} color={accent ?? 'var(--clavex-neutral)'} />
        </div>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 700, color: 'var(--clavex-ink)', textAlign: 'left' }}>{title}</span>
        {open ? <ChevronUp size={14} color="var(--clavex-neutral)" /> : <ChevronDown size={14} color="var(--clavex-neutral)" />}
      </button>
      {open && children}
    </div>
  )
}

// ── CodeBlock ─────────────────────────────────────────────────────────────────

function CodeBlock({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div style={{ position: 'relative' }}>
      <pre style={{
        ...mono, fontSize: 11, lineHeight: 1.6,
        background: '#0D1F2D', color: '#C4DFF0',
        borderRadius: 8, padding: '12px 14px',
        overflowX: 'auto', whiteSpace: 'pre-wrap', maxHeight: 300, overflowY: 'auto',
        margin: 0,
      }}>{value}</pre>
      <button
        onClick={copy}
        style={{
          position: 'absolute', top: 8, right: 8,
          background: copied ? '#16a34a' : 'rgba(255,255,255,0.1)',
          border: 'none', borderRadius: 6, padding: '4px 8px',
          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
          fontSize: 10, fontWeight: 600, color: '#fff',
        }}
      >
        {copied ? <CheckCircle2 size={11} /> : <Copy size={11} />}
        {copied ? 'Copiato' : 'Copia'}
      </button>
    </div>
  )
}

// ── Schema fields editor ──────────────────────────────────────────────────────

function SchemaFieldsEditor({ fields, onChange }: {
  fields: SchemaField[]
  onChange: (fields: SchemaField[]) => void
}) {
  const update = (i: number, patch: Partial<SchemaField>) => {
    const next = [...fields]
    next[i] = { ...next[i], ...patch }
    onChange(next)
  }
  const remove = (i: number) => onChange(fields.filter((_, j) => j !== i))
  const add = () => onChange([...fields, { name: '', label: '', type: 'string', mandatory: false }])

  return (
    <div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {/* Header */}
        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 1fr 90px 80px 32px',
          gap: 8, padding: '0 8px',
        }}>
          {['Nome (snake_case)', 'Label', 'Tipo', 'Obbligatorio', ''].map(h => (
            <span key={h} style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '0.07em', color: 'var(--clavex-neutral)' }}>{h}</span>
          ))}
        </div>

        {fields.map((f, i) => (
          <div key={i} style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr 90px 80px 32px',
            gap: 8, alignItems: 'center',
            background: 'var(--clavex-surface)', borderRadius: 8, padding: '8px',
            border: '0.5px solid var(--clavex-border)',
          }}>
            <input
              value={f.name} onChange={e => update(i, { name: e.target.value })}
              placeholder="field_name"
              style={{ ...inp, ...mono, fontSize: 11 }}
            />
            <input
              value={f.label} onChange={e => update(i, { label: e.target.value })}
              placeholder="Etichetta"
              style={inp}
            />
            <select value={f.type} onChange={e => update(i, { type: e.target.value as SchemaField['type'] })}
              style={selectStyle}>
              {['string', 'date', 'number', 'url'].map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
            <div style={{ display: 'flex', justifyContent: 'center' }}>
              <input type="checkbox" checked={f.mandatory}
                onChange={e => update(i, { mandatory: e.target.checked })}
                style={{ width: 16, height: 16, cursor: 'pointer' }} />
            </div>
            <button onClick={() => remove(i)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--clavex-neutral)', padding: 4,
            }}>
              <Trash2 size={13} />
            </button>
          </div>
        ))}
      </div>
      <button
        onClick={add}
        style={{
          marginTop: 10, display: 'inline-flex', alignItems: 'center', gap: 6,
          fontSize: 12, fontWeight: 600, color: 'var(--clavex-primary)',
          background: 'none', border: '0.5px dashed var(--clavex-primary)', borderRadius: 8,
          padding: '6px 12px', cursor: 'pointer', opacity: 0.8,
        }}
      >
        <Plus size={12} /> Aggiungi campo
      </button>
    </div>
  )
}

// ── Claims mapping editor ─────────────────────────────────────────────────────

function ClaimsMappingEditor({ mapping, onChange }: {
  mapping: Record<string, string>
  onChange: (m: Record<string, string>) => void
}) {
  const entries = Object.entries(mapping)
  const update = (oldKey: string, key: string, value: string) => {
    const next: Record<string, string> = {}
    for (const [k, v] of Object.entries(mapping)) {
      if (k === oldKey) next[key || k] = value
      else next[k] = v
    }
    onChange(next)
  }

  if (entries.length === 0) {
    return (
      <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', fontStyle: 'italic' }}>
        Nessun mapping — i valori saranno inseriti manualmente durante l'emissione.
      </p>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, padding: '0 8px' }}>
        <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--clavex-neutral)' }}>
          Campo credenziale
        </span>
        <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--clavex-neutral)' }}>
          Attributo SPID/CIE
        </span>
      </div>
      {entries.map(([k, v]) => (
        <div key={k} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <input value={k}
            onChange={e => update(k, e.target.value, v)}
            style={{ ...inp, ...mono, fontSize: 11 }}
          />
          <input value={v}
            onChange={e => update(k, k, e.target.value)}
            style={{ ...inp, ...mono, fontSize: 11 }}
          />
        </div>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CredentialSchemaGenerator() {
  const orgId   = useAuthStore(s => s.orgId)
  const orgSlug = useAuthStore(s => s.orgSlug)

  // Phase: 'input' → 'review' → 'done'
  const [phase,   setPhase]   = useState<'input' | 'review' | 'done'>('input')
  const [loading, setLoading] = useState(false)
  const [desc,    setDesc]    = useState('')
  const [lang,    setLang]    = useState('it')
  const [schema,  setSchema]  = useState<GeneratedSchema | null>(null)
  const [createdID, setCreatedID] = useState<string | null>(null)
  const [creating, setCreating]   = useState(false)

  // ── Step 1: generate ──────────────────────────────────────────────────────

  async function generate() {
    if (!desc.trim()) { toast.error('Descrivi il tipo di credenziale'); return }
    setLoading(true)
    try {
      const res = await api.post<GeneratedSchema>(
        `/organizations/${orgId}/ai/suggest-credential-schema`,
        { description: desc, lang }
      )
      setSchema(res.data)
      setPhase('review')
    } catch (e: unknown) {
      const err = e as { response?: { data?: { message?: string } } }
      toast.error(err?.response?.data?.message ?? 'Generazione fallita')
    } finally {
      setLoading(false)
    }
  }

  // ── Step 2: create ────────────────────────────────────────────────────────

  async function createConfig() {
    if (!schema) return
    setCreating(true)
    try {
      // Step A: create base config
      const createRes = await api.post<{ id: string }>(
        `/organizations/${orgId}/oid4vci/configs`,
        {
          vct:           schema.vct,
          display_name:  schema.display_name,
          description:   schema.description || undefined,
          claims_mapping: schema.claims_mapping,
          ttl_seconds:   schema.ttl_seconds,
          category:      schema.category,
          schema_fields: schema.schema_fields,
        }
      )
      const configId = createRes.data.id

      // Step B: patch selective_disclosure + source_idp_type
      if (schema.selective_disclosure !== undefined || schema.source_idp_type !== undefined) {
        await api.patch(`/organizations/${orgId}/oid4vci/configs/${configId}`, {
          selective_disclosure: schema.selective_disclosure ?? true,
          source_idp_type:      schema.source_idp_type ?? null,
        })
      }

      setCreatedID(configId)
      setPhase('done')
      toast.success('Tipo credenziale creato!')
    } catch (e: unknown) {
      const err = e as { response?: { data?: { message?: string } } }
      toast.error(err?.response?.data?.message ?? 'Creazione fallita')
    } finally {
      setCreating(false)
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div style={{ maxWidth: 860, margin: '0 auto' }}>

      {/* ── Header ── */}
      <div style={{ marginBottom: 28 }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: 8,
          background: 'linear-gradient(135deg, #5dcaa518, #8b5cf618)',
          border: '0.5px solid rgba(93,202,165,0.3)',
          borderRadius: 8, padding: '4px 12px', marginBottom: 12,
        }}>
          <Cpu size={13} color="var(--clavex-primary)" />
          <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, fontWeight: 700,
            textTransform: 'uppercase', letterSpacing: '0.15em', color: 'var(--clavex-primary)' }}>
            AI Schema Designer
          </span>
        </div>
        <h1 style={{ fontSize: 24, fontWeight: 300, color: 'var(--clavex-ink)', letterSpacing: '-0.02em', margin: 0 }}>
          Credential <strong style={{ fontWeight: 700 }}>Schema Generator</strong>
        </h1>
        <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginTop: 6 }}>
          Descrivi la credenziale che vuoi emettere — l'AI genera schema SD-JWT, mapping SPID/CIE,
          policy di selective disclosure, DCQL query e documentazione wallet in pochi secondi.
        </p>
      </div>

      {/* ── Progress stepper ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 28 }}>
        {[
          { n: 1, label: 'Descrivi' },
          { n: 2, label: 'Rivedi' },
          { n: 3, label: 'Crea' },
        ].map((s, i) => {
          const active = (phase === 'input' && s.n === 1) || (phase === 'review' && s.n === 2) || (phase === 'done' && s.n === 3)
          const done   = (phase === 'review' && s.n === 1) || (phase === 'done' && s.n <= 2)
          return (
            <div key={s.n} style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{
                  width: 28, height: 28, borderRadius: '50%',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 12, fontWeight: 700,
                  background: done ? 'var(--clavex-primary)' : active ? 'var(--clavex-primary)' : 'var(--clavex-surface)',
                  color: (done || active) ? '#fff' : 'var(--clavex-neutral)',
                  border: `0.5px solid ${(done || active) ? 'var(--clavex-primary)' : 'var(--clavex-border)'}`,
                }}>
                  {done ? <CheckCircle2 size={13} /> : s.n}
                </div>
                <span style={{ fontSize: 12, fontWeight: 600,
                  color: active ? 'var(--clavex-ink)' : 'var(--clavex-neutral)' }}>
                  {s.label}
                </span>
              </div>
              {i < 2 && (
                <div style={{ width: 40, height: 1, background: 'var(--clavex-border)', margin: '0 12px' }} />
              )}
            </div>
          )
        })}
      </div>

      {/* ════════════════════════════════════════════════════════════
          PHASE 1 — Input
      ════════════════════════════════════════════════════════════ */}
      {phase === 'input' && (
        <div style={card()}>
          <div style={{ marginBottom: 16 }}>
            <label style={fieldLabel}>Descrivi la credenziale</label>
            <textarea
              value={desc}
              onChange={e => setDesc(e.target.value)}
              placeholder={
                'Esempi:\n' +
                '• "Certificato di idoneità sportiva per atleti minorenni"\n' +
                '• "Attestato di completamento corso antincendio"\n' +
                '• "Licenza professionale per avvocati iscritti all\'Ordine"\n' +
                '• "Badge di partecipazione alla conferenza ForumPA 2026"'
              }
              rows={6}
              style={{
                ...inp, fontFamily: 'inherit', fontSize: 14, lineHeight: 1.6,
                resize: 'vertical', minHeight: 140,
              }}
              onKeyDown={e => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) generate()
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <label style={fieldLabel}>Lingua output</label>
              <select value={lang} onChange={e => setLang(e.target.value)} style={{ ...selectStyle, width: 'auto' }}>
                <option value="it">Italiano</option>
                <option value="en">English</option>
                <option value="de">Deutsch</option>
                <option value="fr">Français</option>
                <option value="es">Español</option>
              </select>
            </div>
            <div style={{ alignSelf: 'flex-end' }}>
              <button
                onClick={generate}
                disabled={loading || !desc.trim()}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 8,
                  padding: '10px 22px', fontSize: 14, fontWeight: 600,
                  borderRadius: 8, border: 'none', cursor: loading ? 'not-allowed' : 'pointer',
                  background: 'var(--clavex-primary)', color: '#fff',
                  opacity: loading || !desc.trim() ? 0.6 : 1,
                }}
              >
                {loading
                  ? <><Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> Generazione…</>
                  : <><Sparkles size={16} /> Genera Schema</>
                }
              </button>
            </div>
          </div>

          <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 10 }}>
            Suggerimento: ⌘↵ / Ctrl↵ per generare. L'AI applica automaticamente
            GDPR Art.5(1)(c) minimisation e le linee guida EUDIW ARF.
          </p>
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════
          PHASE 2 — Review & Edit
      ════════════════════════════════════════════════════════════ */}
      {phase === 'review' && schema && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Error fallback */}
          {schema.error && (
            <div style={{ background: '#fef2f2', border: '0.5px solid #fca5a5', borderRadius: 10, padding: '12px 16px' }}>
              <p style={{ fontSize: 12, color: '#dc2626', margin: 0 }}>
                ⚠ {schema.error}
              </p>
              <pre style={{ ...mono, fontSize: 11, color: '#dc2626', marginTop: 8, whiteSpace: 'pre-wrap' }}>
                {schema.raw}
              </pre>
            </div>
          )}

          {/* ── Rationale banner ── */}
          {schema.rationale && (
            <div style={{
              display: 'flex', gap: 12, padding: '12px 16px',
              background: 'linear-gradient(135deg, #5dcaa508, #8b5cf508)',
              border: '0.5px solid rgba(93,202,165,0.3)', borderRadius: 10,
            }}>
              <Sparkles size={16} color="var(--clavex-primary)" style={{ flexShrink: 0, marginTop: 1 }} />
              <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: 0, lineHeight: 1.6 }}>
                {schema.rationale}
              </p>
            </div>
          )}

          {/* ── 1. Basic info ── */}
          <Section title="Informazioni di base" icon={FileCode} accent="var(--clavex-primary)">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>

              <div style={{ gridColumn: '1 / -1' }}>
                <label style={fieldLabel}>VCT — Verifiable Credential Type URI</label>
                <input value={schema.vct}
                  onChange={e => setSchema(s => s && { ...s, vct: e.target.value })}
                  style={{ ...inp, ...mono, fontSize: 11 }} />
                <p style={{ fontSize: 10, color: 'var(--clavex-neutral)', marginTop: 4 }}>
                  Sostituisci <code style={mono}>{'{issuer}'}</code> con il tuo dominio.
                </p>
              </div>

              <div>
                <label style={fieldLabel}>Nome visualizzato</label>
                <input value={schema.display_name}
                  onChange={e => setSchema(s => s && { ...s, display_name: e.target.value })}
                  style={inp} />
              </div>

              <div>
                <label style={fieldLabel}>Categoria</label>
                <select value={schema.category}
                  onChange={e => setSchema(s => s && { ...s, category: e.target.value as GeneratedSchema['category'] })}
                  style={selectStyle}>
                  {['identity', 'training', 'qualification', 'badge'].map(c => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
              </div>

              <div style={{ gridColumn: '1 / -1' }}>
                <label style={fieldLabel}>Descrizione</label>
                <input value={schema.description ?? ''}
                  onChange={e => setSchema(s => s && { ...s, description: e.target.value })}
                  style={inp} />
              </div>

              <div>
                <label style={fieldLabel}>Formato</label>
                <select value={schema.credential_format}
                  onChange={e => setSchema(s => s && { ...s, credential_format: e.target.value as GeneratedSchema['credential_format'] })}
                  style={selectStyle}>
                  <option value="vc+sd-jwt">vc+sd-jwt (SD-JWT-VC)</option>
                  <option value="mso_mdoc">mso_mdoc (ISO 18013-5)</option>
                </select>
              </div>

              <div>
                <label style={fieldLabel}>Durata (TTL)</label>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input type="number" value={schema.ttl_seconds}
                    onChange={e => setSchema(s => s && { ...s, ttl_seconds: parseInt(e.target.value) || 0 })}
                    style={{ ...inp, flex: 1 }} />
                  <span style={{ fontSize: 12, color: 'var(--clavex-neutral)', whiteSpace: 'nowrap' }}>
                    = {ttlLabel(schema.ttl_seconds)}
                  </span>
                </div>
              </div>

              <div>
                <label style={fieldLabel}>IdP sorgente</label>
                <select value={schema.source_idp_type ?? ''}
                  onChange={e => setSchema(s => s && { ...s, source_idp_type: e.target.value || null })}
                  style={selectStyle}>
                  <option value="">Nessuno (emissione manuale)</option>
                  <option value="spid">SPID</option>
                  <option value="cie">CIE 3.0</option>
                  <option value="itsme">itsme</option>
                  <option value="franceconnect">FranceConnect</option>
                </select>
              </div>

              <div>
                <label style={fieldLabel}>Selective Disclosure</label>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 6 }}>
                  <input type="checkbox" checked={schema.selective_disclosure}
                    onChange={e => setSchema(s => s && { ...s, selective_disclosure: e.target.checked })}
                    style={{ width: 16, height: 16 }} />
                  <span style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>
                    Ogni claim è divulgato separatamente (SD-JWT-VC §4.1)
                  </span>
                </div>
              </div>

              {/* Category badge */}
              <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{
                  ...categoryColor(schema.category),
                  padding: '3px 10px', borderRadius: 99, fontSize: 11, fontWeight: 700,
                  background: categoryColor(schema.category).bg,
                  color: categoryColor(schema.category).color,
                }}>
                  {schema.category}
                </span>
                <span style={{ ...mono, fontSize: 11, color: 'var(--clavex-neutral)' }}>
                  {schema.credential_format}
                </span>
              </div>
            </div>
          </Section>

          {/* ── 2. Schema fields ── */}
          <Section title="Campi dello schema" icon={FileCode} accent="#3b82f6">
            <SchemaFieldsEditor
              fields={schema.schema_fields}
              onChange={fields => setSchema(s => s && { ...s, schema_fields: fields })}
            />
          </Section>

          {/* ── 3. SPID/CIE mapping ── */}
          <Section title="Mapping SPID / CIE" icon={Cpu} accent="#8b5cf6">
            <ClaimsMappingEditor
              mapping={schema.claims_mapping}
              onChange={mapping => setSchema(s => s && { ...s, claims_mapping: mapping })}
            />
            <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 10 }}>
              I claim mappati vengono popolati automaticamente dagli attributi IdP al login.
              I claim con valore <code style={mono}>manual</code> sono inseriti dall'operatore durante l'emissione.
            </p>
          </Section>

          {/* ── 4. Privacy & disclosure ── */}
          <Section title="Privacy & Selective Disclosure" icon={Shield} accent="#16a34a" defaultOpen={false}>
            {schema.sd_policy && (
              <div style={{ marginBottom: 14 }}>
                <label style={fieldLabel}>SD Policy</label>
                <textarea value={schema.sd_policy}
                  onChange={e => setSchema(s => s && { ...s, sd_policy: e.target.value })}
                  rows={4}
                  style={{ ...inp, fontFamily: 'inherit', resize: 'vertical' }}
                />
              </div>
            )}
            {schema.gdpr_notes && (
              <div style={{
                display: 'flex', gap: 10, padding: '10px 14px',
                background: '#fef3c720', border: '0.5px solid #f59e0b60',
                borderRadius: 8,
              }}>
                <AlertTriangle size={14} color="#d97706" style={{ flexShrink: 0, marginTop: 1 }} />
                <div>
                  <p style={{ fontSize: 11, fontWeight: 700, color: '#92400e', margin: '0 0 4px', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    GDPR Art.5(1)(c) — Note
                  </p>
                  <p style={{ fontSize: 12, color: '#78350f', margin: 0, lineHeight: 1.6 }}>
                    {schema.gdpr_notes}
                  </p>
                </div>
              </div>
            )}
          </Section>

          {/* ── 5. DCQL query ── */}
          <Section title="DCQL Query — per i verifier" icon={FileCode} accent="#0ea5e9" defaultOpen={false}>
            <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginBottom: 10 }}>
              Da includere nel wallet verifier per richiedere questa credenziale agli utenti.
            </p>
            <CodeBlock value={JSON.stringify(schema.dcql_query, null, 2)} />
          </Section>

          {/* ── 6. Wallet dev docs ── */}
          <Section title="Documentazione Wallet Developer" icon={BookOpen} accent="#f59e0b" defaultOpen={false}>
            <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginBottom: 10 }}>
              Markdown da distribuire agli sviluppatori di wallet che integrano questo tipo di credenziale.
            </p>
            <CodeBlock value={schema.wallet_dev_docs ?? ''} />
          </Section>

          {/* ── 7. Adaptive TTL ── */}
          {schema.adaptive_ttl && (
            <Section title="Adaptive TTL — rinnovio automatico" icon={Shield} accent="#5dcaa5" defaultOpen={false}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                {[
                  { label: 'Min TTL', key: 'min_ttl_seconds' as const, hint: ttlLabel(schema.min_ttl_seconds) },
                  { label: 'Max TTL', key: 'max_ttl_seconds' as const, hint: ttlLabel(schema.max_ttl_seconds) },
                  { label: 'Renewal threshold', key: 'renewal_threshold' as const, hint: `${(schema.renewal_threshold * 100).toFixed(0)}% del TTL` },
                  { label: 'Inactivity revoke (giorni)', key: 'inactivity_revoke_days' as const, hint: '' },
                ].map(({ label, key, hint }) => (
                  <div key={key}>
                    <label style={fieldLabel}>{label}</label>
                    <input type="number" value={schema[key] as number}
                      onChange={e => setSchema(s => s && { ...s, [key]: parseFloat(e.target.value) || 0 })}
                      step={key === 'renewal_threshold' ? 0.05 : 1}
                      min={0} max={key === 'renewal_threshold' ? 1 : undefined}
                      style={inp}
                    />
                    {hint && <p style={{ fontSize: 10, color: 'var(--clavex-neutral)', marginTop: 3 }}>{hint}</p>}
                  </div>
                ))}
              </div>
              <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 12 }}>
                Adaptive TTL verrà configurato separatamente via PATCH dopo la creazione.
              </p>
            </Section>
          )}

          {/* ── Action bar ── */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 12,
            padding: '16px 20px', background: 'var(--clavex-panel)',
            border: '0.5px solid var(--clavex-border)', borderRadius: 12,
          }}>
            <button
              onClick={() => setPhase('input')}
              style={{
                background: 'none', border: '0.5px solid var(--clavex-border)', borderRadius: 8,
                padding: '9px 18px', fontSize: 13, fontWeight: 600,
                cursor: 'pointer', color: 'var(--clavex-neutral)',
              }}
            >
              ← Rigenera
            </button>
            <div style={{ flex: 1 }} />
            <button
              onClick={createConfig}
              disabled={creating || !!schema.error}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 8,
                padding: '10px 24px', fontSize: 14, fontWeight: 700,
                borderRadius: 8, border: 'none',
                background: 'var(--clavex-primary)', color: '#fff',
                cursor: creating || schema.error ? 'not-allowed' : 'pointer',
                opacity: creating || schema.error ? 0.6 : 1,
              }}
            >
              {creating
                ? <><Loader2 size={15} style={{ animation: 'spin 1s linear infinite' }} /> Creazione…</>
                : <><ArrowRight size={15} /> Crea tipo credenziale</>
              }
            </button>
          </div>
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════
          PHASE 3 — Done
      ════════════════════════════════════════════════════════════ */}
      {phase === 'done' && schema && (
        <div style={{
          ...card(),
          textAlign: 'center', padding: 48,
          background: 'rgba(22,163,74,0.04)',
          border: '0.5px solid rgba(22,163,74,0.3)',
        }}>
          <div style={{
            width: 64, height: 64, borderRadius: '50%',
            background: 'rgba(22,163,74,0.12)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            margin: '0 auto 20px',
          }}>
            <CheckCircle2 size={32} color="#16a34a" />
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: 'var(--clavex-ink)', margin: '0 0 10px' }}>
            {schema.display_name} creato!
          </h2>
          <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', maxWidth: 440, margin: '0 auto 24px' }}>
            Il tipo credenziale è attivo e pronto per l'emissione. Puoi configurare il webhook
            di pre-issuance e le opzioni avanzate dalla pagina Credenziali Verificabili.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a
              href={`/app/${orgSlug}/verified-credentials`}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 7,
                padding: '9px 20px', fontSize: 13, fontWeight: 600,
                borderRadius: 8, background: 'var(--clavex-primary)', color: '#fff',
                textDecoration: 'none',
              }}
            >
              <ExternalLink size={14} /> Vai a Credenziali Verificabili
            </a>
            <button
              onClick={() => { setPhase('input'); setSchema(null); setDesc('') }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 7,
                padding: '9px 20px', fontSize: 13, fontWeight: 600,
                borderRadius: 8, background: 'none',
                border: '0.5px solid var(--clavex-border)', color: 'var(--clavex-neutral)',
                cursor: 'pointer',
              }}
            >
              <Plus size={14} /> Crea un altro schema
            </button>
          </div>
          {createdID && (
            <p style={{ ...mono, fontSize: 10, color: 'var(--clavex-neutral)', marginTop: 20 }}>
              config_id: {createdID}
            </p>
          )}
        </div>
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
