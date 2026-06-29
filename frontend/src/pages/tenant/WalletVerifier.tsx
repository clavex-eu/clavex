import { useState, useEffect, useRef, useCallback, useMemo, CSSProperties } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  QrCode, CheckCircle2, XCircle, Clock, RefreshCw, ChevronDown,
  ChevronUp, Shield, User, CreditCard, CalendarDays, Hash,
  Fingerprint, Globe, Loader2, ScanLine, History, Plus, Copy,
  UploadCloud, FileDown, Layers, AlertTriangle,
} from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import { Button } from '@/components/ui'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Session {
  id: string
  org_id: string
  request_id: string
  status: 'pending' | 'verified' | 'failed'
  vp_claims?: Record<string, unknown>
  created_at: string
  expires_at: string
}

interface CreateSessionResp {
  request_uri: string
  request_id: string
  expires_at: string
  nonce: string
  authorization_url?: string
  gdpr_warnings?: GDPRWarning[]
}

interface GDPRWarning {
  claim_path: string
  sensitivity: 'low' | 'medium' | 'high'
  article: string
  message: string
  alternative?: string
}

// ── Credential type presets ────────────────────────────────────────────────────

const PRESETS = [
  {
    id: 'pid',
    label: 'PID — Person Identification',
    icon: '🪪',
    description: 'Name, date of birth, tax ID (codice fiscale), nationality',
    definition: {
      id: 'pid-request',
      input_descriptors: [{
        id: 'pid',
        name: 'Person Identification Data',
        constraints: {
          fields: [
            { path: ['$.given_name'],   optional: false },
            { path: ['$.family_name'],  optional: false },
            { path: ['$.birth_date'],   optional: false },
            { path: ['$.tax_id_code'],  optional: true  },
            { path: ['$.nationality'],  optional: true  },
          ],
        },
      }],
    },
    dcqlQuery: {
      credentials: [{
        id: 'pid',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['urn:eudi:pid:1'] },
        claims: [
          { path: ['given_name'] },
          { path: ['family_name'] },
          { path: ['birth_date'] },
        ],
      }],
    },
  },
  {
    id: 'mdl',
    label: 'mDL — Driving Licence',
    icon: '🚗',
    description: 'Name, birth date, driving privilege categories (ISO 18013-5)',
    definition: {
      id: 'mdl-request',
      input_descriptors: [{
        id: 'mdl',
        name: 'Mobile Driving Licence',
        constraints: {
          fields: [
            { path: ['$.given_name'],          optional: false },
            { path: ['$.family_name'],         optional: false },
            { path: ['$.birth_date'],          optional: false },
            { path: ['$.driving_privileges'],  optional: false },
            { path: ['$.expiry_date'],         optional: true  },
          ],
        },
      }],
    },
    dcqlQuery: {
      credentials: [{
        id: 'mdl',
        format: 'mso_mdoc',
        meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
        claims: [
          { path: ['org.iso.18013.5.1', 'family_name'] },
          { path: ['org.iso.18013.5.1', 'given_name'] },
          { path: ['org.iso.18013.5.1', 'birth_date'] },
          { path: ['org.iso.18013.5.1', 'driving_privileges'] },
        ],
      }],
    },
  },
  {
    id: 'age',
    label: 'Age Verification',
    icon: '🔞',
    description: 'age_over_18 boolean only — minimal data, GDPR-friendly',
    definition: {
      id: 'age-request',
      input_descriptors: [{
        id: 'age-check',
        name: 'Age Verification',
        constraints: {
          fields: [{ path: ['$.age_over_18'], optional: false }],
        },
      }],
    },
    dcqlQuery: {
      credentials: [{
        id: 'age-check',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['eu.europa.ec.eudi.pid.1'] },
        claims: [{ path: ['age_over_18'] }],
      }],
    },
  },
  {
    id: 'eidas',
    label: 'eIDAS 2.0 EUDIW',
    icon: '🇪🇺',
    description: 'Full eIDAS 2.0 PID bundle: name, address, birth place, nationality',
    definition: {
      id: 'eudiw-pid',
      input_descriptors: [{
        id: 'eudiw',
        name: 'EUDIW PID',
        constraints: {
          fields: [
            { path: ['$.given_name'],    optional: false },
            { path: ['$.family_name'],   optional: false },
            { path: ['$.birth_date'],    optional: false },
            { path: ['$.birth_place'],   optional: true  },
            { path: ['$.nationality'],   optional: true  },
            { path: ['$.resident_address'], optional: true },
          ],
        },
      }],
    },
    dcqlQuery: {
      credentials: [{
        id: 'eudiw',
        format: 'dc+sd-jwt',
        meta: { vct_values: ['urn:eudi:pid:1'] },
        claims: [
          { path: ['given_name'] },
          { path: ['family_name'] },
          { path: ['birth_date'] },
          { path: ['birth_place'] },
          { path: ['nationality'] },
        ],
      }],
    },
  },
  {
    id: 'custom',
    label: 'Custom',
    icon: '⚙️',
    description: 'Write your own Presentation Exchange v2 definition as JSON',
    definition: null,
    dcqlQuery: null,
  },
]

// ── Claim display helpers ──────────────────────────────────────────────────────

const CLAIM_LABELS: Record<string, { label: string; icon: typeof User }> = {
  given_name:       { label: 'Given name',      icon: User         },
  family_name:      { label: 'Family name',     icon: User         },
  birth_date:       { label: 'Date of birth',   icon: CalendarDays },
  tax_id_code:      { label: 'Tax ID (CF)',      icon: Hash         },
  nationality:      { label: 'Nationality',     icon: Globe        },
  age_over_18:      { label: 'Age ≥ 18',         icon: Shield       },
  driving_privileges: { label: 'Driving categories', icon: CreditCard },
  expiry_date:      { label: 'Expiry date',     icon: CalendarDays },
  birth_place:      { label: 'Birth place',     icon: Globe        },
  resident_address: { label: 'Address',         icon: Globe        },
  sub:              { label: 'Subject',         icon: Fingerprint  },
  iss:              { label: 'Issuer',          icon: Shield       },
}

// ── Client-side GDPR data-minimization checker ────────────────────────────────
// Mirrors internal/oid4w/gdpr_minimization.go — keep in sync.

interface ClaimRule {
  sensitivity: 'low' | 'medium' | 'high'
  article: string
  message: string
  alternative?: string
}

const SENSITIVE_CLAIM_RULES: Record<string, ClaimRule> = {
  // High sensitivity
  tax_id:                { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Fiscal / tax identifier is a unique national identifier that enables cross-context tracking and is unnecessary for most verification purposes.', alternative: 'age_over_18 or age_over_{N} derived claim' },
  tax_id_code:           { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Tax ID code is a unique national identifier enabling cross-context tracking and profiling.', alternative: 'age_over_18 or age_over_{N} derived claim' },
  fiscal_code:           { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Italian codice fiscale is a full national identifier. Request only the derived attribute needed for the use case.', alternative: 'age_over_18' },
  codice_fiscale:        { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Italian codice fiscale is a full national identifier. Request only the derived attribute needed for the use case.', alternative: 'age_over_18' },
  document_number:       { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Document number uniquely identifies a physical document and enables tracking. Use a derived proof of identity instead where possible.' },
  face_image:            { sensitivity: 'high',   article: 'Art.9(1)',    message: 'Biometric data (face image) is a special category under GDPR Art.9. Collection requires explicit consent and a legal basis under Art.9(2).' },
  portrait:              { sensitivity: 'high',   article: 'Art.9(1)',    message: 'Biometric portrait is a special category under GDPR Art.9.' },
  fingerprint_template:  { sensitivity: 'high',   article: 'Art.9(1)',    message: 'Fingerprint biometric data is a special category under GDPR Art.9.' },
  iris_template:         { sensitivity: 'high',   article: 'Art.9(1)',    message: 'Iris biometric data is a special category under GDPR Art.9.' },
  phone_number:          { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Phone number is a direct contact identifier. Request only if strictly required.' },
  resident_address:      { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Full residential address is highly sensitive and rarely necessary. Consider requesting only the country or postal-code prefix.', alternative: 'address_country or place_of_birth' },
  address:               { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Full address is highly sensitive. Consider requesting only the country or postal-code prefix.', alternative: 'address_country' },
  email:                 { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Email address is a unique contact identifier. Request only if strictly required for the purpose.' },
  email_address:         { sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Email address is a unique contact identifier.' },
  social_security_number:{ sensitivity: 'high',   article: 'Art.5(1)(c)', message: 'Social security number is a full national identifier enabling cross-context tracking.', alternative: 'age_over_18 or relevant derived attribute' },
  health_id:             { sensitivity: 'high',   article: 'Art.9(1)',    message: 'Health identifier may expose health-related data, a special category under GDPR Art.9.' },
  // Medium sensitivity
  family_name:           { sensitivity: 'medium', article: 'Art.5(1)(c)', message: 'Full family name combined with other attributes may uniquely identify an individual. Verify that the full name is necessary for the stated purpose.' },
  given_name:            { sensitivity: 'medium', article: 'Art.5(1)(c)', message: 'Given name is personal data. Verify that identity by name is necessary for this purpose.' },
  date_of_birth:         { sensitivity: 'medium', article: 'Art.5(1)(c)', message: 'Full date of birth is more specific than many use cases require. Consider the derived claim age_over_18 or age_over_{N} instead.', alternative: 'age_over_18' },
  birth_date:            { sensitivity: 'medium', article: 'Art.5(1)(c)', message: 'Full birth date is more specific than many use cases require. Consider the derived claim age_over_18 instead.', alternative: 'age_over_18' },
  nationality:           { sensitivity: 'medium', article: 'Art.5(1)(c)', message: 'Nationality can expose ethnic origin, a special category under Art.9. Collect only if strictly necessary.' },
  place_of_birth:        { sensitivity: 'medium', article: 'Art.5(1)(c)', message: 'Place of birth may reveal ethnic or national origin. Collect only if necessary.', alternative: 'place_of_birth_country' },
  personal_number:       { sensitivity: 'medium', article: 'Art.5(1)(c)', message: 'Personal number is a national identifier. Verify it is needed for this purpose.' },
}

function normalizeLeaf(raw: string): string {
  let s = raw.toLowerCase().trim().replace(/^\$\.?/, '')
  if (s.startsWith("['") && s.endsWith("']")) s = s.slice(2, -2)
  const dot = s.lastIndexOf('.')
  if (dot >= 0) s = s.slice(dot + 1)
  return s
}

function checkLeafClient(leaf: string, location: string): GDPRWarning | null {
  const rule = SENSITIVE_CLAIM_RULES[normalizeLeaf(leaf)]
  if (!rule) return null
  return { claim_path: `${location}.${leaf}`, sensitivity: rule.sensitivity, article: rule.article, message: rule.message, alternative: rule.alternative }
}

function checkDCQLClient(dcqlQuery: Record<string, unknown>): GDPRWarning[] {
  const warnings: GDPRWarning[] = []
  const creds = dcqlQuery['credentials']
  const entries: Array<{ id: string; claims: unknown[] }> = Array.isArray(creds)
    ? creds.map((c: unknown) => ({ id: ((c as Record<string, unknown>)['id'] as string) ?? 'cred', claims: ((c as Record<string, unknown>)['claims'] as unknown[]) ?? [] }))
    : creds && typeof creds === 'object'
      ? Object.entries(creds as Record<string, unknown>).map(([id, v]) => ({ id, claims: ((v as Record<string, unknown>)['claims'] as unknown[]) ?? [] }))
      : []
  for (const { id, claims } of entries) {
    for (const claim of claims) {
      for (const p of ((claim as Record<string, unknown>)['path'] as unknown[]) ?? []) {
        if (typeof p === 'string') {
          const w = checkLeafClient(p, `credentials.${id}.claims`)
          if (w) warnings.push(w)
        }
      }
    }
  }
  return warnings
}

function checkPDClient(pd: Record<string, unknown>): GDPRWarning[] {
  const warnings: GDPRWarning[] = []
  for (const desc of (pd['input_descriptors'] as unknown[]) ?? []) {
    const dObj = desc as Record<string, unknown>
    const dId = (dObj['id'] as string) ?? 'unknown'
    const constraints = dObj['constraints'] as Record<string, unknown> | undefined
    if (!constraints) continue
    for (const field of (constraints['fields'] as unknown[]) ?? []) {
      for (const path of ((field as Record<string, unknown>)['path'] as string[]) ?? []) {
        const w = checkLeafClient(normalizeLeaf(path), `input_descriptors[${dId}]`)
        if (w) { w.claim_path = `input_descriptors[${dId}].${normalizeLeaf(path)}`; warnings.push(w) }
      }
    }
  }
  return warnings
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const mono: CSSProperties = { fontFamily: "'IBM Plex Mono', monospace" }
const card = (extra?: CSSProperties): CSSProperties => ({
  background: 'var(--clavex-panel)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  ...extra,
})

// ── Main component ─────────────────────────────────────────────────────────────

// ── Batch Verify Tab (OID4VP bulk verification for PA) ────────────────────────

interface BatchResult {
  id: string
  verified: boolean
  error?: string
  claims?: Record<string, unknown>
}

function BatchVerifyTab({ orgId }: { orgId: string }) {
  const [rawText, setRawText]       = useState('')
  const [tokens, setTokens]         = useState<string[]>([])
  const [parseError, setParseError] = useState('')
  const [preset, setPreset]         = useState(PRESETS[0])
  const [results, setResults]       = useState<BatchResult[] | null>(null)
  const [isPending, setIsPending]   = useState(false)

  function parseInput(text: string) {
    const lines = text.split('\n').map(l => l.trim()).filter(Boolean)
    if (lines.length === 0) { setParseError('No tokens found'); setTokens([]); return }
    if (lines.length > 100) { setParseError('Maximum 100 tokens per batch'); setTokens([]); return }
    setParseError('')
    setTokens(lines)
    setResults(null)
  }

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => {
      const text = ev.target?.result as string
      setRawText(text)
      parseInput(text)
    }
    reader.readAsText(file)
  }

  async function runVerify() {
    setIsPending(true)
    setResults(null)
    try {
      const def = preset.id === 'custom' ? JSON.parse(rawText) : preset.definition
      const items = tokens.map((t, i) => ({ id: String(i), vp_token: t, nonce: '', presentation_definition: def }))
      const resp = await api.post<{ results: BatchResult[] }>(
        `/organizations/${orgId}/oid4vp/batch-verify`,
        { items }
      )
      setResults(resp.data.results)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Batch verification failed'
      toast.error(msg)
    } finally {
      setIsPending(false)
    }
  }

  function exportCSV() {
    if (!results) return
    const header = 'index,status,subject,error'
    const rows = results.map((r, i) => {
      const subject = r.claims ? formatName(r.claims as Record<string, unknown>) : ''
      return [i, r.verified ? 'verified' : 'failed', `"${subject}"`, `"${r.error ?? ''}"`].join(',')
    })
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'batch-verify-results.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  const verifiedCount = results?.filter(r => r.verified).length ?? 0
  const failedCount   = results?.filter(r => !r.verified).length ?? 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 900 }}>
      {/* Info banner */}
      <div style={{ background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)',
        borderRadius: 12, padding: '14px 18px', fontSize: 13, color: 'var(--clavex-neutral)' }}>
        <strong style={{ color: 'var(--clavex-text)' }}>Batch VP verification</strong> — upload a list of VP tokens
        (one per line, CSV or plain text). The server verifies up to 100 presentations in parallel and returns a
        per-token result. Designed for PA use cases: verify qualifications of multiple candidates at once.
      </div>

      {/* Step 1 — Upload tokens */}
      <div style={{ background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)', borderRadius: 12, padding: 20 }}>
        <p style={{ fontSize: 12, fontWeight: 700, color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 12 }}>
          1 — Upload tokens
        </p>
        <label style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px',
          border: '0.5px dashed var(--clavex-border)', borderRadius: 8, cursor: 'pointer',
          fontSize: 13, color: 'var(--clavex-neutral)', marginBottom: 12 }}>
          <UploadCloud size={16} />
          Choose CSV / TXT file (one VP token per line)
          <input type="file" accept=".csv,.txt" onChange={handleFile} style={{ display: 'none' }} />
        </label>
        <textarea
          value={rawText}
          onChange={e => { setRawText(e.target.value); parseInput(e.target.value) }}
          style={{ width: '100%', minHeight: 100, resize: 'vertical', padding: '8px 12px',
            borderRadius: 8, fontSize: 12, fontFamily: 'monospace',
            border: '0.5px solid var(--clavex-border)',
            background: 'var(--clavex-bg)', color: 'var(--clavex-text)' }}
          placeholder="…or paste tokens directly here, one per line" />
        {parseError && <p style={{ fontSize: 12, color: '#dc2626', marginTop: 6 }}>{parseError}</p>}
        {tokens.length > 0 && !parseError && (
          <p style={{ fontSize: 12, color: '#16a34a', marginTop: 6 }}>
            ✓ {tokens.length} token{tokens.length !== 1 ? 's' : ''} ready
          </p>
        )}
      </div>

      {/* Step 2 — Credential type */}
      <div style={{ background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)', borderRadius: 12, padding: 20 }}>
        <p style={{ fontSize: 12, fontWeight: 700, color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 12 }}>
          2 — Credential type
        </p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {PRESETS.map(p => (
            <button key={p.id} onClick={() => setPreset(p)}
              style={{ padding: '6px 14px', borderRadius: 8, fontSize: 12, fontWeight: 600,
                border: '0.5px solid',
                borderColor: preset.id === p.id ? 'var(--clavex-primary)' : 'var(--clavex-border)',
                background: preset.id === p.id ? 'var(--clavex-primary)' : 'transparent',
                color: preset.id === p.id ? '#fff' : 'var(--clavex-text)',
                cursor: 'pointer' }}>
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Verify button */}
      <div>
        <Button variant="primary" disabled={tokens.length === 0 || isPending} onClick={runVerify}>
          {isPending
            ? <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Verifying {tokens.length} tokens…</>
            : <><Layers size={14} /> Verify All ({tokens.length})</>}
        </Button>
      </div>

      {/* Results */}
      {results && (
        <div style={{ background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)', borderRadius: 12, padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Results</h3>
            <span style={{ padding: '2px 10px', borderRadius: 99, background: '#16a34a18', color: '#16a34a', fontSize: 12, fontWeight: 700 }}>
              {verifiedCount} verified
            </span>
            <span style={{ padding: '2px 10px', borderRadius: 99, background: '#dc262618', color: '#dc2626', fontSize: 12, fontWeight: 700 }}>
              {failedCount} failed
            </span>
            <span style={{ padding: '2px 10px', borderRadius: 99, background: '#6b728018', color: '#6b7280', fontSize: 12, fontWeight: 700 }}>
              {results.length} total
            </span>
            <div style={{ flex: 1 }} />
            <button onClick={exportCSV}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '5px 12px',
                borderRadius: 8, fontSize: 12, fontWeight: 600,
                border: '0.5px solid var(--clavex-border)', background: 'transparent',
                color: 'var(--clavex-text)', cursor: 'pointer' }}>
              <FileDown size={13} /> Export CSV
            </button>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ color: 'var(--clavex-neutral)', textAlign: 'left' }}>
                  <th style={{ padding: '6px 10px', fontWeight: 600 }}>#</th>
                  <th style={{ padding: '6px 10px', fontWeight: 600 }}>Status</th>
                  <th style={{ padding: '6px 10px', fontWeight: 600 }}>Subject</th>
                  <th style={{ padding: '6px 10px', fontWeight: 600 }}>Error</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={r.id} style={{ borderTop: '0.5px solid var(--clavex-border)',
                    background: r.verified ? '#16a34a04' : '#dc262604' }}>
                    <td style={{ padding: '8px 10px', color: 'var(--clavex-neutral)' }}>{i + 1}</td>
                    <td style={{ padding: '8px 10px' }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5,
                        padding: '2px 8px', borderRadius: 99, fontSize: 11, fontWeight: 700,
                        background: r.verified ? '#16a34a18' : '#dc262618',
                        color: r.verified ? '#16a34a' : '#dc2626' }}>
                        {r.verified ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
                        {r.verified ? 'verified' : 'failed'}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      {r.claims ? formatName(r.claims as Record<string, unknown>) : '—'}
                    </td>
                    <td style={{ padding: '8px 10px', color: '#dc2626', fontFamily: 'monospace', fontSize: 11 }}>
                      {r.error ?? ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default function WalletVerifier() {
  const orgId   = useAuthStore(s => s.orgId)
  const orgSlug = useAuthStore(s => s.orgSlug)

  const [preset,      setPreset]      = useState(PRESETS[0])
  const [customJSON,  setCustomJSON]  = useState('')
  const [jsonError,   setJSONError]   = useState('')
  const [activeSession, setActiveSession] = useState<CreateSessionResp | null>(null)
  const [gdprWarnings,  setGdprWarnings]  = useState<GDPRWarning[]>([])
  const [result,      setResult]      = useState<Session | null>(null)
  const [showHistory, setShowHistory] = useState(false)
  const [expandedSession, setExpandedSession] = useState<string | null>(null)
  const [mainTab,     setMainTab]     = useState<'session' | 'batch'>('session')
  const [conformanceEndpoint, setConformanceEndpoint] = useState('')
  const [showConformance, setShowConformance] = useState(false)

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Real-time GDPR analysis — runs on every preset/JSON change, no API call needed.
  const liveGdprWarnings = useMemo((): GDPRWarning[] => {
    if (preset.id === 'custom') {
      if (!customJSON.trim()) return []
      try { return checkPDClient(JSON.parse(customJSON)) } catch { return [] }
    }
    if (preset.dcqlQuery) return checkDCQLClient(preset.dcqlQuery as Record<string, unknown>)
    return []
  }, [preset, customJSON])

  // A "valid query is loaded" flag used to decide whether to show the green badge.
  const hasAnalyzableQuery = preset.id !== 'custom' || (customJSON.trim() !== '' && !jsonError)

  // ── Create presentation session ──────────────────────────────────────────────

  const createSession = useMutation({
    mutationFn: ({ definition, dcqlQuery }: { definition: Record<string, unknown> | null; dcqlQuery: Record<string, unknown> | null }) => {
      const conformance = conformanceEndpoint.trim()
      // Prefer DCQL when the preset defines it — the EUDI reference wallet
      // (openid4vp-kt ≥ 0.12) dropped presentation_definition support entirely.
      const usesDCQL = dcqlQuery != null
      return api.post<CreateSessionResp>(`/${orgSlug}/wallet/request`, {
        ...(usesDCQL ? { dcql_query: dcqlQuery } : { presentation_definition: definition }),
        ...(conformance ? { wallet_authorization_endpoint: conformance } : {}),
      }).then(r => r.data)
    },
    onSuccess: (data) => {
      setActiveSession(data)
      setGdprWarnings(data.gdpr_warnings ?? [])
      setResult(null)
      startPolling(data.request_id)
    },
    onError: () => toast.error('Failed to create presentation request'),
  })

  // ── Session history ──────────────────────────────────────────────────────────

  const { data: sessions = [], refetch: refetchHistory } = useQuery<Session[]>({
    queryKey: ['vp-sessions', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/oid4vp/sessions`).then(r =>
      Array.isArray(r.data) ? r.data : []
    ),
    enabled: !!orgId && showHistory,
    refetchInterval: showHistory ? 10_000 : false,
  })

  // ── Polling for status change ─────────────────────────────────────────────────

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }, [])

  const startPolling = useCallback((requestId: string) => {
    stopPolling()
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await api.get<Session>(
          `/organizations/${orgId}/oid4vp/sessions/${requestId}`
        )
        if (data.status === 'verified') {
          setResult(data)
          setActiveSession(null)
          stopPolling()
          refetchHistory()
          toast.success('Identity verified!')
        } else if (data.status === 'failed') {
          setResult(data)
          setActiveSession(null)
          stopPolling()
          refetchHistory()
          toast.error('Verification failed')
        }
      } catch { /* session not found yet — keep polling */ }
    }, 2000)
  }, [orgId, stopPolling, refetchHistory])

  useEffect(() => () => stopPolling(), [stopPolling])

  // ── Handlers ─────────────────────────────────────────────────────────────────

  function handleStart() {
    let definition: Record<string, unknown> | null
    let dcqlQuery: Record<string, unknown> | null = preset.dcqlQuery as Record<string, unknown> | null
    if (preset.id === 'custom') {
      try {
        definition = JSON.parse(customJSON || '{}')
        setJSONError('')
      } catch {
        setJSONError('Invalid JSON — check your Presentation Exchange v2 definition')
        return
      }
      dcqlQuery = null
    } else {
      definition = preset.definition as Record<string, unknown>
    }
    createSession.mutate({ definition, dcqlQuery })
  }

  function handleReset() {
    stopPolling()
    setActiveSession(null)
    setGdprWarnings([])
    setResult(null)
  }

  const qrUrl = activeSession
    ? `${import.meta.env.VITE_API_URL ?? ''}/api/v1/${orgSlug}/wallet/request/${activeSession.request_id}/qr?size=320`
    : null

  // Seconds until expiry
  const [secsLeft, setSecsLeft] = useState(0)
  useEffect(() => {
    if (!activeSession) return
    const tick = () => {
      const diff = Math.max(0, Math.round((new Date(activeSession.expires_at).getTime() - Date.now()) / 1000))
      setSecsLeft(diff)
    }
    tick()
    const t = setInterval(tick, 1000)
    return () => clearInterval(t)
  }, [activeSession])

  return (
    <div>

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <p style={{ ...mono, fontSize: 11, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--clavex-primary)', marginBottom: 8 }}>
          ◈ OID4VP · eIDAS 2.0
        </p>
        <h1 style={{ fontSize: 24, fontWeight: 300, color: 'var(--clavex-ink)', letterSpacing: '-0.02em', margin: 0 }}>
          Wallet <strong style={{ fontWeight: 700 }}>Credential Verifier</strong>
        </h1>
        <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginTop: 6 }}>
          Display a Presentation Request QR code — the citizen scans with IT-Wallet or EUDIW. Verified identity appears in real time.
        </p>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '0.5px solid var(--clavex-border)', marginBottom: 24 }}>
        {([
          { id: 'session', label: 'Session Verify', icon: <QrCode size={14} /> },
          { id: 'batch',   label: 'Batch Verify',   icon: <Layers size={14} /> },
        ] as const).map(t => (
          <button key={t.id} onClick={() => setMainTab(t.id)}
            style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '8px 18px',
              background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 600,
              color: mainTab === t.id ? 'var(--clavex-primary)' : 'var(--clavex-neutral)',
              borderBottom: mainTab === t.id ? '2px solid var(--clavex-primary)' : '2px solid transparent',
              marginBottom: -1 }}>
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {mainTab === 'batch' && <BatchVerifyTab orgId={orgId ?? ''} />}

      {mainTab === 'session' && (
      <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: 24, alignItems: 'flex-start' }}>

        {/* ── Left: Configure + QR ─────────────────────────────────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Preset selector */}
          {!activeSession && !result && (
            <div style={card({ padding: 20 })}>
              <p style={{ fontSize: 12, fontWeight: 700, color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 14 }}>
                Credential type
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {PRESETS.map(p => (
                  <button
                    key={p.id}
                    onClick={() => { setPreset(p); setJSONError('') }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '10px 12px', borderRadius: 8, cursor: 'pointer', textAlign: 'left',
                      background: preset.id === p.id ? 'rgba(93,202,165,0.08)' : 'transparent',
                      border: `0.5px solid ${preset.id === p.id ? 'rgba(93,202,165,0.4)' : 'var(--clavex-border)'}`,
                      transition: 'all 0.15s',
                    }}
                  >
                    <span style={{ fontSize: 20, flexShrink: 0 }}>{p.icon}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)' }}>{p.label}</div>
                      <div style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 2, lineHeight: 1.4 }}>{p.description}</div>
                    </div>
                    {preset.id === p.id && <CheckCircle2 size={14} color="var(--clavex-primary)" style={{ flexShrink: 0 }} />}
                  </button>
                ))}
              </div>

              {/* Custom JSON editor */}
              {preset.id === 'custom' && (
                <div style={{ marginTop: 14 }}>
                  <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6 }}>
                    Presentation Exchange v2 definition
                  </label>
                  <textarea
                    value={customJSON}
                    onChange={e => { setCustomJSON(e.target.value); setJSONError('') }}
                    placeholder={'{\n  "id": "my-request",\n  "input_descriptors": [...]\n}'}
                    rows={8}
                    style={{
                      width: '100%', ...mono, fontSize: 11.5, lineHeight: 1.6,
                      background: '#0D1F2D', color: '#C4DFF0', borderRadius: 8,
                      border: `0.5px solid ${jsonError ? '#E24B4A' : 'rgba(93,202,165,0.2)'}`,
                      padding: 12, resize: 'vertical', outline: 'none', boxSizing: 'border-box',
                    }}
                  />
                  {jsonError && (
                    <p style={{ fontSize: 11, color: '#E24B4A', marginTop: 4 }}>{jsonError}</p>
                  )}
                </div>
              )}

              {/* GDPR Analysis — live preview, updates as the user picks a preset */}
              {liveGdprWarnings.length > 0 ? (
                <div style={{
                  background: '#fef3c720', border: '1px solid #f59e0b60',
                  borderRadius: 10, padding: '12px 14px', marginTop: 14,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <AlertTriangle size={13} color="#d97706" />
                    <span style={{ fontSize: 11, fontWeight: 700, color: '#92400e', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                      GDPR Analysis
                    </span>
                    <span style={{
                      marginLeft: 'auto', fontSize: 10, fontWeight: 700,
                      background: liveGdprWarnings.some(w => w.sensitivity === 'high') ? '#dc262618' : '#f59e0b18',
                      color: liveGdprWarnings.some(w => w.sensitivity === 'high') ? '#dc2626' : '#d97706',
                      padding: '2px 8px', borderRadius: 99,
                    }}>
                      {liveGdprWarnings.length} warning{liveGdprWarnings.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    {liveGdprWarnings.map((w, i) => (
                      <div key={i} style={{
                        background: w.sensitivity === 'high' ? '#fef2f220' : '#fffbeb30',
                        border: `0.5px solid ${w.sensitivity === 'high' ? '#fca5a580' : '#fcd34d80'}`,
                        borderRadius: 7, padding: '7px 10px',
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                          <code style={{ fontSize: 11, fontFamily: 'monospace', fontWeight: 700, color: w.sensitivity === 'high' ? '#dc2626' : '#d97706' }}>
                            {w.claim_path.split('.').pop()}
                          </code>
                          <span style={{
                            padding: '1px 6px', borderRadius: 99, fontSize: 9, fontWeight: 700,
                            background: w.sensitivity === 'high' ? '#dc262618' : '#f59e0b18',
                            color: w.sensitivity === 'high' ? '#dc2626' : '#d97706',
                          }}>
                            {w.sensitivity} · {w.article}
                          </span>
                        </div>
                        <p style={{ fontSize: 10.5, color: '#6b7280', margin: 0, lineHeight: 1.4 }}>{w.message}</p>
                        {w.alternative && (
                          <p style={{ fontSize: 10.5, color: '#16a34a', margin: '3px 0 0', fontWeight: 600 }}>
                            ✓ Use instead: {w.alternative}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ) : hasAnalyzableQuery ? (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 7, marginTop: 14,
                  padding: '8px 12px', borderRadius: 8, fontSize: 11, fontWeight: 600,
                  background: '#f0fdf420', border: '0.5px solid #16a34a40', color: '#16a34a',
                }}>
                  <Shield size={12} color="#16a34a" />
                  GDPR Art.5(1)(c) — data minimisation OK
                </div>
              ) : null}

              <Button
                onClick={handleStart}
                loading={createSession.isPending}
                style={{ width: '100%', marginTop: 16, justifyContent: 'center' }}
              >
                <ScanLine size={15} />
                Generate QR
              </Button>

              {/* Conformance testing section */}
              <div style={{ marginTop: 12 }}>
                <button
                  onClick={() => setShowConformance(v => !v)}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none',
                    cursor: 'pointer', fontSize: 11, color: 'var(--clavex-neutral)', padding: '4px 0' }}
                >
                  {showConformance ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                  Conformance testing
                </button>
                {showConformance && (
                  <div style={{ marginTop: 8 }}>
                    <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--clavex-neutral)', marginBottom: 4 }}>
                      Wallet authorization endpoint
                    </label>
                    <input
                      type="url"
                      value={conformanceEndpoint}
                      onChange={e => setConformanceEndpoint(e.target.value)}
                      placeholder="https://www.certification.openid.net/.../wallet/authorize"
                      style={{
                        width: '100%', boxSizing: 'border-box',
                        ...mono, fontSize: 10.5, padding: '8px 10px',
                        background: 'var(--clavex-surface)', color: 'var(--clavex-text)',
                        border: '0.5px solid var(--clavex-border)', borderRadius: 6, outline: 'none',
                      }}
                    />
                    <p style={{ fontSize: 10, color: 'var(--clavex-neutral)', marginTop: 4, lineHeight: 1.5 }}>
                      When set, the response will include an <code>authorization_url</code> with
                      request parameters inline (url_query). Use instead of the QR code
                      to point the conformance suite wallet at Clavex.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* GDPR Art.5(1)(c) data minimization warnings */}
          {gdprWarnings.length > 0 && (
            <div style={{
              background: '#fef3c720',
              border: '1px solid #f59e0b60',
              borderRadius: 10,
              padding: '12px 16px',
              marginBottom: 4,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <AlertTriangle size={15} color="#d97706" />
                <span style={{ fontSize: 13, fontWeight: 700, color: '#92400e' }}>
                  GDPR Art.5(1)(c) — Data Minimisation Warnings
                </span>
              </div>
              <p style={{ fontSize: 12, color: '#92400e', margin: '0 0 10px 0' }}>
                This presentation request includes claims that may exceed what is necessary for the stated purpose.
                Review each item before deploying to production.
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {gdprWarnings.map((w, i) => (
                  <div key={i} style={{
                    background: w.sensitivity === 'high' ? '#fef2f2' : '#fffbeb',
                    border: `1px solid ${w.sensitivity === 'high' ? '#fca5a560' : '#fcd34d60'}`,
                    borderRadius: 7,
                    padding: '8px 12px',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                      <code style={{ fontSize: 11, fontFamily: 'monospace', color: w.sensitivity === 'high' ? '#dc2626' : '#d97706', fontWeight: 700 }}>
                        {w.claim_path}
                      </code>
                      <span style={{
                        padding: '1px 7px', borderRadius: 99, fontSize: 10, fontWeight: 700,
                        background: w.sensitivity === 'high' ? '#dc262618' : '#f59e0b18',
                        color: w.sensitivity === 'high' ? '#dc2626' : '#d97706',
                      }}>
                        {w.sensitivity} · {w.article}
                      </span>
                    </div>
                    <p style={{ fontSize: 11, color: '#6b7280', margin: 0 }}>{w.message}</p>
                    {w.alternative && (
                      <p style={{ fontSize: 11, color: '#16a34a', margin: '4px 0 0' }}>
                        ✓ Privacy-preserving alternative: <strong>{w.alternative}</strong>
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* QR code display */}
          {activeSession && qrUrl && (
            <div style={card({ padding: 24, textAlign: 'center' })}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, textAlign: 'left' }}>
                <div>
                  <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', margin: 0 }}>Scan with IT-Wallet</p>
                  <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 2 }}>or any EUDIW-compatible wallet</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: secsLeft > 30 ? 'var(--clavex-primary)' : '#F5C842', animation: 'pulse 1.5s infinite' }} />
                  <span style={{ ...mono, fontSize: 11, color: secsLeft > 30 ? 'var(--clavex-primary)' : '#F5C842' }}>
                    {secsLeft}s
                  </span>
                </div>
              </div>

              {/* QR image from backend */}
              <div style={{
                background: '#fff', borderRadius: 12, padding: 16, display: 'inline-block',
                border: '0.5px solid var(--clavex-border)', position: 'relative',
              }}>
                <img
                  src={qrUrl}
                  alt="OID4VP Presentation Request QR"
                  width={280}
                  height={280}
                  style={{ display: 'block' }}
                />
                {/* Corner decorations */}
                {['tl','tr','bl','br'].map(c => (
                  <div key={c} style={{
                    position: 'absolute',
                    width: 20, height: 20,
                    border: `2px solid var(--clavex-primary)`,
                    borderRadius: 3,
                    ...(c === 'tl' ? { top: 8, left: 8, borderRight: 'none', borderBottom: 'none' } : {}),
                    ...(c === 'tr' ? { top: 8, right: 8, borderLeft: 'none', borderBottom: 'none' } : {}),
                    ...(c === 'bl' ? { bottom: 8, left: 8, borderRight: 'none', borderTop: 'none' } : {}),
                    ...(c === 'br' ? { bottom: 8, right: 8, borderLeft: 'none', borderTop: 'none' } : {}),
                  }} />
                ))}
              </div>

              {/* Scanning indicator */}
              <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                <Loader2 size={14} color="var(--clavex-primary)" style={{ animation: 'spin 1s linear infinite' }} />
                <span style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>Waiting for wallet response…</span>
              </div>

              {/* Conformance: authorization_url */}
              {activeSession.authorization_url && (
                <div style={{ marginTop: 16, textAlign: 'left', background: 'var(--clavex-surface)',
                  border: '0.5px solid var(--clavex-border)', borderRadius: 8, padding: '12px 14px' }}>
                  <p style={{ fontSize: 11, fontWeight: 700, color: 'var(--clavex-neutral)',
                    textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
                    Conformance URL
                  </p>
                  <p style={{ fontSize: 10, color: 'var(--clavex-neutral)', marginBottom: 8, lineHeight: 1.5 }}>
                    Open this URL in the conformance suite browser instead of scanning the QR:
                  </p>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                    <code style={{ ...mono, fontSize: 9, color: 'var(--clavex-primary)', wordBreak: 'break-all',
                      flex: 1, lineHeight: 1.6 }}>
                      {activeSession.authorization_url}
                    </code>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(activeSession.authorization_url!)
                        toast.success('Copied!')
                      }}
                      style={{ flexShrink: 0, background: 'none', border: '0.5px solid var(--clavex-border)',
                        borderRadius: 6, padding: '4px 8px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                        fontSize: 11, color: 'var(--clavex-neutral)' }}
                    >
                      <Copy size={11} /> Copy
                    </button>
                  </div>
                </div>
              )}

              <button
                onClick={handleReset}
                style={{ marginTop: 14, fontSize: 12, color: 'var(--clavex-neutral)', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5, margin: '14px auto 0' }}
              >
                <RefreshCw size={12} /> Cancel &amp; start over
              </button>
            </div>
          )}

          {/* Reset after result */}
          {result && (
            <Button variant="secondary" onClick={handleReset} style={{ width: '100%', justifyContent: 'center' }}>
              <Plus size={14} /> New verification
            </Button>
          )}
        </div>

        {/* ── Right: Status + result ───────────────────────────────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* Idle state */}
          {!activeSession && !result && (
            <div style={card({ padding: 48, textAlign: 'center' })}>
              <div style={{ width: 64, height: 64, borderRadius: '50%', background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
                <QrCode size={28} color="var(--clavex-neutral)" />
              </div>
              <p style={{ fontSize: 16, fontWeight: 600, color: 'var(--clavex-ink)', margin: '0 0 8px' }}>
                Ready to verify
              </p>
              <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', maxWidth: 320, margin: '0 auto' }}>
                Select a credential type and click <strong>Generate QR</strong>. The citizen scans with their wallet — verified identity appears here in real time.
              </p>
            </div>
          )}

          {/* Scanning / pending state */}
          {activeSession && (
            <div style={card({ padding: 40, textAlign: 'center', border: '0.5px solid rgba(93,202,165,0.3)' })}>
              <div style={{ width: 64, height: 64, borderRadius: '50%', background: 'rgba(93,202,165,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
                <ScanLine size={28} color="var(--clavex-primary)" />
              </div>
              <p style={{ fontSize: 18, fontWeight: 600, color: 'var(--clavex-ink)', margin: '0 0 8px' }}>
                Waiting for wallet…
              </p>
              <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>
                Show the QR code to the citizen. The identity verification result will appear here automatically.
              </p>
              <div style={{ marginTop: 24, ...mono, fontSize: 11, color: 'var(--clavex-neutral)' }}>
                request_id: {activeSession.request_id.slice(0, 16)}…
              </div>
            </div>
          )}

          {/* Verified result */}
          {result?.status === 'verified' && result.vp_claims && (
            <VerifiedResult claims={result.vp_claims} requestId={result.request_id} />
          )}

          {/* Failed result */}
          {result?.status === 'failed' && (
            <div style={card({ padding: 32, border: '0.5px solid rgba(226,75,74,0.4)' })}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 20 }}>
                <div style={{ width: 48, height: 48, borderRadius: '50%', background: 'rgba(226,75,74,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <XCircle size={24} color="#E24B4A" />
                </div>
                <div>
                  <p style={{ fontSize: 18, fontWeight: 700, color: '#E24B4A', margin: 0 }}>Verification failed</p>
                  <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginTop: 4 }}>
                    The wallet rejected the request, the VP token was invalid, or the session timed out.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Session history */}
          <div style={card({ overflow: 'hidden' })}>
            <button
              onClick={() => setShowHistory(h => !h)}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                width: '100%', padding: '14px 20px', background: 'none', border: 'none', cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <History size={14} color="var(--clavex-neutral)" />
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)' }}>Session history</span>
                {sessions.length > 0 && (
                  <span style={{ ...mono, fontSize: 11, padding: '1px 7px', borderRadius: 10, background: 'var(--clavex-surface)', color: 'var(--clavex-neutral)', border: '0.5px solid var(--clavex-border)' }}>
                    {sessions.length}
                  </span>
                )}
              </div>
              {showHistory ? <ChevronUp size={14} color="var(--clavex-neutral)" /> : <ChevronDown size={14} color="var(--clavex-neutral)" />}
            </button>

            {showHistory && (
              <div style={{ borderTop: '0.5px solid var(--clavex-border)' }}>
                {sessions.length === 0
                  ? (
                    <div style={{ padding: '24px 20px', textAlign: 'center', fontSize: 13, color: 'var(--clavex-neutral)' }}>
                      No sessions yet in this organisation.
                    </div>
                  )
                  : sessions.map((s, i) => (
                    <div key={s.id} style={{ borderBottom: i < sessions.length - 1 ? '0.5px solid var(--clavex-border)' : 'none' }}>
                      <button
                        onClick={() => setExpandedSession(expandedSession === s.id ? null : s.id)}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 12, width: '100%',
                          padding: '12px 20px', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left',
                        }}
                      >
                        <StatusDot status={s.status} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)' }}>
                            {s.status === 'verified' && s.vp_claims
                              ? formatName(s.vp_claims)
                              : s.status === 'failed' ? 'Verification failed'
                              : 'Pending…'
                            }
                          </div>
                          <div style={{ ...mono, fontSize: 10, color: 'var(--clavex-neutral)', marginTop: 2 }}>
                            {new Date(s.created_at).toLocaleString()} · {s.request_id.slice(0, 12)}…
                          </div>
                        </div>
                        {expandedSession === s.id ? <ChevronUp size={12} color="var(--clavex-neutral)" /> : <ChevronDown size={12} color="var(--clavex-neutral)" />}
                      </button>
                      {expandedSession === s.id && s.vp_claims && (
                        <div style={{ padding: '0 20px 16px' }}>
                          <ClaimGrid claims={s.vp_claims} />
                        </div>
                      )}
                    </div>
                  ))
                }
              </div>
            )}
          </div>
        </div>
      </div>
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
      `}</style>
    </div>
  )
}

// ── Verified result panel ──────────────────────────────────────────────────────

function VerifiedResult({ claims, requestId }: { claims: Record<string, unknown>; requestId: string }) {
  const name = formatName(claims)
  return (
    <div style={{
      background: 'rgba(22,163,74,0.04)',
      border: '0.5px solid rgba(22,163,74,0.35)',
      borderRadius: 12, padding: 28,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 28 }}>
        <div style={{ width: 56, height: 56, borderRadius: '50%', background: 'rgba(22,163,74,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <CheckCircle2 size={28} color="#16a34a" />
        </div>
        <div>
          <div style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.15em', textTransform: 'uppercase', color: '#16a34a', marginBottom: 4 }}>
            ✓ Identità verificata
          </div>
          <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--clavex-ink)', letterSpacing: '-0.01em' }}>
            {name}
          </div>
        </div>
      </div>

      {/* Claims grid */}
      <ClaimGrid claims={claims} />

      {/* Footer */}
      <div style={{ marginTop: 20, paddingTop: 16, borderTop: '0.5px solid rgba(22,163,74,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: 'rgba(22,163,74,0.7)' }}>
          OID4VP · eIDAS 2.0 · {new Date().toLocaleString()}
        </span>
        <button
          onClick={() => { navigator.clipboard.writeText(JSON.stringify(claims, null, 2)); toast.success('Claims copied') }}
          style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: '#16a34a', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}
        >
          <Copy size={12} /> Copy JSON
        </button>
      </div>

      <div style={{ marginTop: 10, fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: 'var(--clavex-neutral)' }}>
        request_id: {requestId}
      </div>
    </div>
  )
}

// ── Claim grid ─────────────────────────────────────────────────────────────────

function ClaimGrid({ claims }: { claims: Record<string, unknown> }) {
  const SKIP = ['iss', 'iat', 'exp', 'nbf', 'jti', 'aud', 'cnf', 'vct', 'status']
  const entries = Object.entries(claims).filter(([k]) => !SKIP.includes(k))

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
      {entries.map(([key, val]) => {
        const meta = CLAIM_LABELS[key]
        const Icon = meta?.icon ?? Hash
        const label = meta?.label ?? key.replace(/_/g, ' ')
        const display = typeof val === 'boolean'
          ? (val ? 'Yes ✓' : 'No ✗')
          : (typeof val === 'object' && val !== null)
            ? JSON.stringify(val)
            : String(val ?? '—')
        return (
          <div key={key} style={{
            background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)',
            borderRadius: 8, padding: '12px 14px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <Icon size={12} color="var(--clavex-neutral)" />
              <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--clavex-neutral)' }}>
                {label}
              </span>
            </div>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--clavex-ink)', wordBreak: 'break-word' }}>
              {display}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function StatusDot({ status }: { status: string }) {
  const color = status === 'verified' ? '#16a34a' : status === 'failed' ? '#E24B4A' : '#F5C842'
  const Icon = status === 'verified' ? CheckCircle2 : status === 'failed' ? XCircle : Clock
  return <Icon size={14} color={color} style={{ flexShrink: 0 }} />
}

function formatName(claims: Record<string, unknown>): string {
  const given  = claims.given_name  as string | undefined
  const family = claims.family_name as string | undefined
  if (given && family) return `${given} ${family}`
  if (family) return family
  if (given) return given
  return 'Unknown subject'
}
