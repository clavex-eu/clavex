import { useState, useEffect, useMemo, CSSProperties } from 'react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  BarChart2, Shield, Globe, Target, RefreshCw,
  ChevronDown, ChevronUp, Lock, Info, Download,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SummaryRow {
  vct: string
  day: string        // "2026-06-01"
  purpose_hint: string
  country_hint: string
  count: number
}

interface SummaryResp {
  from: string
  to: string
  rows: SummaryRow[] | null
  totals: Record<string, number>
  privacy_notice: string
}

// ── Styles ────────────────────────────────────────────────────────────────────

const mono: CSSProperties = { fontFamily: "'IBM Plex Mono', monospace" }

const card = (extra?: CSSProperties): CSSProperties => ({
  background: 'var(--clavex-panel)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: 20,
  ...extra,
})

const label: CSSProperties = {
  fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
  letterSpacing: '0.08em', color: 'var(--clavex-neutral)',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function vctShort(vct: string): string {
  try {
    const u = new URL(vct)
    const parts = u.pathname.split('/').filter(Boolean)
    return parts[parts.length - 2] ?? parts[parts.length - 1] ?? vct
  } catch {
    return vct.split('/').pop() ?? vct
  }
}

const PURPOSE_LABELS: Record<string, string> = {
  employment:     'Lavoro',
  education:      'Istruzione',
  age_gate:       'Verifica età',
  access_control: 'Controllo accesso',
  travel:         'Viaggio',
  healthcare:     'Sanità',
  financial:      'Finanza',
  other:          'Altro',
  '':             'Non specificato',
}

function purposeLabel(h: string) { return PURPOSE_LABELS[h] ?? h }

// ── Mini bar chart using SVG ──────────────────────────────────────────────────

function MiniBar({ value, max, color = 'var(--clavex-primary)' }: { value: number; max: number; color?: string }) {
  const pct = max > 0 ? Math.max(4, Math.round((value / max) * 100)) : 0
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
      <div style={{ flex: 1, height: 8, background: 'var(--clavex-surface)', borderRadius: 99, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 99, transition: 'width 0.4s ease' }} />
      </div>
      <span style={{ ...mono, fontSize: 11, color: 'var(--clavex-neutral)', minWidth: 32, textAlign: 'right' }}>
        {value.toLocaleString()}
      </span>
    </div>
  )
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label: lbl, value, sub, color }: {
  icon: React.ElementType; label: string; value: string | number; sub?: string; color?: string
}) {
  return (
    <div style={card({ display: 'flex', alignItems: 'flex-start', gap: 14 })}>
      <div style={{
        width: 38, height: 38, borderRadius: 10, flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: color ? `${color}18` : 'var(--clavex-surface)',
      }}>
        <Icon size={18} color={color ?? 'var(--clavex-neutral)'} />
      </div>
      <div>
        <p style={{ ...label, marginBottom: 2 }}>{lbl}</p>
        <p style={{ fontSize: 24, fontWeight: 700, color: 'var(--clavex-ink)', margin: 0, lineHeight: 1 }}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </p>
        {sub && <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 4 }}>{sub}</p>}
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CredentialAnalytics() {
  const orgId = useAuthStore(s => s.orgId)

  const [data,    setData]    = useState<SummaryResp | null>(null)
  const [loading, setLoading] = useState(false)
  const [range,   setRange]   = useState<'30' | '90' | '180'>('90')
  const [showPrivacy, setShowPrivacy] = useState(false)
  const [showDocs,    setShowDocs]    = useState(false)

  async function load() {
    if (!orgId) return
    setLoading(true)
    try {
      const to   = new Date()
      const from = new Date(to)
      from.setDate(from.getDate() - parseInt(range))
      const res = await api.get<SummaryResp>(
        `/organizations/${orgId}/oid4vci/analytics/summary`,
        { params: { from: from.toISOString().slice(0, 10), to: to.toISOString().slice(0, 10) } }
      )
      setData(res.data)
    } catch {
      toast.error('Impossibile caricare le statistiche')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [orgId, range]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Derived stats ──────────────────────────────────────────────────────────

  const rows = data?.rows ?? []

  const totalPresentations = useMemo(() =>
    rows.reduce((s, r) => s + r.count, 0), [rows])

  const byVCT = useMemo(() => {
    const m: Record<string, number> = {}
    for (const r of rows) m[r.vct] = (m[r.vct] ?? 0) + r.count
    return Object.entries(m).sort((a, b) => b[1] - a[1])
  }, [rows])

  const byPurpose = useMemo(() => {
    const m: Record<string, number> = {}
    for (const r of rows) {
      const k = r.purpose_hint || ''
      m[k] = (m[k] ?? 0) + r.count
    }
    return Object.entries(m).sort((a, b) => b[1] - a[1])
  }, [rows])

  const byCountry = useMemo(() => {
    const m: Record<string, number> = {}
    for (const r of rows) {
      const k = r.country_hint || '??'
      m[k] = (m[k] ?? 0) + r.count
    }
    return Object.entries(m).sort((a, b) => b[1] - a[1])
  }, [rows])

  // Daily totals for sparkline (last 30 days)
  const dailyTotals = useMemo(() => {
    const m: Record<string, number> = {}
    for (const r of rows) m[r.day] = (m[r.day] ?? 0) + r.count
    return Object.entries(m).sort(([a], [b]) => a.localeCompare(b)).slice(-30)
  }, [rows])

  const maxDay = useMemo(() => Math.max(...dailyTotals.map(([, v]) => v), 1), [dailyTotals])

  // ── CSV export ─────────────────────────────────────────────────────────────

  function exportCSV() {
    const header = 'vct,day,purpose_hint,country_hint,count'
    const lines  = rows.map(r =>
      [r.vct, r.day, r.purpose_hint, r.country_hint, r.count].join(',')
    )
    const blob = new Blob([[header, ...lines].join('\n')], { type: 'text/csv' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = 'credential-analytics.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <div style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                background: '#16a34a18', border: '0.5px solid #16a34a40',
                borderRadius: 8, padding: '3px 10px',
              }}>
                <Lock size={11} color="#16a34a" />
                <span style={{ ...mono, fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: '#16a34a' }}>
                  Privacy-Preserving
                </span>
              </div>
            </div>
            <h1 style={{ fontSize: 24, fontWeight: 300, color: 'var(--clavex-ink)', letterSpacing: '-0.02em', margin: 0 }}>
              Credential <strong style={{ fontWeight: 700 }}>Analytics</strong>
            </h1>
            <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginTop: 6 }}>
              Statistiche aggregate anonime sulle presentazioni delle credenziali emesse.
              Nessuna presentazione è tracciabile a un singolo titolare.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
            <select
              value={range}
              onChange={e => setRange(e.target.value as '30' | '90' | '180')}
              style={{
                padding: '7px 12px', fontSize: 13, borderRadius: 8, cursor: 'pointer',
                border: '0.5px solid var(--clavex-border)', background: 'var(--clavex-panel)',
                color: 'var(--clavex-text)', outline: 'none',
              }}
            >
              <option value="30">Ultimi 30 giorni</option>
              <option value="90">Ultimi 90 giorni</option>
              <option value="180">Ultimi 180 giorni</option>
            </select>
            <button onClick={exportCSV} disabled={rows.length === 0}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '7px 12px', fontSize: 12, fontWeight: 600,
                border: '0.5px solid var(--clavex-border)', borderRadius: 8,
                background: 'none', color: 'var(--clavex-neutral)', cursor: 'pointer',
              }}
            >
              <Download size={13} /> CSV
            </button>
            <button onClick={load} disabled={loading}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '7px 12px', fontSize: 12, fontWeight: 600,
                border: '0.5px solid var(--clavex-border)', borderRadius: 8,
                background: 'none', color: 'var(--clavex-neutral)', cursor: 'pointer',
              }}
            >
              <RefreshCw size={13} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
              Aggiorna
            </button>
          </div>
        </div>
      </div>

      {/* Privacy notice (collapsible) */}
      <div style={{
        marginBottom: 20, border: '0.5px solid #16a34a40',
        borderRadius: 10, overflow: 'hidden',
        background: 'linear-gradient(135deg, #f0fdf408, #dcfce708)',
      }}>
        <button
          onClick={() => setShowPrivacy(v => !v)}
          style={{
            display: 'flex', alignItems: 'center', gap: 10, width: '100%',
            padding: '12px 16px', background: 'none', border: 'none', cursor: 'pointer',
          }}
        >
          <Shield size={14} color="#16a34a" />
          <span style={{ flex: 1, fontSize: 12, fontWeight: 700, color: '#16a34a', textAlign: 'left' }}>
            Come funziona la privacy — RSA Blind Signatures
          </span>
          {showPrivacy ? <ChevronUp size={13} color="#16a34a" /> : <ChevronDown size={13} color="#16a34a" />}
        </button>
        {showPrivacy && (
          <div style={{ padding: '0 16px 16px', borderTop: '0.5px solid #16a34a30' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
              {[
                {
                  n: '1',
                  title: 'Il wallet acceca il token',
                  body: 'Prima di presentare una credenziale, il wallet genera un token casuale m e lo "acceca" con un fattore r: m_blind = m · r^e mod n. Invia solo m_blind all\'issuer.',
                },
                {
                  n: '2',
                  title: 'L\'issuer firma alla cieca',
                  body: 'L\'issuer calcola s_blind = m_blind^d mod n e lo restituisce. Non ha mai visto m — la firma è cieca: l\'issuer non sa cosa sta firmando.',
                },
                {
                  n: '3',
                  title: 'Il wallet disacceca',
                  body: 'Il wallet calcola s = s_blind · r⁻¹ mod n. Ottiene (m, s): un token valido che l\'issuer non ha mai visto e che non può collegare all\'emissione.',
                },
                {
                  n: '4',
                  title: 'Report anonimo',
                  body: 'Quando presenta la credenziale, il wallet invia (m, s, vct, scopo) all\'issuer. L\'issuer verifica s^e ≡ SHA-256(m), segna il token come usato e incrementa il contatore. Nessun PII.',
                },
              ].map(step => (
                <div key={step.n} style={{
                  background: '#f0fdf4', border: '0.5px solid #bbf7d0',
                  borderRadius: 8, padding: '10px 12px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span style={{
                      width: 20, height: 20, borderRadius: '50%',
                      background: '#16a34a', color: '#fff',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 11, fontWeight: 700, flexShrink: 0,
                    }}>{step.n}</span>
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#166534' }}>{step.title}</span>
                  </div>
                  <p style={{ fontSize: 11, color: '#15803d', margin: 0, lineHeight: 1.5 }}>{step.body}</p>
                </div>
              ))}
            </div>
            <p style={{ fontSize: 11, color: '#16a34a', marginTop: 10, fontWeight: 600 }}>
              Garanzia: l'issuer può verificare che il token è autentico ma non può collegarlo
              a nessun titolare specifico. Conformità GDPR Art.89 (statistical purposes).
            </p>
          </div>
        )}
      </div>

      {/* KPI cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 20 }}>
        <StatCard
          icon={BarChart2} label="Presentazioni totali"
          value={totalPresentations}
          sub={`negli ultimi ${range} giorni`}
          color="var(--clavex-primary)"
        />
        <StatCard
          icon={Target} label="Tipi credenziale"
          value={byVCT.length}
          sub="con almeno una presentazione"
          color="#8b5cf6"
        />
        <StatCard
          icon={Globe} label="Paesi"
          value={byCountry.filter(([k]) => k !== '??').length}
          sub="con hint di paese noto"
          color="#0ea5e9"
        />
      </div>

      {/* Daily sparkline */}
      {dailyTotals.length > 0 && (
        <div style={{ ...card({ marginBottom: 20 }) }}>
          <p style={{ ...label, marginBottom: 12 }}>Presentazioni per giorno</p>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 80 }}>
            {dailyTotals.map(([day, count]) => {
              const h = Math.max(4, Math.round((count / maxDay) * 72))
              return (
                <div key={day} title={`${day}: ${count}`} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                  <div style={{
                    width: '100%', height: h,
                    background: 'var(--clavex-primary)', borderRadius: '3px 3px 0 0',
                    opacity: 0.8, minWidth: 4,
                  }} />
                </div>
              )
            })}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
            <span style={{ ...mono, fontSize: 9, color: 'var(--clavex-neutral)' }}>
              {dailyTotals[0]?.[0]}
            </span>
            <span style={{ ...mono, fontSize: 9, color: 'var(--clavex-neutral)' }}>
              {dailyTotals[dailyTotals.length - 1]?.[0]}
            </span>
          </div>
        </div>
      )}

      {/* Two-column: by VCT + by purpose */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>

        {/* By VCT */}
        <div style={card()}>
          <p style={{ ...label, marginBottom: 14 }}>Per tipo credenziale</p>
          {byVCT.length === 0 ? (
            <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', fontStyle: 'italic' }}>Nessun dato</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {byVCT.map(([vct, count]) => (
                <div key={vct}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)' }} title={vct}>
                      {vctShort(vct)}
                    </span>
                  </div>
                  <MiniBar value={count} max={byVCT[0][1]} color="var(--clavex-primary)" />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* By purpose */}
        <div style={card()}>
          <p style={{ ...label, marginBottom: 14 }}>Per scopo dichiarato</p>
          {byPurpose.length === 0 ? (
            <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', fontStyle: 'italic' }}>Nessun dato</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {byPurpose.map(([purpose, count]) => (
                <div key={purpose}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)' }}>
                      {purposeLabel(purpose)}
                    </span>
                  </div>
                  <MiniBar value={count} max={byPurpose[0][1]} color="#8b5cf6" />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* By country */}
      {byCountry.length > 0 && (
        <div style={{ ...card({ marginBottom: 20 }) }}>
          <p style={{ ...label, marginBottom: 14 }}>Per paese (hint del verifier)</p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
            {byCountry.map(([country, count]) => (
              <div key={country} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ ...mono, fontSize: 13, width: 28, textAlign: 'center', flexShrink: 0 }}>
                  {country === '??' ? '🌍' : country}
                </span>
                <MiniBar value={count} max={byCountry[0][1]} color="#0ea5e9" />
              </div>
            ))}
          </div>
          <p style={{ fontSize: 10, color: 'var(--clavex-neutral)', marginTop: 10 }}>
            Il paese è un hint opzionale inviato dal verifier — non verificato crittograficamente.
          </p>
        </div>
      )}

      {/* Wallet developer docs (collapsible) */}
      <div style={{ ...card({ marginBottom: 20 }), padding: 0, overflow: 'hidden' }}>
        <button
          onClick={() => setShowDocs(v => !v)}
          style={{
            display: 'flex', alignItems: 'center', gap: 10, width: '100%',
            padding: '14px 20px', background: 'none', border: 'none', cursor: 'pointer',
          }}
        >
          <Info size={14} color="var(--clavex-neutral)" />
          <span style={{ flex: 1, fontSize: 13, fontWeight: 700, color: 'var(--clavex-ink)', textAlign: 'left' }}>
            Come integrare — guida per wallet developer
          </span>
          {showDocs ? <ChevronUp size={13} color="var(--clavex-neutral)" /> : <ChevronDown size={13} color="var(--clavex-neutral)" />}
        </button>
        {showDocs && (
          <div style={{ padding: '0 20px 20px', borderTop: '0.5px solid var(--clavex-border)' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 16 }}>
              {[
                {
                  step: '1. Recupera la chiave pubblica RSA',
                  code: `GET /:org_slug/oid4vci/analytics/public-key\n→ { "keys": [{ "kty":"RSA", "n":"...", "e":"AQAB" }] }`,
                },
                {
                  step: '2. Acceca il token (wallet-side JavaScript)',
                  code: `// Genera m casuale (32 byte)
const m = crypto.getRandomValues(new Uint8Array(32))
// Calcola m_blind = SHA256(m) · r^e mod n
// (usa una libreria RSA blind, es. blind-rsa-signatures su npm)
const { blindedMsg, secret } = await blindSign(pubKey, m)`,
                },
                {
                  step: '3. Richiedi la firma cieca',
                  code: `POST /:org_slug/oid4vci/analytics/token
Content-Type: application/json
{ "blinded": "<hex m_blind>" }
→ { "signed": "<hex s_blind>" }`,
                },
                {
                  step: '4. Disacceca (wallet-side)',
                  code: `const sig = unblind(sBlind, secret, pubKey)
// Conserva { msg: hex(m), sig: hex(sig) } per la presentazione`,
                },
                {
                  step: '5. Invia il report anonimo (dopo la presentazione VP)',
                  code: `POST /:org_slug/oid4vci/analytics/report
{ "token_msg": "<hex m>",
  "token_sig": "<hex sig>",
  "vct": "https://issuer.example.com/credentials/diploma/1",
  "purpose_hint": "employment",   // opzionale
  "country_hint": "IT"            // opzionale, ISO 3166-1 alpha-2
}
→ 202 { "status": "recorded" }`,
                },
              ].map(({ step, code }) => (
                <div key={step}>
                  <p style={{ fontSize: 12, fontWeight: 700, color: 'var(--clavex-ink)', marginBottom: 6 }}>{step}</p>
                  <pre style={{
                    ...mono, fontSize: 11, lineHeight: 1.6,
                    background: '#0D1F2D', color: '#C4DFF0',
                    borderRadius: 8, padding: '10px 14px', margin: 0,
                    whiteSpace: 'pre-wrap', overflowX: 'auto',
                  }}>{code}</pre>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Empty state */}
      {!loading && rows.length === 0 && (
        <div style={{ ...card({ textAlign: 'center', padding: '48px 24px' }) }}>
          <BarChart2 size={36} color="var(--clavex-neutral)" style={{ margin: '0 auto 16px', opacity: 0.3 }} />
          <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--clavex-ink)', margin: '0 0 8px' }}>
            Nessuna presentazione ancora registrata
          </p>
          <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', maxWidth: 380, margin: '0 auto' }}>
            Le statistiche appariranno quando i wallet inizieranno a inviare report anonimi
            tramite il protocollo di blind signature.
          </p>
        </div>
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
