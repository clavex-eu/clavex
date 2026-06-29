import { useState, useEffect, useCallback } from 'react'
import { Search, Tag, Globe, Copy, Check, ExternalLink, ChevronDown, ChevronUp, Package } from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface MarketplaceListing {
  id: string
  display_name: string
  description?: string
  issuer_name: string
  issuer_org_slug: string
  vct: string
  credential_format: string
  lang: string
  issuer_endpoint: string
  schema_json: Record<string, unknown>
  offer_template?: string
  tags: string[]
  created_at: string
}

// ── Scoped styles (marketing dark theme — mirrors Pricing.tsx) ────────────────

const STYLES = `
.mk {
  --bg:      #0D1F2D;
  --bg-2:    #112233;
  --bg-3:    #162B40;
  --rule:    #1E3448;
  --body:    #7AAABB;
  --bright:  #E8F4F8;
  --muted:   #4A7890;
  --teal:    #5DCAA5;
  --teal-d:  #1D9E75;
  --teal-p:  rgba(93,202,165,.07);
  background: var(--bg);
  color: var(--body);
  font-family: 'Plus Jakarta Sans', ui-sans-serif, system-ui, sans-serif;
  min-height: 100vh;
  overflow-x: hidden;
  position: relative;
}
.mk::before {
  content: '';
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(93,202,165,.02) 1px, transparent 1px),
    linear-gradient(90deg, rgba(93,202,165,.02) 1px, transparent 1px);
  background-size: 60px 60px;
}
.mk > * { position: relative; z-index: 1; }

.mk-card {
  background: var(--bg-2);
  border: 1px solid var(--rule);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  gap: .75rem;
  transition: border-color .2s, box-shadow .2s;
  cursor: pointer;
}
.mk-card:hover { border-color: rgba(93,202,165,.35); box-shadow: 0 0 24px rgba(93,202,165,.06); }

.mk-card-expanded {
  border-color: var(--teal) !important;
  box-shadow: 0 0 32px rgba(93,202,165,.12);
}

.mk-tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 10px;
  border-radius: 999px;
  border: 1px solid var(--rule);
  font-size: .72rem;
  color: var(--muted);
  background: transparent;
  cursor: pointer;
  transition: border-color .15s, color .15s;
  white-space: nowrap;
}
.mk-tag:hover, .mk-tag-active {
  border-color: var(--teal);
  color: var(--teal);
}

.mk-pill {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  border-radius: 6px;
  font-size: .7rem;
  font-weight: 600;
  letter-spacing: .03em;
}

.mk-input {
  background: var(--bg-2);
  border: 1px solid var(--rule);
  border-radius: 8px;
  color: var(--bright);
  padding: .55rem .9rem .55rem 2.4rem;
  font-size: .875rem;
  outline: none;
  transition: border-color .2s;
  width: 100%;
}
.mk-input:focus { border-color: rgba(93,202,165,.5); }
.mk-input::placeholder { color: var(--muted); }

.mk-select {
  background: var(--bg-2);
  border: 1px solid var(--rule);
  border-radius: 8px;
  color: var(--bright);
  padding: .55rem .9rem;
  font-size: .875rem;
  outline: none;
  appearance: none;
  cursor: pointer;
  transition: border-color .2s;
}
.mk-select:focus { border-color: rgba(93,202,165,.5); }

.mk-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: .45rem 1rem;
  border-radius: 8px;
  font-size: .82rem;
  font-weight: 600;
  cursor: pointer;
  transition: background .15s, opacity .15s;
  white-space: nowrap;
  border: none;
}
.mk-btn-teal {
  background: var(--teal);
  color: #0D1F2D;
}
.mk-btn-teal:hover { background: var(--teal-d); }
.mk-btn-ghost {
  background: transparent;
  border: 1px solid var(--rule);
  color: var(--body);
}
.mk-btn-ghost:hover { border-color: rgba(93,202,165,.4); color: var(--teal); }

.mk-schema-row:nth-child(even) { background: rgba(255,255,255,.02); }
`

// ── Format helpers ────────────────────────────────────────────────────────────

const FORMAT_COLORS: Record<string, string> = {
  'vc+sd-jwt':  '#3B6DCA',
  'jwt_vc_json': '#7047EB',
  'ldp_vc':      '#1D9E75',
  'mso_mdoc':    '#C47800',
}

function formatPill(fmt: string) {
  const bg = FORMAT_COLORS[fmt] ?? '#4A7890'
  return (
    <span className="mk-pill" style={{ background: bg + '22', color: bg, border: `1px solid ${bg}55` }}>
      {fmt}
    </span>
  )
}

function langLabel(lang: string) {
  const map: Record<string, string> = { it: '🇮🇹 IT', en: '🇬🇧 EN', de: '🇩🇪 DE', fr: '🇫🇷 FR', es: '🇪🇸 ES' }
  return map[lang] ?? lang.toUpperCase()
}

// ── Copy-to-clipboard button ──────────────────────────────────────────────────

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }
  return (
    <button className="mk-btn mk-btn-ghost" onClick={copy} style={{ fontSize: '.78rem', padding: '.35rem .75rem' }}>
      {copied ? <Check size={13} /> : <Copy size={13} />}
      {label ?? (copied ? 'Copied!' : 'Copy')}
    </button>
  )
}

// ── Schema viewer ─────────────────────────────────────────────────────────────

function SchemaViewer({ schema }: { schema: Record<string, unknown> }) {
  const renderValue = (v: unknown, depth = 0): React.ReactNode => {
    if (v === null || v === undefined) return <span style={{ color: 'var(--muted)' }}>null</span>
    if (typeof v === 'boolean') return <span style={{ color: '#5DCAA5' }}>{String(v)}</span>
    if (typeof v === 'number') return <span style={{ color: '#F4A256' }}>{v}</span>
    if (typeof v === 'string') return <span style={{ color: '#A8D8EA' }}>"{v}"</span>
    if (Array.isArray(v)) return (
      <span style={{ color: 'var(--muted)' }}>
        [{v.map((item, i) => <span key={i}>{i > 0 && ', '}{renderValue(item, depth)}</span>)}]
      </span>
    )
    if (typeof v === 'object') {
      const entries = Object.entries(v as Record<string, unknown>)
      if (depth > 0) return <span style={{ color: 'var(--muted)', fontStyle: 'italic' }}>{'{'} {entries.length} fields {'}'}</span>
      return (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '.8rem', tableLayout: 'fixed' }}>
          <tbody>
            {entries.map(([k, val]) => (
              <tr key={k} className="mk-schema-row">
                <td style={{ padding: '.35rem .5rem', color: 'var(--bright)', width: '35%', wordBreak: 'break-all', verticalAlign: 'top' }}>{k}</td>
                <td style={{ padding: '.35rem .5rem', color: 'var(--body)', wordBreak: 'break-all' }}>{renderValue(val, depth + 1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )
    }
    return String(v)
  }
  const keys = Object.keys(schema)
  if (keys.length === 0) return <p style={{ color: 'var(--muted)', fontSize: '.8rem', margin: 0 }}>No schema defined</p>
  return <div style={{ borderRadius: 8, overflow: 'hidden', border: '1px solid var(--rule)' }}>{renderValue(schema)}</div>
}

// ── Card ──────────────────────────────────────────────────────────────────────

function ListingCard({ listing, onTagClick }: { listing: MarketplaceListing; onTagClick: (tag: string) => void }) {
  const [expanded, setExpanded] = useState(false)
  const [activeTab, setActiveTab] = useState<'schema' | 'integration'>('schema')

  const integrationConfig = JSON.stringify({
    issuer: listing.issuer_endpoint,
    vct: listing.vct,
    format: listing.credential_format,
    display_name: listing.display_name,
    issuer_name: listing.issuer_name,
  }, null, 2)

  return (
    <div className={`mk-card ${expanded ? 'mk-card-expanded' : ''}`} onClick={() => setExpanded(e => !e)}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '.75rem' }}>
        <div style={{
          width: 40, height: 40, borderRadius: 8,
          background: 'linear-gradient(135deg,#1D9E75,#3B6DCA)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Package size={18} color="#fff" />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ color: 'var(--bright)', fontWeight: 600, fontSize: '.95rem', lineHeight: 1.3 }}>
            {listing.display_name}
          </div>
          <div style={{ fontSize: '.78rem', color: 'var(--muted)', marginTop: 2 }}>
            {listing.issuer_name}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
          <span style={{ fontSize: '.72rem', color: 'var(--muted)' }}>{langLabel(listing.lang)}</span>
          {expanded ? <ChevronUp size={15} color="var(--teal)" /> : <ChevronDown size={15} color="var(--muted)" />}
        </div>
      </div>

      {/* Description */}
      {listing.description && (
        <p style={{ margin: 0, fontSize: '.82rem', color: 'var(--body)', lineHeight: 1.5 }}>
          {listing.description}
        </p>
      )}

      {/* Chips row */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
        {formatPill(listing.credential_format)}
        <span className="mk-pill" style={{ background: 'rgba(255,255,255,.04)', color: 'var(--muted)', border: '1px solid var(--rule)', fontFamily: 'monospace', fontSize: '.68rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {listing.vct}
        </span>
      </div>

      {/* Tags */}
      {listing.tags.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
          {listing.tags.map(tag => (
            <button
              key={tag}
              className="mk-tag"
              onClick={e => { e.stopPropagation(); onTagClick(tag) }}
            >
              <Tag size={10} />{tag}
            </button>
          ))}
        </div>
      )}

      {/* Expanded detail */}
      {expanded && (
        <div style={{ marginTop: '.5rem', borderTop: '1px solid var(--rule)', paddingTop: '1rem' }} onClick={e => e.stopPropagation()}>
          {/* Tabs */}
          <div style={{ display: 'flex', gap: 8, marginBottom: '1rem' }}>
            {(['schema', 'integration'] as const).map(t => (
              <button
                key={t}
                className="mk-btn"
                style={{
                  padding: '.3rem .8rem',
                  fontWeight: activeTab === t ? 700 : 400,
                  borderBottom: activeTab === t ? '2px solid var(--teal)' : '2px solid transparent',
                  color: activeTab === t ? 'var(--teal)' : 'var(--muted)',
                  borderRadius: 0,
                  background: 'transparent',
                }}
                onClick={() => setActiveTab(t)}
              >
                {t === 'schema' ? 'Schema SD-JWT' : 'Integration'}
              </button>
            ))}
          </div>

          {activeTab === 'schema' && (
            <div>
              <SchemaViewer schema={listing.schema_json} />
            </div>
          )}

          {activeTab === 'integration' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '.75rem' }}>
              {/* Issuer endpoint */}
              <div>
                <div style={{ fontSize: '.75rem', color: 'var(--muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '.05em' }}>Issuer Endpoint</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg)', borderRadius: 8, padding: '.5rem .75rem', border: '1px solid var(--rule)' }}>
                  <code style={{ flex: 1, fontSize: '.8rem', color: 'var(--bright)', wordBreak: 'break-all' }}>{listing.issuer_endpoint}</code>
                  <a href={listing.issuer_endpoint} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--teal)', flexShrink: 0 }} title="Open issuer">
                    <ExternalLink size={14} />
                  </a>
                  <CopyButton text={listing.issuer_endpoint} />
                </div>
              </div>

              {/* VCT */}
              <div>
                <div style={{ fontSize: '.75rem', color: 'var(--muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '.05em' }}>VCT (Credential Type)</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg)', borderRadius: 8, padding: '.5rem .75rem', border: '1px solid var(--rule)' }}>
                  <code style={{ flex: 1, fontSize: '.8rem', color: 'var(--bright)', wordBreak: 'break-all' }}>{listing.vct}</code>
                  <CopyButton text={listing.vct} />
                </div>
              </div>

              {/* Offer template */}
              {listing.offer_template && (
                <div>
                  <div style={{ fontSize: '.75rem', color: 'var(--muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '.05em' }}>Credential Offer URI</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg)', borderRadius: 8, padding: '.5rem .75rem', border: '1px solid var(--rule)' }}>
                    <code style={{ flex: 1, fontSize: '.8rem', color: 'var(--bright)', wordBreak: 'break-all' }}>{listing.offer_template}</code>
                    <CopyButton text={listing.offer_template} />
                  </div>
                </div>
              )}

              {/* Import config */}
              <div>
                <div style={{ fontSize: '.75rem', color: 'var(--muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '.05em' }}>Import Config (JSON)</div>
                <div style={{ position: 'relative' }}>
                  <pre style={{
                    background: 'var(--bg)',
                    border: '1px solid var(--rule)',
                    borderRadius: 8,
                    padding: '.75rem',
                    fontSize: '.75rem',
                    color: 'var(--bright)',
                    overflow: 'auto',
                    maxHeight: 200,
                    margin: 0,
                  }}>{integrationConfig}</pre>
                  <div style={{ position: 'absolute', top: 8, right: 8 }}>
                    <CopyButton text={integrationConfig} label="Copy JSON" />
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main page component ───────────────────────────────────────────────────────

export default function MarketplacePage() {
  const apiBase = (import.meta as { env?: Record<string, string> }).env?.VITE_API_URL ?? ''

  const [listings, setListings] = useState<MarketplaceListing[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [search, setSearch] = useState('')
  const [langFilter, setLangFilter] = useState('')
  const [tagFilter, setTagFilter] = useState('')

  const fetchListings = useCallback(() => {
    setLoading(true)
    setError(null)
    const params = new URLSearchParams()
    if (search) params.set('q', search)
    if (langFilter) params.set('lang', langFilter)
    if (tagFilter) params.set('tag', tagFilter)
    fetch(`${apiBase}/api/v1/marketplace/credentials?${params}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ items: MarketplaceListing[]; total: number }>
      })
      .then(data => { setListings(data.items ?? []); setLoading(false) })
      .catch(e => { setError(String(e)); setLoading(false) })
  }, [apiBase, search, langFilter, tagFilter])

  useEffect(() => { fetchListings() }, [fetchListings])

  // Collect all unique tags for the quick-filter bar
  const allTags = Array.from(new Set(listings.flatMap(l => l.tags))).sort()
  const allLangs = Array.from(new Set(listings.map(l => l.lang))).sort()

  return (
    <div className="mk">
      <style>{STYLES}</style>

      {/* ── Hero ── */}
      <header style={{ maxWidth: 900, margin: '0 auto', padding: '4rem 1.5rem 2.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: '1.25rem' }}>
          <div style={{
            width: 48, height: 48, borderRadius: 12,
            background: 'linear-gradient(135deg,#1D9E75,#3B6DCA)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Globe size={24} color="#fff" />
          </div>
          <div>
            <div style={{ color: 'var(--teal)', fontSize: '.78rem', fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase' }}>
              Credential Marketplace
            </div>
            <h1 style={{ margin: 0, fontSize: '1.7rem', fontWeight: 800, color: 'var(--bright)', lineHeight: 1.2 }}>
              Catalogo Credenziali Verificabili
            </h1>
          </div>
        </div>
        <p style={{ color: 'var(--body)', fontSize: '1rem', lineHeight: 1.6, maxWidth: 600, margin: 0 }}>
          Scopri i template di credenziali pubblicati da PA e privati. Ogni template include il VCT, 
          lo schema SD-JWT e l'endpoint dell'emittente — importabile in un click nel tuo wallet.
        </p>
      </header>

      {/* ── Filters ── */}
      <div style={{ maxWidth: 900, margin: '0 auto', padding: '0 1.5rem 1.5rem' }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          {/* Search */}
          <div style={{ position: 'relative', flex: '1 1 240px', minWidth: 180 }}>
            <Search size={15} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--muted)', pointerEvents: 'none' }} />
            <input
              className="mk-input"
              type="search"
              placeholder="Cerca per nome, emittente, VCT…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>

          {/* Language filter */}
          {allLangs.length > 1 && (
            <div style={{ position: 'relative' }}>
              <Globe size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--muted)', pointerEvents: 'none' }} />
              <select className="mk-select" style={{ paddingLeft: 28 }} value={langFilter} onChange={e => setLangFilter(e.target.value)}>
                <option value="">Tutte le lingue</option>
                {allLangs.map(l => <option key={l} value={l}>{langLabel(l)}</option>)}
              </select>
            </div>
          )}

          {/* Reset */}
          {(search || langFilter || tagFilter) && (
            <button className="mk-btn mk-btn-ghost" onClick={() => { setSearch(''); setLangFilter(''); setTagFilter('') }}>
              Mostra tutti
            </button>
          )}
        </div>

        {/* Tag quick-filters */}
        {allTags.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: '.75rem' }}>
            {allTags.map(tag => (
              <button
                key={tag}
                className={`mk-tag ${tagFilter === tag ? 'mk-tag-active' : ''}`}
                onClick={() => setTagFilter(t => t === tag ? '' : tag)}
              >
                <Tag size={10} />{tag}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* ── Grid ── */}
      <main style={{ maxWidth: 900, margin: '0 auto', padding: '0 1.5rem 4rem' }}>
        {loading && (
          <div style={{ textAlign: 'center', color: 'var(--muted)', padding: '4rem 0' }}>
            Caricamento…
          </div>
        )}
        {error && (
          <div style={{ textAlign: 'center', color: '#F97171', padding: '2rem 0', fontSize: '.9rem' }}>
            Errore nel caricamento del catalogo: {error}
          </div>
        )}
        {!loading && !error && listings.length === 0 && (
          <div style={{ textAlign: 'center', color: 'var(--muted)', padding: '4rem 0' }}>
            <Package size={40} style={{ marginBottom: 12, opacity: .4 }} />
            <p style={{ margin: 0 }}>Nessuna credenziale trovata{(search || tagFilter || langFilter) ? ' per i filtri selezionati' : ''}.</p>
          </div>
        )}
        {!loading && !error && listings.length > 0 && (
          <>
            <div style={{ color: 'var(--muted)', fontSize: '.8rem', marginBottom: '1rem' }}>
              {listings.length} template disponibil{listings.length === 1 ? 'e' : 'i'}
            </div>
            <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))' }}>
              {listings.map(l => (
                <ListingCard key={l.id} listing={l} onTagClick={tag => setTagFilter(t => t === tag ? '' : tag)} />
              ))}
            </div>
          </>
        )}
      </main>

      {/* ── Footer ── */}
      <footer style={{ borderTop: '1px solid var(--rule)', padding: '1.5rem', textAlign: 'center', color: 'var(--muted)', fontSize: '.78rem' }}>
        Vuoi pubblicare le tue credenziali? Accedi al{' '}
        <a href="/dashboard" style={{ color: 'var(--teal)', textDecoration: 'none' }}>pannello amministrativo</a>
        {' '}e pubblica un template — il tuo emittente sarà visibile dopo la verifica.
      </footer>
    </div>
  )
}
