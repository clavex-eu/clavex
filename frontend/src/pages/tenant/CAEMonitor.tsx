/**
 * CAEMonitor — Continuous Access Evaluation push monitoring dashboard.
 *
 * Shows all registered SSF/CAEP push receivers (resource servers), their last
 * delivery status, event type coverage, and copy-paste integration snippets.
 *
 * API: GET /api/v1/organizations/:org_id/ssf/streams  → StreamWithHealth[]
 *      POST /:org_slug/ssf/stream/verify              → trigger test push
 */
import { useState, CSSProperties } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  Zap, CheckCircle2, XCircle, Clock, RefreshCw, Radio,
  Copy, Code2, ChevronDown, ChevronUp, Shield, Wifi,
  AlertTriangle, Info, Play,
} from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import { Button } from '@/components/ui'

// ── Types ──────────────────────────────────────────────────────────────────────

interface DeliveryRecord {
  ts: string          // ISO timestamp
  ok: boolean
  event_type: string
  error?: string
}

interface SSFStream {
  stream_id: string
  client_id: string
  delivery_method: 'push' | 'poll'
  push_endpoint?: string
  events_requested: string[]
  status: 'enabled' | 'paused' | 'disabled'
  description?: string
  created_at: string
  last_delivery?: DeliveryRecord
}

// ── Constants ──────────────────────────────────────────────────────────────────
const EVENT_SHORT: Record<string, string> = {
  'session-revoked':     'session-revoked',
  'token-claims-change': 'token-claims-change',
  'credential-change':   'credential-change',
  'assurance-level-change': 'assurance-level-change',
  'account-disabled':    'account-disabled',
  'sessions-revoked':    'sessions-revoked',
}

function shortEvent(uri: string): string {
  const last = uri.split('/').pop() ?? uri
  return EVENT_SHORT[last] ?? last
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const mono: CSSProperties = { fontFamily: "'IBM Plex Mono', monospace" }
const card = (extra?: CSSProperties): CSSProperties => ({
  background: 'var(--clavex-panel)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  ...extra,
})
const badge = (color: string): CSSProperties => ({
  display: 'inline-flex', alignItems: 'center', gap: 4,
  padding: '2px 8px', borderRadius: 20,
  fontSize: 11, fontWeight: 600,
  background: `${color}18`, color,
  border: `0.5px solid ${color}40`,
})

// ── Integration code snippets ──────────────────────────────────────────────────

const NODE_SNIPPET = `// Express.js resource server — CAE SET receiver
import express from 'express'
import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'

const app = express()
app.use(express.text({ type: 'application/secevent+jwt' }))

// In-memory token blocklist — replace with Redis in production
const revokedTokens = new Map<string, number>() // jti → exp unix

const jwks = jwksClient({ jwksUri: 'https://{issuer}/.well-known/jwks.json' })

function getKey(header, cb) {
  jwks.getSigningKey(header.kid, (err, key) => {
    cb(err, err ? null : key.getPublicKey())
  })
}

// POST /ssf/receiver — registered as push_endpoint in Clavex
app.post('/ssf/receiver', (req, res) => {
  const set = req.body
  jwt.verify(set, getKey, { algorithms: ['RS256'] }, (err, decoded: any) => {
    if (err) return res.status(400).json({ error: 'invalid SET' })

    const events = decoded.events ?? {}

    // CAE: token explicitly revoked — add to blocklist
    if (events['https://schemas.openid.net/secevent/caep/event-type/token-claims-change']) {
      const body = events['https://schemas.openid.net/secevent/caep/event-type/token-claims-change']
      if (body.change_type === 'revoke' && body.token_jti) {
        revokedTokens.set(body.token_jti, decoded.exp ?? Date.now() / 1000 + 3600)
        console.log('[CAE] Revoked token JTI:', body.token_jti)
      }
    }

    // CAE: session revoked — invalidate all tokens for this user (sub_id.sub)
    if (events['https://schemas.openid.net/secevent/caep/event-type/session-revoked']) {
      const sub = decoded.sub_id?.sub
      console.log('[CAE] Session revoked for user:', sub)
      // purge all cached tokens for this sub from your local token store
    }

    res.status(202).send()
  })
})

// Middleware: check the blocklist before accepting a request
function requireValidToken(req, res, next) {
  const jti = getJTIFromToken(req.headers.authorization)
  if (jti && revokedTokens.has(jti)) {
    return res.status(401).json({ error: 'token_revoked' })
  }
  next()
}`

const GO_SNIPPET = `// Go resource server — CAE SET receiver
package main

import (
    "net/http"
    "sync"
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwt"
)

var (
    mu            sync.RWMutex
    revokedTokens = map[string]bool{} // jti → revoked
    revokedSubs   = map[string]bool{} // sub → all sessions revoked
)

func ssfReceiver(w http.ResponseWriter, r *http.Request) {
    // Verify the SET JWT
    set, err := verifySSFToken(r.Body)
    if err != nil {
        http.Error(w, "invalid SET", http.StatusBadRequest)
        return
    }

    events, _ := set.Get("events").(map[string]interface{})
    subID, _ := set.Get("sub_id").(map[string]interface{})
    sub, _ := subID["sub"].(string)

    const tokenRevokedURI = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
    const sessionRevokedURI = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

    mu.Lock()
    defer mu.Unlock()

    if body, ok := events[tokenRevokedURI].(map[string]interface{}); ok {
        if ct, _ := body["change_type"].(string); ct == "revoke" {
            if jti, _ := body["token_jti"].(string); jti != "" {
                revokedTokens[jti] = true // precise per-JTI revocation
            }
        }
    }
    if _, ok := events[sessionRevokedURI]; ok && sub != "" {
        revokedSubs[sub] = true // all tokens for this user are invalid
    }

    w.WriteHeader(http.StatusAccepted)
}

// Call this from your auth middleware
func isTokenRevoked(jti, sub string) bool {
    mu.RLock()
    defer mu.RUnlock()
    return revokedTokens[jti] || revokedSubs[sub]
}`

const PYTHON_SNIPPET = `# Python/FastAPI resource server — CAE SET receiver
from fastapi import FastAPI, Request, HTTPException
import jwt, httpx, asyncio, threading

app = FastAPI()
revoked_jtis: set[str] = set()
revoked_subs: set[str] = set()
lock = threading.Lock()

JWKS_URL = "https://{issuer}/.well-known/jwks.json"
TOKEN_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

@app.post("/ssf/receiver")
async def ssf_receiver(request: Request):
    raw = await request.body()
    try:
        # Fetch JWKS and verify the secevent+jwt
        keys = httpx.get(JWKS_URL).json()
        payload = jwt.decode(raw, keys, algorithms=["RS256"])
    except Exception:
        raise HTTPException(status_code=400, detail="invalid SET")

    events = payload.get("events", {})
    sub = (payload.get("sub_id") or {}).get("sub")

    with lock:
        if body := events.get(TOKEN_REVOKED):
            if body.get("change_type") == "revoke":
                if jti := body.get("token_jti"):
                    revoked_jtis.add(jti)

        if SESSION_REVOKED in events and sub:
            revoked_subs.add(sub)

    return {"status": "accepted"}

# Dependency — use in FastAPI routes
def check_not_revoked(jti: str, sub: str):
    if jti in revoked_jtis or sub in revoked_subs:
        raise HTTPException(status_code=401, detail="token_revoked")`

const SNIPPETS = [
  { label: 'Node.js / Express', lang: 'typescript', code: NODE_SNIPPET },
  { label: 'Go',                lang: 'go',         code: GO_SNIPPET    },
  { label: 'Python / FastAPI',  lang: 'python',     code: PYTHON_SNIPPET },
]

// ── Main component ─────────────────────────────────────────────────────────────

export default function CAEMonitor() {
  const orgId   = useAuthStore(s => s.orgId)
  const orgSlug = useAuthStore(s => s.orgSlug)
  const [snippetIdx, setSnippetIdx] = useState(0)
  const [expandedStream, setExpandedStream] = useState<string | null>(null)
  const [showSnippets, setShowSnippets] = useState(false)

  // Fetch all SSF streams for this org (admin API with delivery health)
  const { data: streams = [], isLoading, refetch } = useQuery<SSFStream[]>({
    queryKey: ['ssf-streams-admin', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/ssf/streams`).then(r =>
      Array.isArray(r.data) ? r.data : []
    ),
    enabled: !!orgId,
    refetchInterval: 30_000,
  })

  // Test push mutation — fires a verification SET to the stream's push endpoint
  const testPush = useMutation({
    mutationFn: (stream: SSFStream) =>
      api.post(`/${orgSlug}/ssf/stream/verify`, { state: 'cae-test' }, {
        headers: { Authorization: `Bearer ${stream.client_id}` },
      }).then(r => r.data),
    onSuccess: (data) => {
      toast.success(`Verification SET sent — ${data.status}`)
      refetch()
    },
    onError: () => toast.error('Push delivery failed — check the endpoint'),
  })

  const pushStreams = streams.filter(s => s.delivery_method === 'push')
  const pollStreams = streams.filter(s => s.delivery_method === 'poll')

  const overallHealth = pushStreams.length === 0 ? 'no-receivers'
    : pushStreams.every(s => s.last_delivery?.ok) ? 'healthy'
    : pushStreams.some(s => s.last_delivery && !s.last_delivery.ok) ? 'degraded'
    : 'unknown'

  return (
    <div style={{ padding: '28px 32px 60px', maxWidth: 1100, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <p style={{ ...mono, fontSize: 11, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--clavex-primary)', marginBottom: 8 }}>
          ◈ CAEP · RFC 9700 · Zero Trust
        </p>
        <h1 style={{ fontSize: 24, fontWeight: 300, color: 'var(--clavex-ink)', letterSpacing: '-0.02em', margin: 0 }}>
          Continuous Access <strong style={{ fontWeight: 700 }}>Evaluation</strong>
        </h1>
        <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginTop: 6, maxWidth: 680 }}>
          Resource servers subscribed to SSF push streams receive a <code style={{ ...mono, fontSize: 12, color: 'var(--clavex-primary)' }}>session-revoked</code> or{' '}
          <code style={{ ...mono, fontSize: 12, color: 'var(--clavex-primary)' }}>token-claims-change</code> SET the instant a token is revoked —
          eliminating the gap between revocation and expiry for both JWT and opaque tokens.
        </p>
      </div>

      {/* Summary bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { label: 'Push receivers',  value: pushStreams.length,  color: 'var(--clavex-primary)' },
          { label: 'Poll receivers',  value: pollStreams.length,  color: 'var(--clavex-neutral)' },
          { label: 'Healthy',         value: pushStreams.filter(s => s.last_delivery?.ok).length, color: '#16a34a' },
          { label: 'Last error',      value: pushStreams.filter(s => s.last_delivery && !s.last_delivery.ok).length, color: '#E24B4A' },
        ].map(({ label, value, color }) => (
          <div key={label} style={card({ padding: '16px 20px' })}>
            <div style={{ fontSize: 28, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
            <div style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginTop: 4 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Status banner */}
      {overallHealth === 'no-receivers' && (
        <div style={{
          ...card({ padding: '16px 20px', marginBottom: 24 }),
          border: '0.5px solid rgba(245,200,66,0.4)',
          background: 'rgba(245,200,66,0.05)',
          display: 'flex', alignItems: 'flex-start', gap: 12,
        }}>
          <AlertTriangle size={18} color="#F5C842" style={{ flexShrink: 0, marginTop: 1 }} />
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', margin: '0 0 4px' }}>
              No push receivers registered
            </p>
            <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: 0 }}>
              Register a resource server via{' '}
              <strong>Shared Signals (SSF)</strong> → Create stream (push delivery) to enable real-time token revocation.
              Until then, RSes fall back to introspection polling (up to 30 s delay).
            </p>
          </div>
        </div>
      )}

      {/* Streams list */}
      {streams.length > 0 && (
        <div style={card({ marginBottom: 24, overflow: 'hidden' })}>
          <div style={{ padding: '16px 20px', borderBottom: '0.5px solid var(--clavex-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Radio size={14} color="var(--clavex-primary)" />
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--clavex-ink)' }}>SSF Receivers</span>
            </div>
            <button
              onClick={() => refetch()}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--clavex-neutral)', display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 }}
            >
              <RefreshCw size={12} /> Refresh
            </button>
          </div>

          {isLoading
            ? <div style={{ padding: 32, textAlign: 'center', color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</div>
            : streams.map((s, i) => (
              <div key={s.stream_id} style={{ borderBottom: i < streams.length - 1 ? '0.5px solid var(--clavex-border)' : 'none' }}>
                <button
                  onClick={() => setExpandedStream(expandedStream === s.stream_id ? null : s.stream_id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 14, width: '100%',
                    padding: '14px 20px', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left',
                  }}
                >
                  {/* Health indicator */}
                  <HealthDot stream={s} />

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ ...mono, fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)' }}>
                        {s.description || s.client_id}
                      </span>
                      <span style={badge(s.delivery_method === 'push' ? 'var(--clavex-primary)' : 'var(--clavex-neutral)')}>
                        {s.delivery_method}
                      </span>
                      <span style={badge(s.status === 'enabled' ? '#16a34a' : s.status === 'paused' ? '#F5C842' : '#E24B4A')}>
                        {s.status}
                      </span>
                    </div>
                    <div style={{ ...mono, fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 3 }}>
                      {s.push_endpoint || `poll · ${s.events_requested.length} events`}
                    </div>
                  </div>

                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    {s.last_delivery ? (
                      <div>
                        <div style={{ fontSize: 11, color: s.last_delivery.ok ? '#16a34a' : '#E24B4A', fontWeight: 600 }}>
                          {s.last_delivery.ok ? '✓ OK' : '✗ Error'}
                        </div>
                        <div style={{ ...mono, fontSize: 10, color: 'var(--clavex-neutral)', marginTop: 2 }}>
                          {relativeTime(s.last_delivery.ts)}
                        </div>
                      </div>
                    ) : (
                      <span style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>No deliveries yet</span>
                    )}
                  </div>

                  {expandedStream === s.stream_id
                    ? <ChevronUp size={14} color="var(--clavex-neutral)" style={{ flexShrink: 0 }} />
                    : <ChevronDown size={14} color="var(--clavex-neutral)" style={{ flexShrink: 0 }} />
                  }
                </button>

                {expandedStream === s.stream_id && (
                  <StreamDetail stream={s} onTestPush={() => testPush.mutate(s)} isPending={testPush.isPending} />
                )}
              </div>
            ))
          }
        </div>
      )}

      {/* CAE event flow diagram (inline SVG-style text art) */}
      <div style={card({ padding: 24, marginBottom: 24 })}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
          <Zap size={14} color="var(--clavex-primary)" />
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--clavex-ink)' }}>How CAE push works</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 0, alignItems: 'center' }}>
          {[
            { label: 'Admin / user\nrevokes token', icon: Shield, color: '#E24B4A' },
            null,
            { label: 'Clavex dispatches\nCAEP SET (push)', icon: Zap, color: 'var(--clavex-primary)' },
            null,
            { label: 'RS invalidates\nlocal cache', icon: CheckCircle2, color: '#16a34a' },
          ].map((item, i) =>
            item === null ? (
              <div key={i} style={{ textAlign: 'center', color: 'var(--clavex-neutral)', fontSize: 20, letterSpacing: 4 }}>→</div>
            ) : (
              <div key={i} style={{ textAlign: 'center', padding: '12px 8px', borderRadius: 8, background: `${item.color}08`, border: `0.5px solid ${item.color}30` }}>
                <item.icon size={20} color={item.color} style={{ margin: '0 auto 8px' }} />
                <p style={{ fontSize: 11, color: 'var(--clavex-ink)', margin: 0, whiteSpace: 'pre-line', lineHeight: 1.4 }}>{item.label}</p>
              </div>
            )
          )}
        </div>
        <div style={{ marginTop: 14, padding: '10px 14px', borderRadius: 8, background: 'rgba(93,202,165,0.05)', border: '0.5px solid rgba(93,202,165,0.2)' }}>
          <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: 0 }}>
            <strong style={{ color: 'var(--clavex-ink)' }}>Result:</strong>{' '}
            Token revocation takes effect in <strong>&lt; 1 s</strong> instead of up to 1 h (JWT expiry) or 30 s (introspection cache TTL).
            The RS does not need to poll — it receives the SET and removes the token from its local cache immediately.
          </p>
        </div>
      </div>

      {/* RS integration code snippets */}
      <div style={card({ overflow: 'hidden', marginBottom: 24 })}>
        <button
          onClick={() => setShowSnippets(s => !s)}
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            width: '100%', padding: '14px 20px', background: 'none', border: 'none', cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Code2 size={14} color="var(--clavex-neutral)" />
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--clavex-ink)' }}>RS integration — SET receiver</span>
            <span style={{ ...mono, fontSize: 10, padding: '2px 7px', borderRadius: 10, background: 'var(--clavex-surface)', color: 'var(--clavex-neutral)', border: '0.5px solid var(--clavex-border)' }}>
              Node · Go · Python
            </span>
          </div>
          {showSnippets ? <ChevronUp size={14} color="var(--clavex-neutral)" /> : <ChevronDown size={14} color="var(--clavex-neutral)" />}
        </button>

        {showSnippets && (
          <div style={{ borderTop: '0.5px solid var(--clavex-border)' }}>
            {/* Language tabs */}
            <div style={{ display: 'flex', padding: '12px 20px 0', gap: 4 }}>
              {SNIPPETS.map((s, i) => (
                <button
                  key={i}
                  onClick={() => setSnippetIdx(i)}
                  style={{
                    padding: '6px 14px', borderRadius: '6px 6px 0 0', fontSize: 12, fontWeight: 600, cursor: 'pointer',
                    border: '0.5px solid var(--clavex-border)', borderBottom: snippetIdx === i ? 'none' : '0.5px solid var(--clavex-border)',
                    background: snippetIdx === i ? 'var(--clavex-surface)' : 'transparent',
                    color: snippetIdx === i ? 'var(--clavex-ink)' : 'var(--clavex-neutral)',
                  }}
                >
                  {s.label}
                </button>
              ))}
            </div>

            <div style={{ position: 'relative', background: '#0D1F2D', margin: '0 20px 20px', borderRadius: 8, border: '0.5px solid rgba(93,202,165,0.15)' }}>
              <button
                onClick={() => { navigator.clipboard.writeText(SNIPPETS[snippetIdx].code); toast.success('Copied') }}
                style={{
                  position: 'absolute', top: 10, right: 10,
                  background: 'rgba(93,202,165,0.1)', border: '0.5px solid rgba(93,202,165,0.3)',
                  borderRadius: 6, padding: '4px 10px', cursor: 'pointer', color: 'var(--clavex-primary)',
                  display: 'flex', alignItems: 'center', gap: 5, fontSize: 11,
                }}
              >
                <Copy size={11} /> Copy
              </button>
              <pre style={{
                ...mono, fontSize: 12, lineHeight: 1.7, color: '#C4DFF0',
                margin: 0, padding: '16px', overflowX: 'auto', whiteSpace: 'pre',
              }}>
                {SNIPPETS[snippetIdx].code}
              </pre>
            </div>

            <div style={{ padding: '0 20px 20px' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '12px 14px', borderRadius: 8, background: 'rgba(93,202,165,0.05)', border: '0.5px solid rgba(93,202,165,0.2)' }}>
                <Info size={14} color="var(--clavex-primary)" style={{ flexShrink: 0, marginTop: 1 }} />
                <div style={{ fontSize: 12, color: 'var(--clavex-neutral)', lineHeight: 1.6 }}>
                  Register your RS endpoint via <strong style={{ color: 'var(--clavex-ink)' }}>Shared Signals → Create stream</strong> with delivery method <code style={mono}>push</code> and subscribe to{' '}
                  <code style={{ ...mono, color: 'var(--clavex-primary)' }}>session-revoked</code> and{' '}
                  <code style={{ ...mono, color: 'var(--clavex-primary)' }}>token-claims-change</code> events.
                  Clavex signs SETs with <code style={mono}>RS256</code> — verify using the JWKS at{' '}
                  <code style={{ ...mono, color: 'var(--clavex-primary)' }}>/{'{org_slug}'}/.well-known/jwks.json</code>.
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* CAEP event coverage table */}
      <div style={card({ padding: 24 })}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
          <Wifi size={14} color="var(--clavex-primary)" />
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--clavex-ink)' }}>Supported CAEP/RISC events</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
          {[
            { uri: 'session-revoked',        trigger: 'Admin revokes session / user logs out',   since: 'always' },
            { uri: 'token-claims-change',    trigger: 'RFC 7009 POST /revoke (access token)',     since: 'this release' },
            { uri: 'credential-change',      trigger: 'Password changed / passkey added',         since: 'always' },
            { uri: 'account-disabled',       trigger: 'Admin disables user account',              since: 'always' },
            { uri: 'sessions-revoked',       trigger: 'Bulk session revocation (RISC)',           since: 'always' },
            { uri: 'assurance-level-change', trigger: 'MFA downgrade / LOA change',              since: 'always' },
          ].map(row => (
            <div key={row.uri} style={{ padding: '10px 12px', borderRadius: 8, background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)' }}>
              <div style={{ ...mono, fontSize: 11, color: 'var(--clavex-primary)', marginBottom: 4, wordBreak: 'break-word' }}>
                {row.uri}
              </div>
              <div style={{ fontSize: 11, color: 'var(--clavex-neutral)', lineHeight: 1.4 }}>{row.trigger}</div>
              {row.since === 'this release' && (
                <div style={{ ...badge('var(--clavex-primary)'), marginTop: 6, fontSize: 10 }}>
                  <Zap size={9} /> new
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Stream detail expansion ────────────────────────────────────────────────────

function StreamDetail({ stream, onTestPush, isPending }: {
  stream: SSFStream
  onTestPush: () => void
  isPending: boolean
}) {
  return (
    <div style={{ padding: '0 20px 20px', borderTop: '0.5px solid var(--clavex-border)' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 14 }}>
        <div>
          <p style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--clavex-neutral)', margin: '0 0 8px' }}>
            Subscribed events
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {stream.events_requested.map(e => (
              <span key={e} style={{ ...badge('var(--clavex-primary)'), fontSize: 10 }}>
                {shortEvent(e)}
              </span>
            ))}
          </div>
        </div>
        <div>
          <p style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--clavex-neutral)', margin: '0 0 8px' }}>
            Last delivery
          </p>
          {stream.last_delivery ? (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {stream.last_delivery.ok
                  ? <CheckCircle2 size={13} color="#16a34a" />
                  : <XCircle size={13} color="#E24B4A" />
                }
                <span style={{ fontSize: 12, color: stream.last_delivery.ok ? '#16a34a' : '#E24B4A', fontWeight: 600 }}>
                  {stream.last_delivery.ok ? 'Delivered' : 'Failed'}
                </span>
              </div>
              <div style={{ ...mono, fontSize: 10, color: 'var(--clavex-neutral)', marginTop: 4 }}>
                {new Date(stream.last_delivery.ts).toLocaleString()} · {shortEvent(stream.last_delivery.event_type)}
              </div>
              {stream.last_delivery.error && (
                <div style={{ ...mono, fontSize: 10, color: '#E24B4A', marginTop: 3 }}>
                  {stream.last_delivery.error}
                </div>
              )}
            </div>
          ) : (
            <span style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>No deliveries recorded</span>
          )}
        </div>
      </div>

      {stream.delivery_method === 'push' && stream.status === 'enabled' && (
        <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Button
            variant="secondary"
            onClick={onTestPush}
            loading={isPending}
            style={{ fontSize: 12 }}
          >
            <Play size={12} /> Send test SET
          </Button>
          <span style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>
            Sends a verification SET to <code style={mono}>{stream.push_endpoint}</code>
          </span>
        </div>
      )}

      <div style={{ marginTop: 12, ...mono, fontSize: 10, color: 'var(--clavex-neutral)' }}>
        stream_id: {stream.stream_id} · client_id: {stream.client_id} · registered {relativeTime(stream.created_at)}
      </div>
    </div>
  )
}

// ── Health dot ─────────────────────────────────────────────────────────────────

function HealthDot({ stream }: { stream: SSFStream }) {
  if (stream.delivery_method === 'poll') {
    return <Clock size={16} color="var(--clavex-neutral)" style={{ flexShrink: 0 }} />
  }
  if (!stream.last_delivery) {
    return <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'var(--clavex-neutral)', flexShrink: 0 }} />
  }
  const color = stream.last_delivery.ok ? '#16a34a' : '#E24B4A'
  return (
    <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, flexShrink: 0, animation: stream.last_delivery.ok ? undefined : 'pulse 1.5s infinite' }} />
  )
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}
