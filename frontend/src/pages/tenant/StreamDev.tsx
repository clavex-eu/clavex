import { useState, useEffect, useRef, useCallback } from 'react'
import { useAuthStore } from '@/stores/auth'
import toast from 'react-hot-toast'
import {
  Zap, ZapOff, Circle, Copy, Trash2, Filter, ChevronDown,
  Wifi, WifiOff, Code2, Clock, TriangleAlert, CheckCircle,
  UserPlus, LogIn, LogOut, KeyRound, Shield, X, Download,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface StreamEvent {
  id: string
  type: string           // CloudEvents type e.g. "com.clavex.user.login"
  time: string
  orgid: string
  subject?: string
  data?: {
    action?: string
    status?: string
    actor_email?: string
    resource_type?: string
    resource_id?: string
    ip_address?: string
    country_code?: string
    [key: string]: unknown
  }
  _meta?: { type: 'connected' | 'heartbeat' | 'event' }
}

type ConnectionStatus = 'idle' | 'connecting' | 'connected' | 'disconnected' | 'error'

const FILTERS = [
  { label: 'All events', value: '' },
  { label: 'Login success', value: 'user.login' },
  { label: 'Login failure', value: 'user.login.failed' },
  { label: 'Token issued', value: 'token.issued' },
  { label: 'Token revoked', value: 'token.revoked' },
  { label: 'User created', value: 'user.created' },
  { label: 'Session revoked', value: 'session.revoked' },
  { label: 'MFA success', value: 'mfa.success' },
  { label: 'MFA failure', value: 'mfa.failed' },
  { label: 'Password reset', value: 'password.reset' },
]

// ── Event type → icon / colour ────────────────────────────────────────────────

const EVENT_META: Record<string, { icon: React.ReactNode; color: string; label: string }> = {
  'user.login':         { icon: <LogIn size={11} />,    color: '#22c55e', label: 'Login' },
  'user.login.failed':  { icon: <TriangleAlert size={11} />, color: '#ef4444', label: 'Login failed' },
  'token.issued':       { icon: <KeyRound size={11} />, color: '#3b82f6', label: 'Token issued' },
  'token.revoked':      { icon: <KeyRound size={11} />, color: '#f59e0b', label: 'Token revoked' },
  'user.created':       { icon: <UserPlus size={11} />, color: '#a855f7', label: 'User created' },
  'session.revoked':    { icon: <LogOut size={11} />,   color: '#f59e0b', label: 'Session revoked' },
  'mfa.success':        { icon: <Shield size={11} />,   color: '#22c55e', label: 'MFA success' },
  'mfa.failed':         { icon: <Shield size={11} />,   color: '#ef4444', label: 'MFA failed' },
  'password.reset':     { icon: <CheckCircle size={11} />, color: '#3b82f6', label: 'Password reset' },
}

function eventMeta(action?: string) {
  if (!action) return { icon: <Circle size={11} />, color: '#6b7280', label: 'Event' }
  return EVENT_META[action] ?? { icon: <Circle size={11} />, color: '#6b7280', label: action }
}

// ── Build WebSocket URL ───────────────────────────────────────────────────────

// buildWsUrl builds the Stream WebSocket URL. The live admin-console connection
// omits the token: the browser sends the HttpOnly session cookie automatically
// on the same-origin handshake. A token is only passed for the copy-paste SDK
// snippets, where an external client authenticates via the ?token= query param.
function buildWsUrl(slug: string, action: string, token?: string): string {
  const apiBase = import.meta.env.VITE_API_URL ?? window.location.origin
  // Replace http(s):// with ws(s)://
  const wsBase = apiBase.replace(/^http/, 'ws')
  const params = new URLSearchParams()
  if (token) params.set('token', token)
  if (action) params.set('action', action)
  const qs = params.toString()
  return `${wsBase}/${slug}/events${qs ? `?${qs}` : ''}`
}

// ── SDK Snippets ──────────────────────────────────────────────────────────────

const SDK_SNIPPETS = (wsUrl: string) => ({
  JavaScript: `const ws = new WebSocket(
  "${wsUrl}"
)

ws.onopen  = () => console.log('🔌 Clavex Stream connected')
ws.onclose = () => console.log('🔌 Clavex Stream disconnected')

ws.onmessage = ({ data }) => {
  const evt = JSON.parse(data)
  if (evt.type === 'heartbeat') return
  console.log('[%s] %s → %s', evt.time, evt.data?.action, evt.data?.actor_email)
}`,

  Python: `import asyncio, json, websockets

async def main():
    async with websockets.connect("${wsUrl}") as ws:
        async for msg in ws:
            evt = json.loads(msg)
            if evt.get("type") == "heartbeat":
                continue
            print(f"[{evt['time']}] {evt['data']['action']} → {evt['data'].get('actor_email')}")

asyncio.run(main())`,

  Go: `package main

import (
    "encoding/json"
    "fmt"
    "github.com/gorilla/websocket"
)

func main() {
    c, _, err := websocket.DefaultDialer.Dial("${wsUrl}", nil)
    if err != nil { panic(err) }
    defer c.Close()

    for {
        _, msg, err := c.ReadMessage()
        if err != nil { break }
        var evt map[string]any
        _ = json.Unmarshal(msg, &evt)
        if data, ok := evt["data"].(map[string]any); ok {
            fmt.Println(evt["time"], data["action"], data["actor_email"])
        }
    }
}`,
})

// ── Status badge ──────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<ConnectionStatus, { label: string; color: string; pulse: boolean }> = {
  idle:         { label: 'Idle',         color: '#6b7280', pulse: false },
  connecting:   { label: 'Connecting…',  color: '#f59e0b', pulse: true  },
  connected:    { label: 'Live',         color: '#22c55e', pulse: true  },
  disconnected: { label: 'Disconnected', color: '#f59e0b', pulse: false },
  error:        { label: 'Error',        color: '#ef4444', pulse: false },
}

function StatusBadge({ status }: { status: ConnectionStatus }) {
  const s = STATUS_CONFIG[status]
  return (
    <span className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full"
      style={{ background: `${s.color}1a`, color: s.color, border: `1px solid ${s.color}33` }}>
      <span className={`w-1.5 h-1.5 rounded-full${s.pulse ? ' animate-pulse' : ''}`}
        style={{ background: s.color }} />
      {s.label}
    </span>
  )
}

// ── Event row ─────────────────────────────────────────────────────────────────

function EventRow({ evt, onExpand }: { evt: StreamEvent; onExpand: (e: StreamEvent) => void }) {
  const action = evt.data?.action
  const meta = eventMeta(action)
  const ts = evt.time ? new Date(evt.time).toLocaleTimeString('en-GB', { hour12: false }) : ''

  return (
    <button onClick={() => onExpand(evt)}
      className="w-full flex items-center gap-3 px-3 py-2 text-left rounded-lg hover:bg-white/5 transition-colors text-xs"
      style={{ borderBottom: '1px solid var(--clavex-border)' }}>

      {/* Action badge */}
      <span className="flex-shrink-0 flex items-center gap-1 px-2 py-0.5 rounded-full font-medium"
        style={{ background: `${meta.color}1a`, color: meta.color, border: `1px solid ${meta.color}33` }}>
        {meta.icon} {meta.label}
      </span>

      {/* Email / subject */}
      <span className="flex-1 truncate" style={{ color: 'var(--clavex-ink)' }}>
        {evt.data?.actor_email ?? evt.subject ?? '—'}
      </span>

      {/* IP */}
      {evt.data?.ip_address && (
        <span className="flex-shrink-0 font-mono" style={{ color: 'var(--clavex-muted)' }}>
          {evt.data.ip_address}
          {evt.data.country_code ? ` (${evt.data.country_code})` : ''}
        </span>
      )}

      {/* Time */}
      <span className="flex-shrink-0 font-mono tabular-nums" style={{ color: 'var(--clavex-muted)' }}>
        {ts}
      </span>
    </button>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function StreamDev() {
  const slug   = useAuthStore(s => s.orgSlug)

  const [status,    setStatus]    = useState<ConnectionStatus>('idle')
  const [events,    setEvents]    = useState<StreamEvent[]>([])
  const [filter,    setFilter]    = useState('')
  const [expanded,  setExpanded]  = useState<StreamEvent | null>(null)
  const [activeTab, setActiveTab] = useState<'JavaScript' | 'Python' | 'Go'>('JavaScript')
  const [paused,    setPaused]    = useState(false)
  const wsRef    = useRef<WebSocket | null>(null)
  const listRef  = useRef<HTMLDivElement>(null)

  // Live connection: cookie-authenticated, no token in the URL.
  const wsUrl = slug ? buildWsUrl(slug, filter) : ''

  // Auto-scroll to bottom unless paused
  useEffect(() => {
    if (!paused && listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight
    }
  }, [events, paused])

  const connect = useCallback(() => {
    if (!wsUrl) { toast.error('Not authenticated'); return }
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    setStatus('connecting')
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => setStatus('connected')

    ws.onmessage = (e) => {
      try {
        const raw = JSON.parse(e.data as string)
        if (raw.type === 'heartbeat') return
        if (raw.type === 'connected') return
        setEvents(prev => [...prev.slice(-499), raw as StreamEvent])
      } catch { /* ignore parse errors */ }
    }

    ws.onerror = () => setStatus('error')

    ws.onclose = (e) => {
      setStatus(e.code === 1000 ? 'disconnected' : 'error')
      wsRef.current = null
    }
  }, [wsUrl])

  const disconnect = useCallback(() => {
    wsRef.current?.close(1000, 'user disconnect')
    wsRef.current = null
    setStatus('disconnected')
  }, [])

  // Reconnect when filter changes while connected
  useEffect(() => {
    if (status === 'connected') {
      disconnect()
      setTimeout(connect, 100)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter])

  // Cleanup on unmount
  useEffect(() => () => { wsRef.current?.close() }, [])

  const exportNDJSON = () => {
    const blob = new Blob(events.map(e => JSON.stringify(e) + '\n'), { type: 'application/x-ndjson' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `clavex-stream-${Date.now()}.ndjson`
    a.click()
  }

  // Snippets target external SDK clients, which authenticate via ?token=.
  const snippets = SDK_SNIPPETS(slug ? buildWsUrl(slug, filter, 'YOUR_API_TOKEN') : '')

  return (
    <div className="space-y-5">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg"
            style={{ background: 'rgba(93,202,165,0.12)' }}>
            <Zap size={20} style={{ color: 'var(--clavex-accent)' }} />
          </div>
          <div>
            <h1 className="text-lg font-semibold" style={{ color: 'var(--clavex-ink)' }}>
              Clavex Stream
            </h1>
            <p className="text-sm" style={{ color: 'var(--clavex-muted)' }}>
              Real-time IAM event feed over WebSocket — <code className="text-xs" style={{ color: 'var(--clavex-accent)' }}>wss://…/{slug}/events</code>
            </p>
          </div>
        </div>
        <StatusBadge status={status} />
      </div>

      {/* Controls */}
      <div className="flex items-center gap-2 flex-wrap">
        {status !== 'connected'
          ? (
            <button onClick={connect}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium"
              style={{ background: 'var(--clavex-accent)', color: '#0d1f1a', cursor: 'pointer' }}>
              <Wifi size={14} /> Connect
            </button>
          ) : (
            <button onClick={disconnect}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium"
              style={{ background: 'rgba(239,68,68,0.12)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer' }}>
              <WifiOff size={14} /> Disconnect
            </button>
          )
        }

        {/* Filter */}
        <div className="relative flex items-center">
          <Filter size={12} className="absolute left-2.5" style={{ color: 'var(--clavex-muted)' }} />
          <select value={filter} onChange={e => setFilter(e.target.value)}
            className="pl-7 pr-7 py-2 text-xs rounded-lg appearance-none"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-ink)', cursor: 'pointer' }}>
            {FILTERS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
          <ChevronDown size={12} className="absolute right-2.5 pointer-events-none" style={{ color: 'var(--clavex-muted)' }} />
        </div>

        {/* Pause / resume */}
        <button onClick={() => setPaused(p => !p)}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs"
          style={{ background: paused ? 'rgba(245,158,11,0.1)' : 'var(--clavex-surface)', border: `1px solid ${paused ? 'rgba(245,158,11,0.4)' : 'var(--clavex-border)'}`, color: paused ? '#f59e0b' : 'var(--clavex-muted)', cursor: 'pointer' }}>
          <Clock size={12} /> {paused ? 'Resume scroll' : 'Pause scroll'}
        </button>

        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs" style={{ color: 'var(--clavex-muted)' }}>{events.length} event{events.length !== 1 ? 's' : ''}</span>
          <button onClick={exportNDJSON} disabled={events.length === 0}
            title="Export as NDJSON"
            className="flex items-center gap-1 px-2.5 py-2 rounded-lg text-xs"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: events.length ? 'pointer' : 'not-allowed', opacity: events.length ? 1 : 0.5 }}>
            <Download size={12} /> Export
          </button>
          <button onClick={() => setEvents([])}
            title="Clear events"
            className="flex items-center gap-1 px-2.5 py-2 rounded-lg text-xs"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
            <Trash2 size={12} /> Clear
          </button>
        </div>
      </div>

      {/* Event feed */}
      <div className="rounded-xl overflow-hidden"
        style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>

        {/* Feed header */}
        <div className="flex items-center gap-2 px-3 py-2.5 border-b"
          style={{ borderColor: 'var(--clavex-border)', background: 'var(--clavex-surface)' }}>
          <Circle size={8} className="animate-pulse" style={{ color: status === 'connected' ? '#22c55e' : '#6b7280' }} />
          <span className="text-xs font-medium" style={{ color: 'var(--clavex-ink)' }}>Live feed</span>
          <span className="ml-auto text-xs" style={{ color: 'var(--clavex-muted)' }}>latest 500 events in memory</span>
        </div>

        <div ref={listRef} className="overflow-y-auto" style={{ height: '320px' }}>
          {events.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3"
              style={{ color: 'var(--clavex-muted)' }}>
              {status === 'idle' || status === 'disconnected'
                ? <><ZapOff size={28} /><p className="text-sm">Connect to start streaming events</p></>
                : status === 'connecting'
                ? <><Circle size={28} className="animate-pulse" /><p className="text-sm">Waiting for events…</p></>
                : <><Zap size={28} className="animate-pulse" style={{ color: 'var(--clavex-accent)' }} /><p className="text-sm">Connected — waiting for events…</p></>
              }
            </div>
          ) : (
            events.slice().reverse().map((evt, i) => (
              <EventRow key={evt.id ?? i} evt={evt} onExpand={setExpanded} />
            ))
          )}
        </div>
      </div>

      {/* Expanded event detail */}
      {expanded && (
        <div className="rounded-xl overflow-hidden"
          style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
          <div className="flex items-center justify-between px-3 py-2.5 border-b"
            style={{ borderColor: 'var(--clavex-border)', background: 'var(--clavex-surface)' }}>
            <span className="text-xs font-medium" style={{ color: 'var(--clavex-ink)' }}>Event detail — {expanded.id}</span>
            <div className="flex gap-2">
              <button onClick={() => { navigator.clipboard.writeText(JSON.stringify(expanded, null, 2)); toast.success('Copied') }}
                className="flex items-center gap-1 text-xs px-2 py-1 rounded"
                style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
                <Copy size={11} /> Copy
              </button>
              <button onClick={() => setExpanded(null)}
                className="flex items-center text-xs px-2 py-1 rounded"
                style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
                <X size={11} />
              </button>
            </div>
          </div>
          <pre className="p-4 text-xs overflow-auto" style={{ color: 'var(--clavex-ink)', maxHeight: '200px', fontFamily: 'monospace' }}>
            {JSON.stringify(expanded, null, 2)}
          </pre>
        </div>
      )}

      {/* SDK Snippets */}
      <div className="rounded-xl overflow-hidden"
        style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
        <div className="flex items-center justify-between px-3 py-2.5 border-b"
          style={{ borderColor: 'var(--clavex-border)', background: 'var(--clavex-surface)' }}>
          <div className="flex items-center gap-2">
            <Code2 size={14} style={{ color: 'var(--clavex-accent)' }} />
            <span className="text-xs font-medium" style={{ color: 'var(--clavex-ink)' }}>Connect from your code</span>
          </div>
          <div className="flex gap-1">
            {(['JavaScript', 'Python', 'Go'] as const).map(lang => (
              <button key={lang} onClick={() => setActiveTab(lang)}
                className="text-xs px-2.5 py-1 rounded"
                style={{
                  background: activeTab === lang ? 'rgba(93,202,165,0.15)' : 'transparent',
                  border: `1px solid ${activeTab === lang ? 'rgba(93,202,165,0.4)' : 'transparent'}`,
                  color: activeTab === lang ? 'var(--clavex-accent)' : 'var(--clavex-muted)',
                  cursor: 'pointer',
                }}>
                {lang}
              </button>
            ))}
          </div>
          <button onClick={() => { navigator.clipboard.writeText(snippets[activeTab]); toast.success('Copied') }}
            className="flex items-center gap-1 text-xs px-2.5 py-1 rounded"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
            <Copy size={11} /> Copy
          </button>
        </div>
        <pre className="p-4 text-xs overflow-x-auto" style={{ color: 'var(--clavex-ink)', fontFamily: 'monospace', lineHeight: '1.6' }}>
          {snippets[activeTab]}
        </pre>
      </div>

      {/* Info footer */}
      <div className="grid grid-cols-3 gap-3 text-xs" style={{ color: 'var(--clavex-muted)' }}>
        {[
          { icon: <Zap size={12} />, title: 'No webhook needed', body: 'React to IAM events in real-time without managing webhook endpoints or retries.' },
          { icon: <Shield size={12} />, title: 'Bearer JWT auth', body: 'Authenticate with your admin JWT via Authorization header or ?token= query param.' },
          { icon: <Filter size={12} />, title: 'Server-side filters', body: 'Use ?action=user.login to receive only the event types you care about.' },
        ].map((c, i) => (
          <div key={i} className="rounded-lg p-3 space-y-1"
            style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
            <div className="flex items-center gap-1.5 font-medium" style={{ color: 'var(--clavex-ink)' }}>
              <span style={{ color: 'var(--clavex-accent)' }}>{c.icon}</span> {c.title}
            </div>
            <p className="leading-relaxed">{c.body}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
