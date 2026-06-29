import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import {
  ShieldOff, Unlock, Mail, RefreshCw, Clock, TriangleAlert,
  Loader2, Shield, SlidersHorizontal, Trash2, CheckCircle,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface LockoutBand {
  score_min: number
  score_max: number
  max_attempts: number
  lockout_seconds: number
}

interface LockoutConfig {
  bands: LockoutBand[]
  alert_admin: boolean
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatSeconds(s: number): string {
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.round(s / 60)}m`
  return `${Math.round(s / 3600)}h`
}

const BAND_COLORS: [number, string][] = [
  [79, '#ef4444'],  // critical
  [59, '#f59e0b'],  // high
  [29, '#3b82f6'],  // medium
  [0,  '#22c55e'],  // low
]
function bandColor(scoreMin: number): string {
  for (const [threshold, color] of BAND_COLORS) {
    if (scoreMin >= threshold) return color
  }
  return '#6b7280'
}

// ── Unlock form ───────────────────────────────────────────────────────────────

function UnlockPanel({ orgId }: { orgId: string }) {
  const [email, setEmail] = useState('')
  const [mode, setMode]   = useState<'instant' | 'magic'>('magic')

  const qc = useQueryClient()

  const instantMutation = useMutation({
    mutationFn: (email: string) =>
      api.put(`/organizations/${orgId}/lockout/unlock/${encodeURIComponent(email)}`),
    onSuccess: () => {
      toast.success(`Lockout cleared for ${email}`)
      setEmail('')
      qc.invalidateQueries({ queryKey: ['lockout-config', orgId] })
    },
    onError: () => toast.error('Failed to clear lockout'),
  })

  const magicMutation = useMutation({
    mutationFn: (email: string) =>
      api.post(`/organizations/${orgId}/lockout/unlock-link`, { email }),
    onSuccess: () => {
      toast.success(`Unlock link sent to ${email}`)
      setEmail('')
    },
    onError: () => toast.error('Failed to send unlock link'),
  })

  const isLoading = instantMutation.isPending || magicMutation.isPending

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = email.trim()
    if (!trimmed) { toast.error('Enter an email address'); return }
    if (mode === 'instant') instantMutation.mutate(trimmed)
    else magicMutation.mutate(trimmed)
  }

  return (
    <div className="rounded-xl p-5 space-y-4"
      style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>

      <div className="flex items-center gap-2">
        <ShieldOff size={16} style={{ color: 'var(--clavex-accent)' }} />
        <h2 className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>Unlock a locked account</h2>
      </div>

      {/* Mode toggle */}
      <div className="flex gap-2">
        {(['magic', 'instant'] as const).map(m => (
          <button key={m} type="button" onClick={() => setMode(m)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
            style={{
              background: mode === m ? 'rgba(93,202,165,0.15)' : 'var(--clavex-surface)',
              border: `1px solid ${mode === m ? 'rgba(93,202,165,0.5)' : 'var(--clavex-border)'}`,
              color: mode === m ? 'var(--clavex-accent)' : 'var(--clavex-muted)',
              cursor: 'pointer',
            }}>
            {m === 'magic' ? <><Mail size={12} /> Send magic link</> : <><Unlock size={12} /> Instant unlock</>}
          </button>
        ))}
      </div>

      {/* Mode description */}
      <p className="text-xs" style={{ color: 'var(--clavex-muted)' }}>
        {mode === 'magic'
          ? 'A one-time unlock link (valid for 15 minutes) is emailed to the user. The user clicks it to self-serve their account back. Requires SMTP to be configured.'
          : 'Immediately clears the Redis lockout for the account. No email is sent. Use when the user is on the phone with support.'}
      </p>

      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          type="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          placeholder="user@example.com"
          className="flex-1 rounded-lg px-3 py-2 text-sm"
          style={{
            background: 'var(--clavex-surface)',
            border: '1px solid var(--clavex-border)',
            color: 'var(--clavex-ink)',
            outline: 'none',
          }}
        />
        <button type="submit" disabled={isLoading}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium"
          style={{
            background: mode === 'magic' ? 'var(--clavex-accent)' : '#f59e0b',
            color: mode === 'magic' ? '#0d1f1a' : '#fff',
            opacity: isLoading ? 0.6 : 1,
            cursor: isLoading ? 'not-allowed' : 'pointer',
          }}>
          {isLoading
            ? <><Loader2 size={14} className="animate-spin" /> Sending…</>
            : mode === 'magic'
              ? <><Mail size={14} /> Send link</>
              : <><Unlock size={14} /> Unlock now</>
          }
        </button>
      </form>

      {mode === 'magic' && (
        <div className="rounded-lg p-3 text-xs flex gap-2"
          style={{ background: 'rgba(93,202,165,0.06)', border: '1px solid rgba(93,202,165,0.15)', color: 'var(--clavex-muted)' }}>
          <Clock size={13} className="flex-shrink-0 mt-0.5" style={{ color: 'var(--clavex-accent)' }} />
          The link is signed with a 24-byte random token, stored in Redis with a 15-minute TTL, and consumed atomically on first use — it cannot be replayed.
        </div>
      )}
    </div>
  )
}

// ── Lockout band config panel ─────────────────────────────────────────────────

function BandConfig({ orgId }: { orgId: string }) {
  const qc = useQueryClient()

  const { data, isLoading } = useQuery<LockoutConfig>({
    queryKey: ['lockout-config', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/lockout`).then(r => r.data),
    enabled: !!orgId,
  })

  const resetMutation = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/lockout`),
    onSuccess: () => {
      toast.success('Lockout config reset to defaults')
      qc.invalidateQueries({ queryKey: ['lockout-config', orgId] })
    },
    onError: () => toast.error('Failed to reset lockout config'),
  })

  if (isLoading) return (
    <div className="rounded-xl p-5 flex items-center justify-center h-32"
      style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
      <Loader2 size={18} className="animate-spin" style={{ color: 'var(--clavex-muted)' }} />
    </div>
  )

  const bands = data?.bands ?? []

  return (
    <div className="rounded-xl p-5 space-y-4"
      style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SlidersHorizontal size={16} style={{ color: 'var(--clavex-accent)' }} />
          <h2 className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>Active lockout bands</h2>
        </div>
        <button onClick={() => resetMutation.mutate()} disabled={resetMutation.isPending}
          className="flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg"
          style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', color: 'var(--clavex-muted)', cursor: 'pointer' }}>
          <Trash2 size={11} /> Reset to defaults
        </button>
      </div>

      <p className="text-xs" style={{ color: 'var(--clavex-muted)' }}>
        Lockout duration scales with the real-time risk score. Edit via <code style={{ background: 'var(--clavex-surface)', borderRadius: 4, padding: '1px 4px' }}>PUT /lockout</code>.
      </p>

      <div className="space-y-2">
        {bands.map((b, i) => (
          <div key={i} className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)' }}>
            {/* Risk score range pill */}
            <span className="flex-shrink-0 font-mono px-2 py-0.5 rounded-full text-white text-[11px] font-semibold"
              style={{ background: bandColor(b.score_min) }}>
              {b.score_min}–{b.score_max}
            </span>
            <span style={{ color: 'var(--clavex-muted)' }}>
              Max <strong style={{ color: 'var(--clavex-ink)' }}>{b.max_attempts}</strong> attempt{b.max_attempts !== 1 ? 's' : ''}
              {' → '}
              lock for <strong style={{ color: 'var(--clavex-ink)' }}>{formatSeconds(b.lockout_seconds)}</strong>
            </span>
            <span className="ml-auto flex items-center gap-1" style={{ color: bandColor(b.score_min) }}>
              <Shield size={11} />
              {b.score_min >= 80 ? 'Critical' : b.score_min >= 60 ? 'High' : b.score_min >= 30 ? 'Medium' : 'Low'} risk
            </span>
          </div>
        ))}
      </div>

      {data?.alert_admin && (
        <div className="flex items-center gap-2 text-xs px-3 py-2 rounded-lg"
          style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)', color: '#f59e0b' }}>
          <TriangleAlert size={12} />
          Admin alert is enabled — you will be notified when the highest-risk band triggers a lockout.
        </div>
      )}
    </div>
  )
}

// ── How it works info panel ───────────────────────────────────────────────────

function HowItWorks() {
  const steps = [
    {
      icon: <TriangleAlert size={14} style={{ color: '#f59e0b' }} />,
      title: 'Adaptive lockout triggered',
      body: 'Too many failed attempts or a high-risk signal (Tor, new country, impossible travel) triggers a time-boxed lockout scaled to the risk score.',
    },
    {
      icon: <Mail size={14} style={{ color: 'var(--clavex-accent)' }} />,
      title: 'Admin sends magic link',
      body: 'From this page, enter the user\'s email and click "Send magic link". A one-time HMAC-signed link valid for 15 minutes is delivered to the user\'s inbox.',
    },
    {
      icon: <Unlock size={14} style={{ color: '#22c55e' }} />,
      title: 'User self-serves',
      body: 'The user clicks the link in their email. The backend atomically consumes the token, calls ClearFailures() on the Guard, and redirects to the login page with ?unlocked=1.',
    },
    {
      icon: <CheckCircle size={14} style={{ color: '#22c55e' }} />,
      title: 'Login resumes',
      body: 'The lockout key is gone from Redis. The user can log in again immediately. The token cannot be replayed (one-time, stored in Redis).',
    },
  ]

  return (
    <div className="rounded-xl p-5 space-y-3"
      style={{ background: 'var(--clavex-card)', border: '1px solid var(--clavex-border)' }}>
      <div className="flex items-center gap-2">
        <RefreshCw size={14} style={{ color: 'var(--clavex-accent)' }} />
        <h2 className="text-sm font-semibold" style={{ color: 'var(--clavex-ink)' }}>How it works</h2>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {steps.map((s, i) => (
          <div key={i} className="rounded-lg p-3 space-y-1"
            style={{ background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)' }}>
            <div className="flex items-center gap-1.5 font-medium text-xs" style={{ color: 'var(--clavex-ink)' }}>
              {s.icon}
              <span>{i + 1}. {s.title}</span>
            </div>
            <p className="text-xs leading-relaxed" style={{ color: 'var(--clavex-muted)' }}>{s.body}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function LockoutAdmin() {
  const orgId = useAuthStore(s => s.orgId)

  if (!orgId) return null

  return (
    <div className="space-y-5">

      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-10 h-10 rounded-lg"
          style={{ background: 'rgba(93,202,165,0.12)' }}>
          <ShieldOff size={20} style={{ color: 'var(--clavex-accent)' }} />
        </div>
        <div>
          <h1 className="text-lg font-semibold" style={{ color: 'var(--clavex-ink)' }}>
            Clavex Guard — Account Unlock
          </h1>
          <p className="text-sm" style={{ color: 'var(--clavex-muted)' }}>
            Send a one-time magic link to unblock a legitimately locked account without waiting for the TTL.
          </p>
        </div>
      </div>

      <UnlockPanel orgId={orgId} />
      <BandConfig orgId={orgId} />
      <HowItWorks />
    </div>
  )
}
