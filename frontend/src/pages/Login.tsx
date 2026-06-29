import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { AlertBanner } from '@/components/ui'
import api from '@/lib/api'
import { Building2, Mail, Lock } from 'lucide-react'
import { ClavexLogo } from '@/components/logo/ClavexLogo'

export default function LoginPage() {
  const navigate = useNavigate()
  const setAuth = useAuthStore((s) => s.setAuth)
  const [orgSlug, setOrgSlug] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const { data } = await api.post('/auth/login', { org_slug: orgSlug, email, password })
      setAuth(data.org_id, data.org_slug, data.email ?? email, data.is_super_admin)
      navigate(data.is_super_admin ? '/admin/orgs' : `/admin/${data.org_slug}`)
    } catch {
      setError('Invalid organization, email, or password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex" style={{ fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
      {/* Left panel — dark 44% */}
      <div
        className="hidden lg:flex lg:w-[44%] flex-col justify-between p-12 relative overflow-hidden"
        style={{ background: 'var(--clavex-dark)' }}
      >
        {/* Subtle mesh background */}
        <div className="absolute inset-0 pointer-events-none" style={{ opacity: 0.06 }}>
          <div style={{
            position: 'absolute', top: -80, right: -80,
            width: 380, height: 380, borderRadius: '50%',
            background: 'var(--clavex-primary)',
            filter: 'blur(80px)',
          }} />
          <div style={{
            position: 'absolute', bottom: -100, left: -60,
            width: 320, height: 320, borderRadius: '50%',
            background: 'var(--clavex-400)',
            filter: 'blur(80px)',
          }} />
        </div>

        {/* Top: logo */}
        <div className="relative">
          <ClavexLogo variant="dark" size={0.6} />
        </div>

        {/* Middle: tagline */}
        <div className="relative">
          <p style={{ fontSize: 11, fontWeight: 700, letterSpacing: '2.5px', color: 'rgba(196,223,240,0.4)', marginBottom: 20, textTransform: 'uppercase' }}>
            Identity &amp; Access Management
          </p>
          <blockquote>
            <span style={{ fontSize: 22, fontWeight: 300, lineHeight: 1.5, color: 'rgba(196,223,240,0.75)' }}>
              "Identity that stays where you put it.{' '}
            </span>
            <span style={{ fontSize: 22, fontWeight: 700, lineHeight: 1.5, color: 'var(--clavex-400)' }}>
              In Europe."
            </span>
          </blockquote>

          <div className="mt-8 flex flex-col gap-3">
            {[
              { label: 'Self-hostable', note: 'EU Kubernetes-native' },
              { label: 'No vendor lock-in', note: 'Full data ownership' },
              { label: 'Data stays in EU', note: 'GDPR · NIS2 · eIDAS 2.0' },
            ].map(({ label, note }) => (
              <div key={label} className="flex items-center gap-3">
                <div style={{
                  width: 18, height: 18, borderRadius: '50%', flexShrink: 0,
                  background: 'rgba(29,158,117,0.15)', border: '0.5px solid var(--clavex-primary)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <svg width="9" height="7" viewBox="0 0 9 7" fill="none">
                    <path d="M1 3.5L3.5 6L8 1" stroke="#1D9E75" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>
                <span style={{ fontSize: 13, fontWeight: 500, color: 'rgba(196,223,240,0.8)' }}>{label}</span>
                <span style={{ fontSize: 11, color: 'rgba(196,223,240,0.35)' }}>{note}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom: compliance badges */}
        <div className="relative">
          <p style={{ fontSize: 9, fontWeight: 700, letterSpacing: '2px', color: 'rgba(196,223,240,0.3)', marginBottom: 10, textTransform: 'uppercase' }}>
            All data processed in EU
          </p>
          <div className="flex flex-wrap gap-2">
            {['GDPR', 'NIS2', 'eIDAS 2.0', 'ISO 27001'].map((badge) => (
              <span key={badge} style={{
                padding: '3px 10px', borderRadius: 20, fontSize: 10, fontWeight: 700,
                letterSpacing: '0.5px',
                background: 'var(--clavex-dark-surface)',
                border: '0.5px solid var(--clavex-primary)',
                color: 'var(--clavex-400)',
              }}>{badge}</span>
            ))}
          </div>
        </div>
      </div>

      {/* Right panel — white 56% */}
      <div
        className="flex-1 flex items-center justify-center p-8"
        style={{ background: 'white' }}
      >
        <div className="w-full max-w-[360px]">
          {/* Mobile logo */}
          <div className="mb-8 lg:hidden">
            <ClavexLogo variant="light" size={0.55} />
          </div>

          {/* Header */}
          <div className="mb-8">
            <h2 style={{ fontSize: 24, fontWeight: 700, color: 'var(--clavex-ink)', letterSpacing: '-0.5px', marginBottom: 4 }}>
              Welcome back
            </h2>
            <p style={{ fontSize: 14, color: 'var(--clavex-ink-subtle)' }}>
              Sign in to your workspace
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Organization */}
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6 }}>
                Organization
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5" style={{ color: 'var(--clavex-neutral)' }}>
                  <Building2 className="h-4 w-4" />
                </div>
                <input
                  type="text"
                  value={orgSlug}
                  onChange={(e) => setOrgSlug(e.target.value)}
                  placeholder="your-org-slug"
                  required
                  autoFocus
                  className="input-base"
                  style={{ paddingLeft: '2.25rem' }}
                />
              </div>
            </div>

            {/* Email */}
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6 }}>
                Email
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5" style={{ color: 'var(--clavex-neutral)' }}>
                  <Mail className="h-4 w-4" />
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@example.com"
                  required
                  className="input-base"
                  style={{ paddingLeft: '2.25rem' }}
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)' }}>
                  Password
                </label>
                <a href="#" style={{ fontSize: 12, color: 'var(--clavex-700)', fontWeight: 500 }}
                  onClick={(e) => e.preventDefault()}>
                  Forgot password?
                </a>
              </div>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5" style={{ color: 'var(--clavex-neutral)' }}>
                  <Lock className="h-4 w-4" />
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="input-base"
                  style={{ paddingLeft: '2.25rem' }}
                />
              </div>
            </div>

            {error && <AlertBanner variant="danger">{error}</AlertBanner>}

            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                background: loading ? 'var(--clavex-700)' : 'var(--clavex-primary)',
                color: 'white', border: 'none',
                borderRadius: 'var(--clavex-radius-md)',
                padding: '12px 24px', fontSize: 14, fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                transition: 'background 150ms ease',
                marginTop: 8,
              }}
              onMouseEnter={(e) => { if (!loading) (e.currentTarget.style.background = 'var(--clavex-700)') }}
              onMouseLeave={(e) => { if (!loading) (e.currentTarget.style.background = 'var(--clavex-primary)') }}
            >
              {loading ? (
                <div style={{ width: 16, height: 16, borderRadius: '50%', border: '2px solid rgba(255,255,255,0.3)', borderTopColor: 'white', animation: 'spin 0.7s linear infinite' }} />
              ) : null}
              {loading ? 'Signing in…' : 'Sign in →'}
            </button>
          </form>

          {/* Footer */}
          <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', textAlign: 'center', marginTop: 32 }}>
            Protected by{' '}
            <span style={{ fontWeight: 700, color: 'var(--clavex-700)' }}>Clavex</span>
            {' · '}
            <a href="#" style={{ color: 'var(--clavex-neutral)' }} onClick={(e) => e.preventDefault()}>Privacy Policy</a>
            {' · '}
            <span>Data stored in EU</span>
          </p>
        </div>
      </div>
    </div>
  )
}
