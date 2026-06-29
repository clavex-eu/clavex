import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Users, Shield, KeyRound, Palette, FileText, ArrowRight, ShieldCheck, ShieldAlert, Rocket } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import { StatCard, Card } from '@/components/ui'
import api, { toArr } from '@/lib/api'

interface SecurityPosture {
  score: number
  mfa_coverage: number
  passkey_coverage: number
  policy_engine: number
  anomaly_score: number
  total_users: number
  users_with_mfa: number
  users_with_passkey: number
  active_policy_rules: number
  failed_logins_24h: number
}

function SecurityPostureWidget({ orgId }: { orgId: string }) {
  const { data, isLoading } = useQuery<SecurityPosture>({
    queryKey: ['security-posture', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/security-posture`).then(r => r.data),
    enabled: !!orgId,
    staleTime: 60_000,
  })

  if (isLoading || !data) {
    return (
      <div className="p-5" style={{ gridColumn: 'span 2', background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', borderRadius: 12 }}>
        <div style={{ height: 80, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--clavex-neutral)', fontSize: 13 }}>
          Computing posture…
        </div>
      </div>
    )
  }

  const score = data.score
  const color = score >= 80 ? '#16a34a' : score >= 55 ? '#d97706' : '#dc2626'
  const Icon = score >= 55 ? ShieldCheck : ShieldAlert
  const label = score >= 80 ? 'Good' : score >= 55 ? 'Fair' : 'Poor'

  const bars: { name: string; pct: number; raw: string }[] = [
    { name: 'MFA coverage',    pct: data.mfa_coverage,    raw: `${data.users_with_mfa}/${data.total_users} users` },
    { name: 'Passkey coverage',pct: data.passkey_coverage,raw: `${data.users_with_passkey}/${data.total_users} users` },
    { name: 'Policy engine',   pct: data.policy_engine,   raw: data.active_policy_rules > 0 ? `${data.active_policy_rules} rules active` : 'No rules configured' },
    { name: 'Anomaly score',   pct: data.anomaly_score,   raw: `${data.failed_logins_24h} failed logins (24 h)` },
  ]

  return (
    <div className="p-5" style={{ gridColumn: 'span 2', background: 'var(--clavex-surface)', border: '1px solid var(--clavex-border)', borderRadius: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '1.5px', color: 'var(--clavex-neutral)', textTransform: 'uppercase' }}>Security posture</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Icon style={{ width: 16, height: 16, color }} />
          <span style={{ fontSize: 24, fontWeight: 800, color, lineHeight: 1 }}>{score}</span>
          <span style={{ fontSize: 12, color: 'var(--clavex-neutral)', alignSelf: 'flex-end', paddingBottom: 2 }}>/ 100 · {label}</span>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {bars.map(b => (
          <div key={b.name}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
              <span style={{ color: 'var(--clavex-ink)', fontWeight: 500 }}>{b.name}</span>
              <span style={{ color: 'var(--clavex-neutral)' }}>{b.raw}</span>
            </div>
            <div style={{ height: 6, background: 'var(--clavex-border)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${b.pct}%`, background: b.pct >= 80 ? '#16a34a' : b.pct >= 50 ? '#d97706' : '#dc2626', borderRadius: 3, transition: 'width 0.4s' }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function TenantDashboard() {
  const { orgSlug } = useParams<{ orgSlug: string }>()
  const { email, orgId } = useAuthStore()
  const navigate = useNavigate()
  const base = `/admin/${orgSlug}`

  const { data: users = [] } = useQuery({ queryKey: ['users', orgId], queryFn: () => api.get(`/organizations/${orgId}/users`).then((r) => toArr(r.data)), enabled: !!orgId })
  const { data: roles = [] } = useQuery({ queryKey: ['roles', orgId], queryFn: () => api.get(`/organizations/${orgId}/roles`).then((r) => toArr(r.data)), enabled: !!orgId })
  const { data: clients = [] } = useQuery({ queryKey: ['clients', orgId], queryFn: () => api.get(`/organizations/${orgId}/clients`).then((r) => toArr(r.data)), enabled: !!orgId })

  const isNewTenant = clients.length === 0

  const quickLinks = [
    { to: `${base}/users`,    icon: Users,    label: 'Users',        description: 'Manage members and invite new users' },
    { to: `${base}/roles`,    icon: Shield,   label: 'Roles',        description: 'Define and assign access roles' },
    { to: `${base}/clients`,  icon: KeyRound, label: 'OIDC Clients', description: 'Manage OAuth2 application registrations' },
    { to: `${base}/branding`, icon: Palette,  label: 'Branding',     description: 'Customize your login page look & feel' },
    { to: `${base}/audit`,    icon: FileText, label: 'Audit Log',    description: 'Review authentication and admin activity' },
  ]

  return (
    <div>
      <div className="mb-8">
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--clavex-ink)', letterSpacing: '-0.5px' }}>
          Good {getTimeGreeting()}, {email?.split('@')[0]}
        </h1>
        <p style={{ fontSize: 13, color: 'var(--clavex-ink-subtle)', marginTop: 4 }}>
          Managing <span style={{ fontWeight: 600, color: 'var(--clavex-ink)' }}>{orgSlug}</span>
        </p>
      </div>

      {/* Onboarding banner — shown until first OIDC client is created */}
      {isNewTenant && (
        <div
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            gap: 16, padding: '16px 20px', marginBottom: 28, borderRadius: 10,
            background: 'linear-gradient(135deg, rgba(93,202,165,0.08) 0%, rgba(29,158,117,0.06) 100%)',
            border: '0.5px solid rgba(93,202,165,0.35)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 40, height: 40, borderRadius: '50%', background: 'var(--clavex-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
              <Rocket size={18} color="#fff" />
            </div>
            <div>
              <p style={{ fontSize: 14, fontWeight: 700, color: 'var(--clavex-ink)', margin: 0 }}>
                Complete your setup — 5 minutes to first login
              </p>
              <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: '2px 0 0' }}>
                Configure branding, create your first user, and generate working code for your app.
              </p>
            </div>
          </div>
          <button
            onClick={() => navigate(`${base}/onboarding`)}
            style={{
              padding: '8px 18px', borderRadius: 8, cursor: 'pointer',
              background: 'var(--clavex-primary)', color: '#fff',
              fontWeight: 600, fontSize: 13, border: 'none', flexShrink: 0,
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            Start setup <ArrowRight size={14} />
          </button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        <StatCard label="Total users" value={users.length} icon={Users} />
        <StatCard label="Roles defined" value={roles.length} icon={Shield} />
        <StatCard label="OIDC clients" value={clients.length} icon={KeyRound} />
      </div>

      {/* Security posture */}
      {orgId && (
        <div className="grid grid-cols-2 gap-4 mb-8">
          <SecurityPostureWidget orgId={orgId} />
        </div>
      )}

      {/* Quick links */}
      <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '1.5px', color: 'var(--clavex-neutral)', textTransform: 'uppercase', marginBottom: 12 }}>
        Quick access
      </p>
      <div className="grid grid-cols-2 gap-3">
        {quickLinks.map(({ to, icon: Icon, label, description }) => (
          <Link key={to} to={to}>
            <Card className="flex items-center gap-4 px-5 py-4 cursor-pointer group hover:shadow-sm transition-shadow">
              <div
                className="h-10 w-10 flex items-center justify-center flex-shrink-0"
                style={{ background: 'var(--clavex-50)', borderRadius: 10 }}
              >
                <Icon className="h-5 w-5" style={{ color: 'var(--clavex-700)' }} />
              </div>
              <div className="flex-1 min-w-0">
                <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', fontSize: 14 }}>{label}</p>
                <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginTop: 2 }} className="line-clamp-1">{description}</p>
              </div>
              <ArrowRight className="h-4 w-4 flex-shrink-0 transition-transform group-hover:translate-x-0.5" style={{ color: 'var(--clavex-border)' }} />
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}

function getTimeGreeting() {
  const h = new Date().getHours()
  if (h < 12) return 'morning'
  if (h < 18) return 'afternoon'
  return 'evening'
}
