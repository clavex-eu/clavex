import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Users, Shield, KeyRound, Palette, FileText, ArrowRight, ShieldCheck, ShieldAlert, Rocket } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import { Card } from '@/components/ui'
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

// ── Colour helper ─────────────────────────────────────────────────────────────
// Higher pct = healthier. Green ≥ 80, amber ≥ 50, red below.
function pctColor(pct: number) {
  return pct >= 80 ? '#16a34a' : pct >= 50 ? '#d97706' : '#dc2626'
}

// ── DonutRing ─────────────────────────────────────────────────────────────────
// Compact circular gauge: an arc filled to `pct` with a big centre figure and a
// tiny caption beneath it. Far clearer at a glance than a thin horizontal bar.
function DonutRing({ pct, center, caption, color }: { pct: number; center: string; caption: string; color: string }) {
  const size = 84
  const stroke = 8
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const dash = (Math.max(0, Math.min(100, pct)) / 100) * c
  return (
    <div style={{ position: 'relative', width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--clavex-border)" strokeWidth={stroke} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={color} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={`${dash} ${c}`}
          style={{ transition: 'stroke-dasharray 0.5s ease' }}
        />
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <span style={{ fontSize: 18, fontWeight: 800, color: 'var(--clavex-ink)', lineHeight: 1 }}>{center}</span>
        <span style={{ fontSize: 10, color: 'var(--clavex-neutral)', marginTop: 2 }}>{caption}</span>
      </div>
    </div>
  )
}

// ── RingMetric ────────────────────────────────────────────────────────────────
function RingMetric({ name, pct, center, caption, raw, color }: { name: string; pct: number; center: string; caption: string; raw: string; color: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 10 }}>
      <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)' }}>{name}</p>
      <DonutRing pct={pct} center={center} caption={caption} color={color} />
      <p style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>{raw}</p>
    </div>
  )
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
      <Card className="p-5">
        <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--clavex-neutral)', fontSize: 13 }}>
          Computing posture…
        </div>
      </Card>
    )
  }

  const score = data.score
  const color = score >= 80 ? '#16a34a' : score >= 55 ? '#d97706' : '#dc2626'
  const Icon = score >= 55 ? ShieldCheck : ShieldAlert
  const label = score >= 80 ? 'Good' : score >= 55 ? 'Fair' : 'Poor'

  const metrics = [
    {
      name: 'MFA coverage', pct: data.mfa_coverage,
      center: `${data.users_with_mfa}/${data.total_users}`, caption: 'users',
      raw: `${data.mfa_coverage}% covered`, color: pctColor(data.mfa_coverage),
    },
    {
      name: 'Passkey coverage', pct: data.passkey_coverage,
      center: `${data.users_with_passkey}/${data.total_users}`, caption: 'users',
      raw: `${data.passkey_coverage}% covered`, color: pctColor(data.passkey_coverage),
    },
    {
      name: 'Policy engine', pct: data.policy_engine,
      center: data.active_policy_rules > 0 ? `${data.active_policy_rules}` : '—',
      caption: data.active_policy_rules > 0 ? 'rules' : 'no rules',
      raw: data.active_policy_rules > 0 ? `${data.active_policy_rules} rules active` : 'No rules configured',
      color: data.active_policy_rules > 0 ? pctColor(data.policy_engine) : 'var(--clavex-neutral)',
    },
    {
      name: 'Anomaly score', pct: data.anomaly_score,
      center: `${data.anomaly_score}`, caption: 'score',
      raw: `${data.failed_logins_24h} failed logins (24 h)`, color: pctColor(data.anomaly_score),
    },
  ]

  return (
    <Card className="p-5">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '1.5px', color: 'var(--clavex-neutral)', textTransform: 'uppercase' }}>Security posture</p>
        <div
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '4px 12px', borderRadius: 999,
            background: `${color}14`, border: `0.5px solid ${color}55`,
          }}
        >
          <Icon style={{ width: 15, height: 15, color }} />
          <span style={{ fontSize: 15, fontWeight: 800, color, lineHeight: 1 }}>{score}</span>
          <span style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>/ 100 · {label}</span>
        </div>
      </div>
      <div className="grid grid-cols-4 gap-4">
        {metrics.map(m => (
          <RingMetric key={m.name} {...m} />
        ))}
      </div>
    </Card>
  )
}

// ── DashboardStatCard ─────────────────────────────────────────────────────────
// Local, richer stat card: uppercase label + large figure on the left, a tinted
// icon tile on the right, and a coloured accent bar along the bottom edge.
function DashboardStatCard({ label, value, icon: Icon }: { label: string; value: string | number; icon: React.ElementType }) {
  return (
    <Card className="relative overflow-hidden px-5 pt-4 pb-5">
      <div className="flex items-start justify-between">
        <div>
          <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.6px' }}>{label}</p>
          <p style={{ fontSize: 32, fontWeight: 800, color: 'var(--clavex-ink)', letterSpacing: '-1px', lineHeight: 1.1, marginTop: 8 }}>{value}</p>
        </div>
        <div
          className="flex items-center justify-center flex-shrink-0"
          style={{ height: 44, width: 44, borderRadius: 12, background: 'var(--clavex-50)' }}
        >
          <Icon className="h-5 w-5" style={{ color: 'var(--clavex-700)' }} />
        </div>
      </div>
      <div
        style={{
          position: 'absolute', left: 0, right: 0, bottom: 0, height: 3,
          background: 'linear-gradient(90deg, var(--clavex-primary), var(--clavex-300, #86dcbf))',
        }}
      />
    </Card>
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
        <DashboardStatCard label="Total users" value={users.length} icon={Users} />
        <DashboardStatCard label="Roles defined" value={roles.length} icon={Shield} />
        <DashboardStatCard label="OIDC clients" value={clients.length} icon={KeyRound} />
      </div>

      {/* Security posture */}
      {orgId && (
        <div className="mb-8">
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
