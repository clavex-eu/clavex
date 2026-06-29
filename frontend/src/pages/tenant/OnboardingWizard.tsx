import { useState, useRef, CSSProperties } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  Building2, Palette, UserPlus, ShieldCheck, Code2,
  CheckCircle2, ChevronRight, Copy, ExternalLink, Rocket,
  Globe, KeyRound, AlertCircle,
} from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import { Button, Input } from '@/components/ui'

// ── Types ─────────────────────────────────────────────────────────────────────

interface OrgStep   { name: string; display_name: string }
interface BrandStep { primary_color: string; logo_url: string; welcome_title: string }
interface UserStep  { email: string; password: string; first_name: string; last_name: string }
interface LoginStep { methods: Set<string> }
interface ClientStep {
  name: string
  redirect_uri: string
  app_type: 'spa' | 'server' | 'mobile' | 'machine'
  // filled after creation
  client_id?: string
  client_secret?: string
}

const LOGIN_METHODS = [
  { id: 'email',         label: 'Email & Password',   flag: '✉',  always: true  },
  { id: 'spid',          label: 'SPID (Italy)',        flag: '🇮🇹', always: false },
  { id: 'cie',           label: 'CIE (Italy)',         flag: '🇮🇹', always: false },
  { id: 'franceconnect', label: 'FranceConnect',       flag: '🇫🇷', always: false },
  { id: 'itsme',         label: 'itsme® (BE/LU)',      flag: '🇧🇪', always: false },
  { id: 'bundid',        label: 'BundID (Germany)',    flag: '🇩🇪', always: false },
  { id: 'clave',         label: 'Cl@ve (Spain)',       flag: '🇪🇸', always: false },
  { id: 'digid',         label: 'DigiD (Netherlands)', flag: '🇳🇱', always: false },
]

const APP_TYPES = [
  { id: 'spa',     label: 'Single-Page App',    hint: 'React, Vue, Angular — public client, PKCE'     },
  { id: 'server',  label: 'Web / Server App',   hint: 'Next.js, Django, Rails — confidential client'  },
  { id: 'mobile',  label: 'Mobile / Native',    hint: 'iOS, Android, Flutter — PKCE + custom scheme'  },
  { id: 'machine', label: 'Machine-to-Machine', hint: 'CLI, daemon, service — client credentials'     },
]

const STEPS = [
  { id: 'org',    label: 'Organisation',   icon: Building2   },
  { id: 'brand',  label: 'Branding',       icon: Palette     },
  { id: 'user',   label: 'First admin',    icon: UserPlus    },
  { id: 'login',  label: 'Login methods',  icon: ShieldCheck },
  { id: 'client', label: 'First app',      icon: Code2       },
  { id: 'done',   label: 'Done',           icon: Rocket      },
]

// ── CSS helpers ───────────────────────────────────────────────────────────────

const card: CSSProperties = {
  background: 'var(--clavex-panel)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 10,
  padding: 20,
}
const label14: CSSProperties = { fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6, display: 'block' }
const muted: CSSProperties  = { fontSize: 12, color: 'var(--clavex-neutral)' }
const mono: CSSProperties   = { fontFamily: "'IBM Plex Mono', monospace" }

// ── Code snippet generator ─────────────────────────────────────────────────────

function buildSnippet(tab: string, clientId: string, issuer: string, redirectUri: string): string {
  if (tab === 'react') return `// @clavex/react — drop-in auth
import { ClavexProvider, useSignIn, useUser } from '@clavex/react'

function App() {
  return (
    <ClavexProvider
      issuer="${issuer}"
      clientId="${clientId}"
      redirectUri="${redirectUri}"
    >
      <MyApp />
    </ClavexProvider>
  )
}

function MyApp() {
  const { user }    = useUser()
  const { signIn }  = useSignIn()

  if (!user) return <button onClick={() => signIn()}>Sign in</button>
  return <p>Hello, {user.email}</p>
}`

  if (tab === 'nextjs') return `// Next.js App Router middleware
// middleware.ts
import { withAuth } from '@clavex/next'
export default withAuth({
  issuer:      '${issuer}',
  clientId:    '${clientId}',
  redirectUri: '${redirectUri}',
})
export const config = { matcher: ['/dashboard/:path*'] }

// app/api/auth/[...clavex]/route.ts
export { GET, POST } from '@clavex/next/route'`

  if (tab === 'js') return `// Vanilla JS — PKCE flow
const ISSUER      = '${issuer}'
const CLIENT_ID   = '${clientId}'
const REDIRECT    = '${redirectUri}'

async function signIn() {
  const { metadata } = await fetch(\`\${ISSUER}/.well-known/openid-configuration\`).then(r => r.json())
  const verifier  = crypto.randomUUID() + crypto.randomUUID()
  const challenge = btoa(String.fromCharCode(...new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  ))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=/g,'')

  sessionStorage.setItem('pkce', verifier)
  location.href = \`\${ISSUER}/authorize?\` + new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID,
    redirect_uri: REDIRECT, scope: 'openid email profile',
    code_challenge: challenge, code_challenge_method: 'S256',
  })
}`

  return ''
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function OnboardingWizard() {
  const { orgSlug }  = useParams<{ orgSlug: string }>()
  const orgId        = useAuthStore(s => s.orgId)
  const navigate     = useNavigate()

  const [step,      setStep]  = useState(0)
  const [completed, setCompleted] = useState<Set<number>>(new Set())
  const [codeTab,   setCodeTab]   = useState<'react' | 'nextjs' | 'js'>('react')
  const copyRef = useRef<HTMLPreElement>(null)

  // Step data
  const [org,    setOrg]    = useState<OrgStep>({ name: '', display_name: '' })
  const [brand,  setBrand]  = useState<BrandStep>({ primary_color: '#5DCAA5', logo_url: '', welcome_title: 'Welcome back' })
  const [user,   setUser]   = useState<UserStep>({ email: '', password: '', first_name: '', last_name: '' })
  const [login,  setLogin]  = useState<LoginStep>({ methods: new Set(['email']) })
  const [client, setClient] = useState<ClientStep>({ name: '', redirect_uri: '', app_type: 'spa' })

  const issuer = `${window.location.origin}/${orgSlug}`

  // Mutations
  const saveOrg = useMutation({
    mutationFn: () => api.patch(`/organizations/${orgId}`, {
      name: org.name || undefined,
      display_name: org.display_name || undefined,
    }),
    onSuccess: () => advance(),
    onError: (e: unknown) => toast.error(apiMsg(e, 'Failed to update organisation')),
  })

  const saveBrand = useMutation({
    mutationFn: () => api.put(`/organizations/${orgId}/branding`, {
      primary_color:   brand.primary_color,
      logo_url:        brand.logo_url || undefined,
      welcome_title:   brand.welcome_title,
      bg_color:        '#ffffff',
      text_color:      '#1A2332',
    }),
    onSuccess: () => advance(),
    onError: (e: unknown) => toast.error(apiMsg(e, 'Failed to save branding')),
  })

  const saveUser = useMutation({
    mutationFn: () => api.post(`/organizations/${orgId}/users`, {
      email:      user.email,
      password:   user.password,
      first_name: user.first_name || undefined,
      last_name:  user.last_name  || undefined,
      role:       'admin',
    }),
    onSuccess: () => advance(),
    onError: (e: unknown) => toast.error(apiMsg(e, 'Failed to create user')),
  })

  const saveClient = useMutation({
    mutationFn: () => api.post(`/organizations/${orgId}/clients`, {
      name:          client.name,
      redirect_uris: [client.redirect_uri],
      is_public:     client.app_type === 'spa' || client.app_type === 'mobile',
      grant_types:   client.app_type === 'machine'
        ? ['client_credentials']
        : ['authorization_code', 'refresh_token'],
    }),
    onSuccess: (res) => {
      setClient(c => ({ ...c, client_id: res.data.client_id, client_secret: res.data.client_secret }))
      advance()
    },
    onError: (e: unknown) => toast.error(apiMsg(e, 'Failed to create client')),
  })

  function advance() {
    setCompleted(s => new Set(s).add(step))
    setStep(s => Math.min(s + 1, STEPS.length - 1))
  }

  function handleNext() {
    if (step === 0) { if (!org.name.trim()) { toast.error('Organisation name is required'); return }; saveOrg.mutate() }
    if (step === 1) { saveBrand.mutate() }
    if (step === 2) {
      if (!user.email.trim() || !user.password.trim()) { toast.error('Email and password are required'); return }
      saveUser.mutate()
    }
    if (step === 3) { advance() /* login methods — recorded locally, IDP config is separate */ }
    if (step === 4) {
      if (!client.name.trim() || !client.redirect_uri.trim()) { toast.error('App name and redirect URI are required'); return }
      saveClient.mutate()
    }
  }

  const isPending = saveOrg.isPending || saveBrand.isPending || saveUser.isPending || saveClient.isPending
  const snippet   = buildSnippet(codeTab, client.client_id ?? 'YOUR_CLIENT_ID', issuer, client.redirect_uri || 'https://your-app.example.com/callback')

  return (
    <div style={{ minHeight: '100%', padding: '32px 40px 60px', maxWidth: 960, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ marginBottom: 32 }}>
        <p style={{ ...mono, fontSize: 11, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--clavex-primary)', marginBottom: 8 }}>
          ◈ Clavex Launch
        </p>
        <h1 style={{ fontSize: 26, fontWeight: 300, color: 'var(--clavex-ink)', letterSpacing: '-0.02em', marginBottom: 6 }}>
          Get started with <strong style={{ fontWeight: 700 }}>{orgSlug}</strong>
        </h1>
        <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>
          5 steps — configure your tenant, create your first user, and generate working code in minutes.
        </p>
      </div>

      <div style={{ display: 'flex', gap: 28, alignItems: 'flex-start' }}>

        {/* Steps sidebar */}
        <div style={{ width: 200, flexShrink: 0 }}>
          {STEPS.map((s, i) => {
            const done    = completed.has(i)
            const active  = step === i
            const future  = i > step && !done
            const Icon    = s.icon
            return (
              <div
                key={s.id}
                onClick={() => done ? setStep(i) : undefined}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '9px 12px', borderRadius: 8, marginBottom: 4,
                  cursor: done ? 'pointer' : 'default',
                  background: active ? 'rgba(93,202,165,0.1)' : 'transparent',
                  border: active ? '0.5px solid rgba(93,202,165,0.35)' : '0.5px solid transparent',
                  transition: 'all 0.15s',
                }}
              >
                <div style={{
                  width: 28, height: 28, borderRadius: '50%',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  background: done ? 'var(--clavex-primary)' : active ? 'rgba(93,202,165,0.15)' : 'var(--clavex-panel)',
                  border: `0.5px solid ${done ? 'var(--clavex-primary)' : active ? 'rgba(93,202,165,0.5)' : 'var(--clavex-border)'}`,
                }}>
                  {done
                    ? <CheckCircle2 size={14} color="#fff" />
                    : <Icon size={13} color={active ? 'var(--clavex-primary)' : future ? 'var(--clavex-muted)' : 'var(--clavex-neutral)'} />
                  }
                </div>
                <div>
                  <div style={{ fontSize: 11, ...mono, letterSpacing: '0.06em', textTransform: 'uppercase',
                    color: done ? 'var(--clavex-primary)' : active ? 'var(--clavex-ink)' : 'var(--clavex-neutral)' }}>
                    Step {i + 1}
                  </div>
                  <div style={{ fontSize: 12, fontWeight: active ? 600 : 400, color: active ? 'var(--clavex-ink)' : 'var(--clavex-neutral)' }}>
                    {s.label}
                  </div>
                </div>
              </div>
            )
          })}

          {/* Progress bar */}
          <div style={{ marginTop: 20, padding: '0 12px' }}>
            <div style={{ height: 3, background: 'var(--clavex-border)', borderRadius: 4 }}>
              <div style={{
                height: 3, background: 'var(--clavex-primary)', borderRadius: 4,
                width: `${(completed.size / (STEPS.length - 1)) * 100}%`,
                transition: 'width 0.4s ease',
              }} />
            </div>
            <p style={{ ...muted, marginTop: 6, ...mono }}>
              {completed.size}/{STEPS.length - 1} complete
            </p>
          </div>
        </div>

        {/* Step content */}
        <div style={{ flex: 1, minWidth: 0 }}>

          {/* ── Step 0: Organisation ── */}
          {step === 0 && (
            <StepCard
              title="Organisation identity"
              subtitle="Set your organisation's display name. The URL slug was assigned at creation and is read-only."
              icon={<Building2 size={20} color="var(--clavex-primary)" />}
            >
              <Input
                label="Organisation name *"
                value={org.name}
                onChange={e => setOrg(o => ({ ...o, name: e.target.value }))}
                placeholder="Acme Corp"
                autoFocus
              />
              <Input
                label="Display name (optional)"
                value={org.display_name}
                onChange={e => setOrg(o => ({ ...o, display_name: e.target.value }))}
                placeholder="Acme Corporation"
                style={{ marginTop: 14 }}
              />
              <ReadOnly label="URL slug (issuer)" value={orgSlug ?? ''} style={{ marginTop: 14 }} />
              <ReadOnly label="Issuer URL" value={issuer} style={{ marginTop: 14 }} />
            </StepCard>
          )}

          {/* ── Step 1: Branding ── */}
          {step === 1 && (
            <StepCard
              title="Login page branding"
              subtitle="Set your brand color, logo, and welcome message. Previewed immediately on the login page."
              icon={<Palette size={20} color="var(--clavex-primary)" />}
            >
              <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', gap: 14, alignItems: 'flex-end', marginBottom: 14 }}>
                    <div style={{ flex: 1 }}>
                      <label style={label14}>Primary color</label>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <input
                          type="color"
                          value={brand.primary_color}
                          onChange={e => setBrand(b => ({ ...b, primary_color: e.target.value }))}
                          style={{ width: 44, height: 36, border: 'none', background: 'none', cursor: 'pointer', padding: 0 }}
                        />
                        <span style={{ ...mono, fontSize: 13, color: 'var(--clavex-ink)' }}>{brand.primary_color}</span>
                      </div>
                    </div>
                  </div>
                  <Input
                    label="Welcome title"
                    value={brand.welcome_title}
                    onChange={e => setBrand(b => ({ ...b, welcome_title: e.target.value }))}
                    placeholder="Welcome back"
                    style={{ marginBottom: 14 }}
                  />
                  <Input
                    label="Logo URL (optional)"
                    value={brand.logo_url}
                    onChange={e => setBrand(b => ({ ...b, logo_url: e.target.value }))}
                    placeholder="https://cdn.example.com/logo.svg"
                  />
                </div>
                {/* Mini preview */}
                <div style={{ width: 190, flexShrink: 0, background: '#f8f9fa', border: '0.5px solid #e5e7eb', borderRadius: 10, padding: 18, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
                  {brand.logo_url
                    ? <img src={brand.logo_url} alt="logo" style={{ maxHeight: 36, maxWidth: 120, objectFit: 'contain' }} />
                    : <div style={{ width: 48, height: 48, borderRadius: '50%', background: brand.primary_color, opacity: 0.25 }} />
                  }
                  <p style={{ fontSize: 13, fontWeight: 600, color: '#1A2332', textAlign: 'center', margin: 0 }}>
                    {brand.welcome_title || 'Welcome back'}
                  </p>
                  <div style={{ width: '100%', height: 32, borderRadius: 6, background: brand.primary_color, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ fontSize: 12, color: '#fff', fontWeight: 600 }}>Continue</span>
                  </div>
                  <p style={{ ...muted, fontSize: 10, textAlign: 'center' }}>Login page preview</p>
                </div>
              </div>
            </StepCard>
          )}

          {/* ── Step 2: First admin user ── */}
          {step === 2 && (
            <StepCard
              title="First admin user"
              subtitle="Create the first administrator who will manage this organisation. You can invite more users later."
              icon={<UserPlus size={20} color="var(--clavex-primary)" />}
            >
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                <Input
                  label="First name"
                  value={user.first_name}
                  onChange={e => setUser(u => ({ ...u, first_name: e.target.value }))}
                  placeholder="Ada"
                  autoFocus
                />
                <Input
                  label="Last name"
                  value={user.last_name}
                  onChange={e => setUser(u => ({ ...u, last_name: e.target.value }))}
                  placeholder="Lovelace"
                />
              </div>
              <Input
                label="Email *"
                type="email"
                value={user.email}
                onChange={e => setUser(u => ({ ...u, email: e.target.value }))}
                placeholder="ada@example.com"
                style={{ marginTop: 14 }}
              />
              <Input
                label="Temporary password *"
                type="password"
                value={user.password}
                onChange={e => setUser(u => ({ ...u, password: e.target.value }))}
                placeholder="Min 8 characters"
                style={{ marginTop: 14 }}
              />
              <div style={{ marginTop: 14, padding: '10px 14px', background: 'rgba(93,202,165,0.06)', border: '0.5px solid rgba(93,202,165,0.2)', borderRadius: 8 }}>
                <p style={{ ...muted, fontSize: 12, margin: 0 }}>
                  💡 The user will be created with the <strong>admin</strong> role. Prompt them to change their password on first login via Settings → Users.
                </p>
              </div>
            </StepCard>
          )}

          {/* ── Step 3: Login methods ── */}
          {step === 3 && (
            <StepCard
              title="Login methods"
              subtitle="Choose which authentication methods are enabled. EU national eIDs require additional provider configuration after setup."
              icon={<Globe size={20} color="var(--clavex-primary)" />}
            >
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                {LOGIN_METHODS.map(m => {
                  const on = login.methods.has(m.id)
                  return (
                    <button
                      key={m.id}
                      onClick={() => {
                        if (m.always) return
                        setLogin(l => {
                          const next = new Set(l.methods)
                          if (on) { next.delete(m.id) } else { next.add(m.id) }
                          return { methods: next }
                        })
                      }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '11px 14px', borderRadius: 8, cursor: m.always ? 'default' : 'pointer',
                        background: on ? 'rgba(93,202,165,0.08)' : 'var(--clavex-panel)',
                        border: `0.5px solid ${on ? 'rgba(93,202,165,0.45)' : 'var(--clavex-border)'}`,
                        textAlign: 'left', transition: 'all 0.15s',
                      }}
                    >
                      <span style={{ fontSize: 18 }}>{m.flag}</span>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)' }}>{m.label}</div>
                        {m.always && <div style={{ fontSize: 11, color: 'var(--clavex-primary)', ...mono }}>always on</div>}
                        {!m.always && !on && <div style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>tap to enable</div>}
                        {!m.always && on && <div style={{ fontSize: 11, color: 'var(--clavex-primary)', ...mono }}>enabled</div>}
                      </div>
                      <div style={{
                        width: 18, height: 18, borderRadius: '50%', flexShrink: 0,
                        background: on ? 'var(--clavex-primary)' : 'var(--clavex-border)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                      }}>
                        {on && <CheckCircle2 size={12} color="#fff" />}
                      </div>
                    </button>
                  )
                })}
              </div>
              {[...login.methods].some(m => m !== 'email') && (
                <div style={{ marginTop: 14, padding: '10px 14px', background: 'rgba(245,200,66,0.07)', border: '0.5px solid rgba(245,200,66,0.3)', borderRadius: 8 }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                    <AlertCircle size={14} color="#F5C842" style={{ marginTop: 2, flexShrink: 0 }} />
                    <p style={{ ...muted, fontSize: 12, margin: 0 }}>
                      EU national eIDs require additional credentials (SAML certificates, client secrets, or OIDC discovery URIs) — go to <strong>EuroID</strong> after setup to complete the configuration.
                    </p>
                  </div>
                </div>
              )}
            </StepCard>
          )}

          {/* ── Step 4: First OIDC client ── */}
          {step === 4 && (
            <StepCard
              title="First application"
              subtitle="Register your first OIDC client. A working code snippet will be generated instantly."
              icon={<KeyRound size={20} color="var(--clavex-primary)" />}
            >
              <Input
                label="Application name *"
                value={client.name}
                onChange={e => setClient(c => ({ ...c, name: e.target.value }))}
                placeholder="My App"
                autoFocus
              />
              <Input
                label="Redirect URI *"
                value={client.redirect_uri}
                onChange={e => setClient(c => ({ ...c, redirect_uri: e.target.value }))}
                placeholder="https://app.example.com/callback"
                style={{ marginTop: 14 }}
              />
              <div style={{ marginTop: 14 }}>
                <label style={label14}>Application type</label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  {APP_TYPES.map(t => (
                    <button
                      key={t.id}
                      onClick={() => setClient(c => ({ ...c, app_type: t.id as ClientStep['app_type'] }))}
                      style={{
                        padding: '10px 14px', borderRadius: 8, cursor: 'pointer', textAlign: 'left',
                        background: client.app_type === t.id ? 'rgba(93,202,165,0.08)' : 'var(--clavex-panel)',
                        border: `0.5px solid ${client.app_type === t.id ? 'rgba(93,202,165,0.45)' : 'var(--clavex-border)'}`,
                        transition: 'all 0.15s',
                      }}
                    >
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)' }}>{t.label}</div>
                      <div style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 2 }}>{t.hint}</div>
                    </button>
                  ))}
                </div>
              </div>
            </StepCard>
          )}

          {/* ── Step 5: Done + code snippet ── */}
          {step === 5 && (
            <div>
              {/* Success banner */}
              <div style={{ ...card, background: 'rgba(93,202,165,0.07)', border: '0.5px solid rgba(93,202,165,0.3)', marginBottom: 20, display: 'flex', gap: 16, alignItems: 'center' }}>
                <div style={{ width: 48, height: 48, borderRadius: '50%', background: 'var(--clavex-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <Rocket size={22} color="#fff" />
                </div>
                <div>
                  <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--clavex-ink)', margin: 0, marginBottom: 4 }}>
                    {orgSlug} is ready to go 🎉
                  </h2>
                  <p style={{ ...muted, margin: 0 }}>
                    Organisation configured · branding set · admin user created · OIDC client registered.
                  </p>
                </div>
              </div>

              {/* Summary chips */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 24 }}>
                {[
                  { label: 'Org', value: org.name || orgSlug! },
                  { label: 'Admin', value: user.email },
                  { label: 'Client', value: client.client_id ?? client.name },
                  { label: 'Type', value: client.app_type },
                  { label: 'Methods', value: [...login.methods].join(', ') },
                ].map(chip => (
                  <div key={chip.label} style={{ padding: '6px 12px', background: 'var(--clavex-panel)', border: '0.5px solid var(--clavex-border)', borderRadius: 20 }}>
                    <span style={{ fontSize: 11, color: 'var(--clavex-neutral)', ...mono }}>{chip.label}: </span>
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-ink)' }}>{chip.value}</span>
                  </div>
                ))}
              </div>

              {/* Code snippet */}
              <div style={card}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                  <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--clavex-ink)', margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Code2 size={16} color="var(--clavex-primary)" />
                    Integration snippet
                  </h3>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {(['react', 'nextjs', 'js'] as const).map(t => (
                      <button
                        key={t}
                        onClick={() => setCodeTab(t)}
                        style={{
                          padding: '4px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer',
                          background: codeTab === t ? 'var(--clavex-primary)' : 'var(--clavex-panel)',
                          color: codeTab === t ? '#fff' : 'var(--clavex-neutral)',
                          border: `0.5px solid ${codeTab === t ? 'var(--clavex-primary)' : 'var(--clavex-border)'}`,
                        }}
                      >
                        {t === 'react' ? 'React' : t === 'nextjs' ? 'Next.js' : 'Vanilla JS'}
                      </button>
                    ))}
                  </div>
                </div>

                <div style={{ position: 'relative' }}>
                  <pre
                    ref={copyRef}
                    style={{
                      ...mono, fontSize: 11.5, lineHeight: 1.65,
                      background: '#0D1F2D', color: '#C4DFF0',
                      padding: '18px 20px', borderRadius: 8, overflow: 'auto',
                      border: '0.5px solid rgba(93,202,165,0.15)',
                      maxHeight: 320, margin: 0,
                    }}
                  >
                    {snippet}
                  </pre>
                  <button
                    onClick={() => { navigator.clipboard.writeText(snippet); toast.success('Copied!') }}
                    style={{
                      position: 'absolute', top: 10, right: 10,
                      padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                      background: 'rgba(93,202,165,0.12)', border: '0.5px solid rgba(93,202,165,0.3)',
                      display: 'flex', alignItems: 'center', gap: 5, color: 'var(--clavex-primary)',
                      fontSize: 11, fontWeight: 600,
                    }}
                  >
                    <Copy size={12} /> Copy
                  </button>
                </div>

                {client.client_id && (
                  <div style={{ marginTop: 14, display: 'flex', gap: 20, flexWrap: 'wrap' }}>
                    <InfoPair label="client_id" value={client.client_id} />
                    {client.client_secret && <InfoPair label="client_secret" value={client.client_secret} secret />}
                    <InfoPair label="issuer" value={issuer} />
                  </div>
                )}
              </div>

              {/* Next steps */}
              <div style={{ marginTop: 20, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[
                  { label: 'Invite users', href: 'users',              icon: '👥' },
                  { label: 'Configure branding', href: 'branding',     icon: '🎨' },
                  { label: 'Set up identity providers', href: 'identity-providers', icon: '🌍' },
                  { label: 'View audit log', href: 'audit',            icon: '📋' },
                ].map(l => (
                  <button
                    key={l.href}
                    onClick={() => navigate(`/admin/${orgSlug}/${l.href}`)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 12,
                      padding: '12px 16px', borderRadius: 8, cursor: 'pointer',
                      background: 'var(--clavex-panel)', border: '0.5px solid var(--clavex-border)',
                      textAlign: 'left', transition: 'border-color 0.15s',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.borderColor = 'rgba(93,202,165,0.4)')}
                    onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--clavex-border)')}
                  >
                    <span style={{ fontSize: 20 }}>{l.icon}</span>
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)' }}>{l.label}</span>
                    <ExternalLink size={12} color="var(--clavex-neutral)" style={{ marginLeft: 'auto' }} />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Navigation buttons */}
          {step < 5 && (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 24 }}>
              {step > 0
                ? <Button variant="secondary" onClick={() => setStep(s => s - 1)}>Back</Button>
                : <div />
              }
              <div style={{ display: 'flex', gap: 10 }}>
                {step === 3 && (
                  <Button variant="secondary" onClick={advance}>Skip</Button>
                )}
                <Button
                  onClick={handleNext}
                  loading={isPending}
                  style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                >
                  {step === 4 ? 'Create & finish' : 'Continue'}
                  {!isPending && <ChevronRight size={15} />}
                </Button>
              </div>
            </div>
          )}

          {step === 5 && (
            <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end' }}>
              <Button onClick={() => navigate(`/admin/${orgSlug}`)}>
                Go to dashboard →
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function StepCard({ title, subtitle, icon, children }: {
  title: string; subtitle: string; icon: React.ReactNode; children: React.ReactNode
}) {
  return (
    <div style={{
      background: 'var(--clavex-panel)',
      border: '0.5px solid var(--clavex-border)',
      borderRadius: 12, padding: 24,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        {icon}
        <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--clavex-ink)', margin: 0 }}>{title}</h2>
      </div>
      <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginBottom: 22, marginLeft: 30 }}>
        {subtitle}
      </p>
      {children}
    </div>
  )
}

function ReadOnly({ label, value, style }: { label: string; value: string; style?: CSSProperties }) {
  return (
    <div style={style}>
      <label style={label14}>{label}</label>
      <div style={{
        padding: '9px 12px', borderRadius: 8,
        background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)',
        fontSize: 13, color: 'var(--clavex-neutral)', fontFamily: "'IBM Plex Mono', monospace",
      }}>
        {value}
      </div>
    </div>
  )
}

function InfoPair({ label, value, secret }: { label: string; value: string; secret?: boolean }) {
  const [show, setShow] = useState(false)
  return (
    <div>
      <div style={{ fontSize: 11, ...mono, color: 'var(--clavex-neutral)', marginBottom: 3 }}>{label}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <code style={{ ...mono, fontSize: 12, color: 'var(--clavex-primary)', background: 'rgba(93,202,165,0.08)', padding: '3px 8px', borderRadius: 5 }}>
          {secret && !show ? '•'.repeat(Math.min(value.length, 20)) : value}
        </code>
        {secret && (
          <button onClick={() => setShow(s => !s)} style={{ fontSize: 11, color: 'var(--clavex-neutral)', background: 'none', border: 'none', cursor: 'pointer' }}>
            {show ? 'hide' : 'show'}
          </button>
        )}
        <button onClick={() => { navigator.clipboard.writeText(value); toast.success('Copied!') }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--clavex-neutral)', display: 'flex' }}>
          <Copy size={12} />
        </button>
      </div>
    </div>
  )
}

function apiMsg(e: unknown, fallback: string): string {
  if (e && typeof e === 'object' && 'response' in e) {
    const r = (e as { response?: { data?: { error?: string } } }).response
    return r?.data?.error ?? fallback
  }
  return fallback
}
