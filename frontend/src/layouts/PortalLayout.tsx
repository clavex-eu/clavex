import { NavLink, Outlet } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { doLogout } from '@/lib/logout'
import { Settings, Users, Globe, Shield, LogOut } from 'lucide-react'

const NAV_ITEMS = [
  { to: 'sso',     label: 'SSO / Identity',  Icon: Globe  },
  { to: 'scim',    label: 'SCIM Sync',        Icon: Users  },
  { to: 'domains', label: 'Domain Enrollment', Icon: Settings },
  { to: 'mfa',     label: 'MFA Policy',       Icon: Shield },
]

export default function PortalLayout() {
  const orgSlug = useAuthStore((s) => s.orgSlug)

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', fontFamily: 'system-ui, sans-serif' }}>
      {/* Top bar */}
      <header style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 32px', height: 56,
        borderBottom: '0.5px solid var(--clavex-border)',
        background: 'var(--clavex-surface)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: 'var(--clavex-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield size={18} color="#fff" />
          </div>
          <div>
            <span style={{ fontSize: 14, fontWeight: 700 }}>IT Admin Portal</span>
            {orgSlug && (
              <span style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginLeft: 8 }}>{orgSlug}</span>
            )}
          </div>
        </div>

        {/* Nav */}
        <nav style={{ display: 'flex', gap: 4 }}>
          {NAV_ITEMS.map(({ to, label, Icon }) => (
            <NavLink
              key={to}
              to={to}
              style={({ isActive }) => ({
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 8, fontSize: 13,
                textDecoration: 'none', fontWeight: isActive ? 600 : 400,
                color: isActive ? 'var(--clavex-primary)' : 'var(--clavex-neutral)',
                background: isActive ? 'var(--clavex-primary)10' : 'transparent',
              })}
            >
              <Icon size={14} /> {label}
            </NavLink>
          ))}
        </nav>

        <button onClick={() => { doLogout() }} style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          background: 'none', border: 'none', cursor: 'pointer',
          fontSize: 13, color: 'var(--clavex-neutral)',
        }}>
          <LogOut size={14} /> Sign out
        </button>
      </header>

      {/* Content */}
      <main style={{ flex: 1, padding: '32px 40px', maxWidth: 960, width: '100%', margin: '0 auto' }}>
        <Outlet />
      </main>
    </div>
  )
}
