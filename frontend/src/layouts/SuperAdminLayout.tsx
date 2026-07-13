import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { doLogout } from '@/lib/logout'
import { Activity, Building2, LogOut, Zap, Key, ShieldCheck, Fingerprint, RotateCw } from 'lucide-react'
import { ClavexLogo } from '@/components/logo/ClavexLogo'

export default function SuperAdminLayout() {
  const email = useAuthStore((s) => s.email)
  const navigate = useNavigate()

  return (
    <div className="flex h-screen" style={{ background: 'var(--clavex-surface)' }}>
      <aside
        className="w-56 flex flex-col flex-shrink-0"
        style={{ background: 'var(--clavex-dark)', borderRight: '0.5px solid rgba(93,202,165,0.15)' }}
      >
        {/* Logo */}
        <div className="h-16 flex items-center px-5" style={{ borderBottom: '0.5px solid rgba(93,202,165,0.12)' }}>
          <ClavexLogo variant="dark" size={0.55} />
        </div>

        {/* Superadmin badge */}
        <div className="px-5 pt-4 pb-2">
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '3px 10px', borderRadius: 20,
            background: 'var(--clavex-dark-surface)',
            border: '0.5px solid var(--clavex-primary)',
            color: 'var(--clavex-400)',
            fontSize: 10, fontWeight: 700, letterSpacing: '1px',
          }}>
            SUPERADMIN
          </span>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-3">
          <p style={{
            fontSize: 10, fontWeight: 700, letterSpacing: '1.5px',
            color: 'rgba(196, 223, 240, 0.35)',
            padding: '6px 12px 4px',
            textTransform: 'uppercase',
          }}>Management</p>
          <NavLink
            to="/admin/orgs"
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <Building2 className="h-4 w-4" />
            Organizations
          </NavLink>
          <NavLink
            to="/admin/provision"
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <Zap className="h-4 w-4" />
            Provision
          </NavLink>
          <NavLink
            to="/admin/health"
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <Activity className="h-4 w-4" />
            Health
          </NavLink>
          <NavLink
            to="/admin/api-keys"
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <Key className="h-4 w-4" />
            API Keys
          </NavLink>
          <NavLink
            to="/admin/signing-keys"
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <RotateCw className="h-4 w-4" />
            Signing Keys
          </NavLink>
          <NavLink
            to="/admin/license"
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <ShieldCheck className="h-4 w-4" />
            License
          </NavLink>
          <NavLink
            to="/admin/spid-instance"
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <Fingerprint className="h-4 w-4" />
            SPID SP
          </NavLink>
        </nav>

        {/* User footer */}
        <div className="p-4" style={{ borderTop: '0.5px solid rgba(93,202,165,0.12)' }}>
          <div className="flex items-center gap-3">
            <div
              className="h-8 w-8 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ background: 'var(--clavex-dark-surface)', border: '0.5px solid var(--clavex-primary)' }}
            >
              <span style={{ color: 'var(--clavex-400)', fontSize: 11, fontWeight: 700 }}>
                {email?.[0]?.toUpperCase() ?? 'S'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p style={{ fontSize: 12, fontWeight: 500, color: '#C4DFF0' }} className="truncate">{email}</p>
              <p style={{ fontSize: 10, color: 'rgba(196, 223, 240, 0.4)' }}>Superadmin</p>
            </div>
            <button
              onClick={async () => { await doLogout(); navigate('/login') }}
              style={{ color: 'rgba(196, 223, 240, 0.35)', padding: 4, borderRadius: 6 }}
              className="hover:text-red-400 transition-colors"
              title="Sign out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="max-w-6xl mx-auto p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
