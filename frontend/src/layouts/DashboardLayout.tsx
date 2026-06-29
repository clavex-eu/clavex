import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { doLogout } from '@/lib/logout'
import { ClavexLogo } from '@/components/logo/ClavexLogo'

const navItems = [
  { to: '/organizations', label: 'Spaces' },
]

export default function DashboardLayout() {
  const email = useAuthStore((s) => s.email)
  const navigate = useNavigate()

  async function handleLogout() {
    await doLogout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen" style={{ background: 'var(--clavex-surface)' }}>
      {/* Sidebar */}
      <aside
        className="w-56 flex flex-col"
        style={{ background: 'var(--clavex-dark)', borderRight: '0.5px solid rgba(93,202,165,0.15)' }}
      >
        <div className="h-14 flex items-center px-4" style={{ borderBottom: '0.5px solid rgba(93,202,165,0.12)' }}>
          <ClavexLogo variant="dark" size={0.5} />
        </div>
        <nav className="flex-1 overflow-y-auto py-3 px-3 space-y-0.5">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-4 truncate" style={{ borderTop: '0.5px solid rgba(93,202,165,0.12)', fontSize: 12, color: 'rgba(196,223,240,0.5)' }}>
          {email}
          <button
            onClick={handleLogout}
            style={{ display: 'block', marginTop: 4, color: 'var(--clavex-400)', fontSize: 12 }}
            className="hover:underline"
          >
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto p-6">
        <Outlet />
      </main>
    </div>
  )
}
