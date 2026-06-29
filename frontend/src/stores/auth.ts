import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AuthState {
  // authenticated is the session-presence signal. The session JWT lives in an
  // HttpOnly cookie the browser cannot read (and is never returned in the login
  // response body), so route guards key off this persisted boolean.
  authenticated: boolean
  orgId: string | null
  orgSlug: string | null
  email: string | null
  isAdmin: boolean
  isSuperAdmin: boolean
  setAuth: (orgId: string, orgSlug: string, email: string, isSuperAdmin: boolean) => void
  clear: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      authenticated: false,
      orgId: null,
      orgSlug: null,
      email: null,
      isAdmin: false,
      isSuperAdmin: false,
      setAuth: (orgId, orgSlug, email, isSuperAdmin) =>
        set({ authenticated: true, orgId, orgSlug, email, isAdmin: true, isSuperAdmin }),
      clear: () =>
        set({ authenticated: false, orgId: null, orgSlug: null, email: null, isAdmin: false, isSuperAdmin: false }),
    }),
    {
      name: 'clavex-auth',
      // Only non-secret UI state is persisted; there is no token to leak.
      partialize: (s) => ({
        authenticated: s.authenticated,
        orgId: s.orgId,
        orgSlug: s.orgSlug,
        email: s.email,
        isAdmin: s.isAdmin,
        isSuperAdmin: s.isSuperAdmin,
      }),
    },
  ),
)
