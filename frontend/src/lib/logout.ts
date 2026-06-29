import api from '@/lib/api'
import { useAuthStore } from '@/stores/auth'

/**
 * Log the admin out. The session + CSRF cookies are HttpOnly / server-owned,
 * so they can only be cleared by the server — hence the POST. Local UI state is
 * cleared regardless of whether the request succeeds.
 */
export async function doLogout(): Promise<void> {
  try {
    await api.post('/auth/logout')
  } catch {
    // Best-effort: even if the call fails (offline, already expired), drop local
    // state so the user lands on /login.
  }
  useAuthStore.getState().clear()
}
