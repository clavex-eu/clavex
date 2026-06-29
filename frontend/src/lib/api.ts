import axios from 'axios'
import { useAuthStore } from '@/stores/auth'

/**
 * Safely extract an array from a paginated or plain-array API response.
 * Handles: Page<T> {items: T[]}, plain T[], null items (Go nil slice), null/undefined.
 */
export function toArr<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[]
  if (data && typeof data === 'object') {
    // Page[T] with items field (most endpoints)
    if ('items' in data) {
      const items = (data as { items: unknown }).items
      if (Array.isArray(items)) return items as T[]
    }
    // AuditPage with events field
    if ('events' in data) {
      const events = (data as { events: unknown }).events
      if (Array.isArray(events)) return events as T[]
    }
  }
  return []
}

/** Read a non-HttpOnly cookie value by name (used for the CSRF double-submit token). */
export function readCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1') + '=([^;]*)'))
  return match ? decodeURIComponent(match[1]) : null
}

const CSRF_COOKIE = 'clavex_csrf'
const SAFE_METHODS = new Set(['get', 'head', 'options'])

const api = axios.create({
  baseURL: `${import.meta.env.VITE_API_URL ?? ''}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
  // Send the HttpOnly session cookie on every request.
  withCredentials: true,
})

api.interceptors.request.use((config) => {
  // Authentication now rides the HttpOnly cookie — no Authorization header.
  // For state-changing requests, echo the CSRF token (double-submit pattern).
  const method = (config.method ?? 'get').toLowerCase()
  if (!SAFE_METHODS.has(method)) {
    const csrf = readCookie(CSRF_COOKIE)
    if (csrf) config.headers['X-CSRF-Token'] = csrf
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    // Don't hijack 401s from the login endpoint itself — the Login page
    // surfaces those as an inline error. Hard-redirecting here would reload
    // the page before the error banner paints.
    const isLoginAttempt = err.config?.url?.includes('/auth/login')
    if (err.response?.status === 401 && !isLoginAttempt) {
      useAuthStore.getState().clear()
      window.location.href = '/login'
    }
    return Promise.reject(err)
  },
)

export default api
