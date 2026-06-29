import { useAuthStore } from '@/stores/auth'
import SessionsPage from '@/components/SessionsPage'

export default function TenantSessionsPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <SessionsPage orgId={orgId!} />
}
