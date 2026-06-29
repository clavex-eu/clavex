import { useAuthStore } from '@/stores/auth'
import ScimPushPage from '@/components/ScimPushPage'

export default function TenantScimPushPage() {
  const orgId = useAuthStore((s) => s.orgId)
  if (!orgId) return null
  return <ScimPushPage orgId={orgId} />
}
