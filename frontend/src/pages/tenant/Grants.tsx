import { useAuthStore } from '@/stores/auth'
import ConsentGrantsPage from '@/components/ConsentGrantsPage'

export default function TenantGrantsPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <ConsentGrantsPage orgId={orgId ?? ''} />
}
