import { useAuthStore } from '@/stores/auth'
import IdentityProvidersPage from '@/components/IdentityProvidersPage'

export default function TenantIdentityProvidersPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <IdentityProvidersPage orgId={orgId!} />
}
