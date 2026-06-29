import { useAuthStore } from '@/stores/auth'
import ClientScopesPage from '@/components/ClientScopesPage'

export default function TenantClientScopesPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <ClientScopesPage orgId={orgId!} />
}
