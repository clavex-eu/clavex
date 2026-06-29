import { useAuthStore } from '@/stores/auth'
import ClientsPage from '@/components/ClientsPage'

export default function TenantClientsPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <ClientsPage orgId={orgId!} />
}
