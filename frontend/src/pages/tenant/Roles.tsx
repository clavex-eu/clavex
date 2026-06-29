import { useAuthStore } from '@/stores/auth'
import RolesPage from '@/components/RolesPage'

export default function TenantRolesPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <RolesPage orgId={orgId!} />
}
