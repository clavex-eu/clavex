import { useAuthStore } from '@/stores/auth'
import UsersPage from '@/components/UsersPage'

export default function TenantUsersPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <UsersPage orgId={orgId!} />
}
