import { useAuthStore } from '@/stores/auth'
import LifecycleRulesPage from '@/components/LifecycleRulesPage'

export default function TenantLifecycleRulesPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <LifecycleRulesPage orgId={orgId!} />
}
