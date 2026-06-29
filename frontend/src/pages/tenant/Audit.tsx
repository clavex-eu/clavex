import { useAuthStore } from '@/stores/auth'
import AuditLogPage from '@/components/AuditLogPage'

export default function TenantAuditPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <AuditLogPage orgId={orgId!} />
}
