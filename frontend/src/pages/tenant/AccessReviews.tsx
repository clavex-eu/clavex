import { useAuthStore } from '@/stores/auth'
import AccessReviewsPage from '@/components/AccessReviewsPage'

export default function TenantAccessReviewsPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <AccessReviewsPage orgId={orgId!} />
}
