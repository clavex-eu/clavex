import { useAuthStore } from '@/stores/auth'
import WebhooksPage from '@/components/WebhooksPage'

export default function TenantWebhooksPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <WebhooksPage orgId={orgId!} />
}
