import { useAuthStore } from '@/stores/auth'
import BrandingPage from '@/components/BrandingPage'

export default function TenantBrandingPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <BrandingPage orgId={orgId!} />
}
