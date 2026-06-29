import { useAuthStore } from '@/stores/auth'
import CaptchaPage from '@/pages/admin/CaptchaPage'

export default function TenantCaptchaPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <CaptchaPage orgId={orgId!} />
}
