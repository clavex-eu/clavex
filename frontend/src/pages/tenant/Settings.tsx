import { useAuthStore } from '@/stores/auth'
import SettingsPage from '@/components/SettingsPage'

export default function TenantSettingsPage() {
  const orgId = useAuthStore((s) => s.orgId)
  return <SettingsPage orgId={orgId!} />
}
