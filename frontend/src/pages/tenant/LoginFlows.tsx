import LoginFlowsPage from '../../components/LoginFlowsPage';
import { useAuthStore } from '@/stores/auth';

export default function LoginFlows() {
  const orgId = useAuthStore((s) => s.orgId);
  return <LoginFlowsPage orgId={orgId!} />;
}
