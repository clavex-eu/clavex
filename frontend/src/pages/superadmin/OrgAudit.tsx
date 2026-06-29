import { useParams, Link } from 'react-router-dom'
import AuditLogPage from '@/components/AuditLogPage'

function Breadcrumb({ orgId }: { orgId: string }) {
  return (
    <p className="text-sm text-gray-400 mb-4">
      <Link to="/admin/orgs" className="hover:text-indigo-600">Organizations</Link>
      <span className="mx-1.5">/</span>
      <Link to={`/admin/orgs/${orgId}`} className="hover:text-indigo-600">Detail</Link>
      <span className="mx-1.5">/</span>
      <span className="text-gray-700">Audit Log</span>
    </p>
  )
}

export default function OrgAuditPage() {
  const { orgId } = useParams<{ orgId: string }>()
  return <AuditLogPage orgId={orgId!} breadcrumb={<Breadcrumb orgId={orgId!} />} />
}
