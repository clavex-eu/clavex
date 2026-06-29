import { useParams, Link } from 'react-router-dom'
import CaptchaPage from '@/pages/admin/CaptchaPage'

function Breadcrumb({ orgId }: { orgId: string }) {
  return (
    <p className="text-sm text-gray-400 mb-4">
      <Link to="/admin/orgs" className="hover:text-indigo-600">Organizations</Link>
      <span className="mx-1.5">/</span>
      <Link to={`/admin/orgs/${orgId}`} className="hover:text-indigo-600">Detail</Link>
      <span className="mx-1.5">/</span>
      <span className="text-gray-700">CAPTCHA</span>
    </p>
  )
}

export default function OrgCaptchaPage() {
  const { orgId } = useParams<{ orgId: string }>()
  return <CaptchaPage orgId={orgId!} breadcrumb={<Breadcrumb orgId={orgId!} />} />
}
