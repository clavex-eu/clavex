import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Users, KeyRound, Palette, FileText, ChevronRight, Shield, ShieldCheck } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Badge, Card, Spinner, PageHeader, Button } from '@/components/ui'

interface Org {
  id: string
  name: string
  slug: string
  is_active: boolean
  mfa_required: boolean
  created_at: string
}

const sections = [
  { to: 'users',    icon: Users,         label: 'Users',        description: 'Manage users and role assignments' },
  { to: 'roles',    icon: Shield,        label: 'Roles',        description: 'Create and assign roles for this org' },
  { to: 'clients',  icon: KeyRound,      label: 'OIDC Clients', description: 'OAuth2/OIDC application registrations' },
  { to: 'branding', icon: Palette,       label: 'Branding',     description: 'Customize the login page appearance' },
  { to: 'captcha',  icon: ShieldCheck,   label: 'CAPTCHA',      description: 'Bot protection on the login page' },
  { to: 'audit',    icon: FileText,      label: 'Audit Log',    description: 'Authentication and admin activity' },
]

export default function OrgDetailPage() {
  const { orgId } = useParams<{ orgId: string }>()
  const qc = useQueryClient()

  const { data: org, isLoading } = useQuery<Org>({
    queryKey: ['org', orgId],
    queryFn: () => api.get(`/organizations/${orgId}`).then((r) => r.data),
  })

  const updateOrg = useMutation({
    mutationFn: (body: object) => api.patch(`/organizations/${orgId}`, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['org', orgId] }); toast.success('Organization updated') },
    onError: () => toast.error('Failed to update'),
  })

  if (isLoading) return <Spinner />

  return (
    <div>
      <div style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginBottom: 8 }}>
        <Link to="/admin/orgs" style={{ color: 'var(--clavex-700)', textDecoration: 'none' }}>Organizations</Link>
        <span style={{ margin: '0 6px' }}>/</span>
        <span style={{ color: 'var(--clavex-ink)' }}>{org?.name}</span>
      </div>

      <PageHeader
        title={org?.name ?? ''}
        action={
          <Badge variant={org?.is_active ? 'green' : 'gray'}>
            {org?.is_active ? 'Active' : 'Inactive'}
          </Badge>
        }
      />

      <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginBottom: 24 }}>
        Slug: <code style={{ background: 'var(--clavex-50)', border: '0.5px solid var(--clavex-border)', padding: '2px 8px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace' }}>{org?.slug}</code>
      </p>

      {/* MFA org-level policy */}
      <div style={{
        background: 'white', border: '0.5px solid var(--clavex-border)',
        borderRadius: 'var(--clavex-radius-lg)', padding: '16px 20px', marginBottom: 20,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 8, background: org?.mfa_required ? 'var(--clavex-50)' : '#F5F4F0', border: '0.5px solid var(--clavex-border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield style={{ width: 16, height: 16, color: org?.mfa_required ? 'var(--clavex-700)' : 'var(--clavex-neutral)' }} />
          </div>
          <div>
            <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', fontSize: 14 }}>MFA organization policy</p>
            <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginTop: 2 }}>
              {org?.mfa_required
                ? 'MFA is required for all users in this organization'
                : 'MFA is optional — users can enable it voluntarily'}
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <Badge variant={org?.mfa_required ? 'purple' : 'gray'}>
            {org?.mfa_required ? 'Required' : 'Optional'}
          </Badge>
          <Button
            variant="secondary"
            size="sm"
            loading={updateOrg.isPending}
            onClick={() => updateOrg.mutate({ mfa_required: !org?.mfa_required })}
          >
            {org?.mfa_required ? 'Make optional' : 'Require MFA'}
          </Button>
        </div>
      </div>

      {/* Section grid */}
      <div className="grid grid-cols-2 gap-4">
        {sections.map(({ to, icon: Icon, label, description }) => (
          <Link key={to} to={`/admin/orgs/${orgId}/${to}`} style={{ textDecoration: 'none' }}>
            <Card className="flex items-center gap-4 px-5 py-4 cursor-pointer group hover:shadow-sm transition-shadow">
              <div style={{ flexShrink: 0, width: 36, height: 36, borderRadius: 8, background: 'var(--clavex-50)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Icon style={{ width: 18, height: 18, color: 'var(--clavex-700)' }} />
              </div>
              <div className="flex-1 min-w-0">
                <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', fontSize: 14 }}>{label}</p>
                <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginTop: 2 }} className="truncate">{description}</p>
              </div>
              <ChevronRight style={{ width: 15, height: 15, color: 'var(--clavex-border)', flexShrink: 0 }} />
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}

