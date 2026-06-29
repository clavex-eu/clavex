import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, Users, KeyRound, Palette, FileText, Building2, ChevronRight } from 'lucide-react'
import toast from 'react-hot-toast'
import api, { toArr } from '@/lib/api'
import { Badge, Button, Modal, Input, PageHeader, EmptyState, Spinner } from '@/components/ui'

interface Org { id: string; name: string; slug: string; is_active: boolean; created_at: string }

export default function OrgsPage() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')

  const { data, isLoading } = useQuery<Org[]>({
    queryKey: ['orgs'],
    queryFn: () => api.get('/organizations').then((r) => toArr(r.data)),
  })

  const createMutation = useMutation({
    mutationFn: (body: { name: string; slug: string }) => api.post('/organizations', body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['orgs'] }); toast.success('Organization created'); setShowCreate(false); setName(''); setSlug('') },
    onError: () => toast.error('Failed to create organization'),
  })

  const orgs = data ?? []

  return (
    <div>
      <PageHeader
        title="Organizations"
        subtitle={`${orgs.length} total`}
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" /> New organization
          </Button>
        }
      />

      {isLoading ? <Spinner /> : orgs.length === 0 ? (
        <div style={{
          background: 'white',
          border: '0.5px solid var(--clavex-border)',
          borderRadius: 'var(--clavex-radius-lg)',
        }}>
          <EmptyState icon={Building2} title="No organizations yet" message="Create your first organization to get started" />
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
          {orgs.map((org) => (
            <Link key={org.id} to={`/admin/orgs/${org.id}`} style={{ textDecoration: 'none' }}>
              <div style={{
                background: 'white',
                border: '0.5px solid var(--clavex-border)',
                borderRadius: 'var(--clavex-radius-lg)',
                padding: '18px 20px',
                display: 'flex',
                flexDirection: 'column',
                gap: 14,
                transition: 'box-shadow 150ms ease, border-color 150ms ease',
                cursor: 'pointer',
              }}
                onMouseEnter={(e) => {
                  const el = e.currentTarget
                  el.style.borderColor = 'var(--clavex-primary)'
                  el.style.boxShadow = '0 2px 12px rgba(29,158,117,0.08)'
                }}
                onMouseLeave={(e) => {
                  const el = e.currentTarget
                  el.style.borderColor = 'var(--clavex-border)'
                  el.style.boxShadow = 'none'
                }}
              >
                {/* Header row */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div style={{
                    width: 40, height: 40, borderRadius: 10, flexShrink: 0,
                    background: 'var(--clavex-50)',
                    border: '0.5px solid var(--clavex-border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <span style={{ color: 'var(--clavex-700)', fontWeight: 700, fontSize: 16 }}>
                      {org.name[0].toUpperCase()}
                    </span>
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', fontSize: 14, lineHeight: 1.2 }}>
                      {org.name}
                    </p>
                    <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', fontFamily: 'monospace', marginTop: 2 }}>
                      {org.slug}
                    </p>
                  </div>
                  <Badge variant={org.is_active ? 'green' : 'gray'}>
                    {org.is_active ? 'Active' : 'Inactive'}
                  </Badge>
                </div>

                {/* Footer row */}
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  paddingTop: 12,
                  borderTop: '0.5px solid var(--clavex-surface)',
                }}>
                  <div style={{ display: 'flex', gap: 16 }}>
                    {[
                      { Icon: Users, label: 'Users' },
                      { Icon: KeyRound, label: 'Clients' },
                      { Icon: Palette, label: 'Branding' },
                      { Icon: FileText, label: 'Audit' },
                    ].map(({ Icon, label }) => (
                      <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <Icon style={{ width: 13, height: 13, color: 'var(--clavex-400)' }} />
                        <span style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>{label}</span>
                      </div>
                    ))}
                  </div>
                  <ChevronRight style={{ width: 15, height: 15, color: 'var(--clavex-border)' }} />
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}

      <Modal open={showCreate} title="New organization" description="Create a new tenant in Clavex" onClose={() => setShowCreate(false)}>
        <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate({ name, slug }) }} className="space-y-4">
          <Input
            label="Display name" value={name} required autoFocus
            onChange={(e) => { setName(e.target.value); setSlug(e.target.value.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '')) }}
          />
          <Input label="Slug" value={slug} pattern="[a-z0-9-]+" required hint="Lowercase letters, numbers and hyphens" onChange={(e) => setSlug(e.target.value)} />
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="secondary" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button type="submit" loading={createMutation.isPending}>Create</Button>
          </div>
        </form>
      </Modal>
    </div>
  )
}
