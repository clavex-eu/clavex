import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, ChevronDown, ChevronRight, GitMerge } from 'lucide-react'
import toast from 'react-hot-toast'
import api, { toArr } from '@/lib/api'
import { Button, Card, Modal, Input, PageHeader, EmptyState, Spinner } from '@/components/ui'

interface Role {
  id: string
  name: string
  description?: string
  is_system: boolean
  created_at: string
}

interface Props {
  orgId: string
  breadcrumb?: React.ReactNode
}

// ── Composite role panel ───────────────────────────────────────────────────────

function ChildRolesPanel({ orgId, roleId, allRoles }: { orgId: string; roleId: string; allRoles: Role[] }) {
  const qc = useQueryClient()
  const [adding, setAdding] = useState(false)
  const [childId, setChildId] = useState('')

  const { data: children = [], isLoading } = useQuery<Role[]>({
    queryKey: ['role-children', orgId, roleId],
    queryFn: () => api.get(`/organizations/${orgId}/roles/${roleId}/children`).then((r) => toArr(r.data)),
  })

  const add = useMutation({
    mutationFn: (cid: string) =>
      api.put(`/organizations/${orgId}/roles/${roleId}/children/${cid}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['role-children', orgId, roleId] })
      toast.success('Child role added')
      setAdding(false)
      setChildId('')
    },
    onError: () => toast.error('Failed to add child role'),
  })

  const remove = useMutation({
    mutationFn: (cid: string) =>
      api.delete(`/organizations/${orgId}/roles/${roleId}/children/${cid}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['role-children', orgId, roleId] })
      toast.success('Child role removed')
    },
    onError: () => toast.error('Failed to remove child role'),
  })

  const childIdSet = new Set(children.map((c) => c.id))
  const available = allRoles.filter((r) => r.id !== roleId && !childIdSet.has(r.id))

  if (isLoading) return <div className="px-6 py-3 text-xs text-gray-400">Loading…</div>

  return (
    <div className="px-6 pb-4 pt-1 bg-gray-50 border-t border-gray-100">
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
        Inherited roles (composite)
      </p>
      <div className="flex flex-wrap gap-2 mb-3">
        {children.length === 0 && (
          <span className="text-xs text-gray-400 italic">No child roles — this role is not composite</span>
        )}
        {children.map((c) => (
          <span
            key={c.id}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 text-xs font-medium"
          >
            {c.name}
            <button
              onClick={() => remove.mutate(c.id)}
              className="ml-0.5 hover:text-red-600 transition-colors"
              title="Remove"
            >
              ×
            </button>
          </span>
        ))}
      </div>

      {adding ? (
        <div className="flex items-center gap-2">
          <select
            value={childId}
            onChange={(e) => setChildId(e.target.value)}
            className="text-sm border border-gray-300 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
          >
            <option value="">Select a role…</option>
            {available.map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </select>
          <Button size="sm" onClick={() => childId && add.mutate(childId)} disabled={!childId || add.isPending}>
            Add
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setAdding(false)}>Cancel</Button>
        </div>
      ) : (
        <button
          onClick={() => setAdding(true)}
          className="text-xs text-[var(--clavex-primary)] hover:underline flex items-center gap-1"
        >
          <Plus className="h-3 w-3" /> Add child role
        </button>
      )}
    </div>
  )
}

export default function RolesPage({ orgId, breadcrumb }: Props) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })
  const [expanded, setExpanded] = useState<string | null>(null)

  const { data: roles = [], isLoading } = useQuery<Role[]>({
    queryKey: ['roles', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/roles`).then((r) => toArr(r.data)),
    enabled: !!orgId,
  })

  const createRole = useMutation({
    mutationFn: (body: { name: string; description: string }) =>
      api.post(`/organizations/${orgId}/roles`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['roles', orgId] })
      toast.success('Role created')
      setShowCreate(false)
      setForm({ name: '', description: '' })
    },
    onError: () => toast.error('Failed to create role'),
  })

  const deleteRole = useMutation({
    mutationFn: (roleId: string) => api.delete(`/organizations/${orgId}/roles/${roleId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['roles', orgId] })
      toast.success('Role deleted')
    },
    onError: () => toast.error('Failed to delete role — it may be a system role or still assigned'),
  })

  return (
    <div>
      {breadcrumb}
      <PageHeader
        title="Roles"
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" />
            New role
          </Button>
        }
      />

      {isLoading ? (
        <Spinner />
      ) : (
        <Card>
          {roles.length === 0 ? (
            <EmptyState message="No roles defined." />
          ) : (
            <div className="divide-y divide-gray-200">
              {roles.map((role) => (
                <div key={role.id}>
                  <div className="flex items-center justify-between px-6 py-4">
                    <div className="flex items-center gap-3 min-w-0">
                      <button
                        onClick={() => setExpanded(expanded === role.id ? null : role.id)}
                        className="text-gray-400 hover:text-gray-600 flex-shrink-0 transition-colors"
                        title="Composite roles"
                      >
                        {expanded === role.id
                          ? <ChevronDown className="h-4 w-4" />
                          : <ChevronRight className="h-4 w-4" />
                        }
                      </button>
                      <div className="min-w-0">
                        <p className="font-medium text-gray-900 text-sm">{role.name}</p>
                        {role.description && (
                          <p className="text-xs text-gray-400 mt-0.5">{role.description}</p>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {role.is_system && (
                        <span className="text-xs text-gray-400 italic">system</span>
                      )}
                      <button
                        onClick={() => setExpanded(expanded === role.id ? null : role.id)}
                        className="p-1.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition-colors"
                        title="Manage composite roles"
                      >
                        <GitMerge className="h-3.5 w-3.5" />
                      </button>
                      {!role.is_system && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            if (confirm(`Delete role "${role.name}"?`)) deleteRole.mutate(role.id)
                          }}
                        >
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                    </div>
                  </div>
                  {expanded === role.id && (
                    <ChildRolesPanel orgId={orgId} roleId={role.id} allRoles={roles} />
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      <Modal open={showCreate} title="Create role" onClose={() => setShowCreate(false)}>
        <form
          onSubmit={(e) => { e.preventDefault(); createRole.mutate(form) }}
          className="space-y-4"
        >
          <Input
            label="Role name"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value.toLowerCase().replace(/\s+/g, '_') }))}
            placeholder="e.g. billing_admin"
            required
            autoFocus
          />
          <Input
            label="Description (optional)"
            value={form.description}
            onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
          />
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button type="submit" disabled={createRole.isPending}>
              {createRole.isPending ? 'Creating…' : 'Create role'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  )
}
