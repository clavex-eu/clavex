import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Users, Shield, UserPlus, X } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuthStore } from '@/stores/auth'
import { Button, Card, Modal, Input, PageHeader, Badge, Spinner, ManagedBadge } from '@/components/ui'
import { cn } from '@/lib/cn'
import api, { toArr } from '@/lib/api'

interface Group {
  id: string
  name: string
  description?: string
  is_system: boolean
  member_count: number
  created_at: string
  managed_by?: string | null
  managed_ref?: string | null
}

interface User {
  id: string
  email: string
  first_name?: string
  last_name?: string
}

interface Role {
  id: string
  name: string
  description?: string
  is_system: boolean
}

export default function GroupsPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()

  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })
  const [selected, setSelected] = useState<Group | null>(null)
  const [tab, setTab] = useState<'members' | 'roles'>('members')
  const [showAddMember, setShowAddMember] = useState(false)
  const [showAddRole, setShowAddRole] = useState(false)

  // ── Queries ──────────────────────────────────────────────────────────────

  const { data: groups = [], isLoading } = useQuery<Group[]>({
    queryKey: ['groups', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/groups`).then((r) => toArr(r.data)),
    enabled: !!orgId,
  })

  const { data: members = [] } = useQuery<User[]>({
    queryKey: ['group-members', selected?.id],
    queryFn: () => api.get(`/organizations/${orgId}/groups/${selected!.id}/members`).then((r) => toArr(r.data)),
    enabled: !!selected,
  })

  const { data: groupRoles = [] } = useQuery<Role[]>({
    queryKey: ['group-roles', selected?.id],
    queryFn: () => api.get(`/organizations/${orgId}/groups/${selected!.id}/roles`).then((r) => toArr(r.data)),
    enabled: !!selected,
  })

  const { data: allUsers = [] } = useQuery<User[]>({
    queryKey: ['users-for-group', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/users`).then((r) => toArr(r.data)),
    enabled: showAddMember,
  })

  const { data: allRoles = [] } = useQuery<Role[]>({
    queryKey: ['roles-for-group', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/roles`).then((r) => Array.isArray(r.data) ? r.data : (r.data?.items ?? [])),
    enabled: showAddRole,
  })

  // ── Mutations ─────────────────────────────────────────────────────────────

  const createGroup = useMutation({
    mutationFn: () => api.post(`/organizations/${orgId}/groups`, form),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['groups', orgId] })
      toast.success('Group created')
      setShowCreate(false)
      setForm({ name: '', description: '' })
      setSelected(res.data)
    },
    onError: () => toast.error('Failed to create group'),
  })

  const deleteGroup = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/groups/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['groups', orgId] })
      toast.success('Group deleted')
      setSelected(null)
    },
    onError: () => toast.error('Failed to delete group'),
  })

  const addMember = useMutation({
    mutationFn: (userId: string) =>
      api.post(`/organizations/${orgId}/groups/${selected!.id}/members`, { user_id: userId }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['group-members', selected?.id] })
      qc.invalidateQueries({ queryKey: ['groups', orgId] })
      toast.success('Member added')
      setShowAddMember(false)
    },
    onError: () => toast.error('Failed to add member'),
  })

  const removeMember = useMutation({
    mutationFn: (userId: string) =>
      api.delete(`/organizations/${orgId}/groups/${selected!.id}/members/${userId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['group-members', selected?.id] })
      qc.invalidateQueries({ queryKey: ['groups', orgId] })
    },
    onError: () => toast.error('Failed to remove member'),
  })

  const assignRole = useMutation({
    mutationFn: (roleId: string) =>
      api.post(`/organizations/${orgId}/groups/${selected!.id}/roles`, { role_id: roleId }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['group-roles', selected?.id] })
      toast.success('Role assigned')
      setShowAddRole(false)
    },
    onError: () => toast.error('Failed to assign role'),
  })

  const removeRole = useMutation({
    mutationFn: (roleId: string) =>
      api.delete(`/organizations/${orgId}/groups/${selected!.id}/roles/${roleId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['group-roles', selected?.id] }),
    onError: () => toast.error('Failed to remove role'),
  })

  // ── Helpers ───────────────────────────────────────────────────────────────

  const memberIds = new Set(members.map((m) => m.id))
  const assignedRoleIds = new Set(groupRoles.map((r) => r.id))

  function userDisplayName(u: User) {
    const name = [u.first_name, u.last_name].filter(Boolean).join(' ')
    return name || u.email
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div>
      <PageHeader
        title="Groups"
        subtitle="Organize users into groups and assign roles in bulk."
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" />
            New group
          </Button>
        }
      />

      <div className="flex gap-5 items-start">
        {/* ── Group list ─────────────────────────────────────── */}
        <Card className="w-64 flex-shrink-0 overflow-hidden">
          {isLoading ? (
            <div className="flex justify-center py-10"><Spinner /></div>
          ) : groups.length === 0 ? (
            <div className="py-10 px-5 text-center">
              <Users className="h-6 w-6 text-gray-300 mx-auto mb-2" />
              <p className="text-sm text-gray-400">No groups yet</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-50">
              {groups.map((g) => (
                <button
                  key={g.id}
                  onClick={() => { setSelected(g); setTab('members') }}
                  className={cn(
                    'w-full text-left px-4 py-3 flex items-center gap-3 transition-colors',
                    selected?.id === g.id
                      ? 'bg-brand-50 border-l-2 border-brand-500'
                      : 'hover:bg-gray-50 border-l-2 border-transparent',
                  )}
                >
                  <div className="h-8 w-8 rounded-lg bg-gray-100 flex items-center justify-center flex-shrink-0">
                    <span className="text-xs font-bold text-gray-500">{g.name[0].toUpperCase()}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <p className="text-sm font-medium text-gray-900 truncate">{g.name}</p>
                      <ManagedBadge managedBy={g.managed_by} managedRef={g.managed_ref} />
                    </div>
                    <p className="text-xs text-gray-400">{g.member_count} member{g.member_count !== 1 ? 's' : ''}</p>
                  </div>
                  {g.is_system && (
                    <span className="text-[10px] text-gray-400 bg-gray-100 px-1.5 py-0.5 rounded-full">sys</span>
                  )}
                </button>
              ))}
            </div>
          )}
        </Card>

        {/* ── Group detail ───────────────────────────────────── */}
        {selected ? (
          <div className="flex-1 space-y-4">
            {/* Header */}
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-gray-900">{selected.name}</h2>
                {selected.description && (
                  <p className="text-sm text-gray-500 mt-0.5">{selected.description}</p>
                )}
              </div>
              {!selected.is_system && (
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => {
                    if (confirm(`Delete group "${selected.name}"?`)) deleteGroup.mutate(selected.id)
                  }}
                >
                  <Trash2 className="h-4 w-4" />
                  Delete group
                </Button>
              )}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-gray-100">
              {(['members', 'roles'] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={cn(
                    'px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors capitalize',
                    tab === t
                      ? 'border-brand-500 text-brand-700'
                      : 'border-transparent text-gray-500 hover:text-gray-700',
                  )}
                >
                  {t}
                  <span className={cn(
                    'ml-1.5 text-xs px-1.5 py-0.5 rounded-full',
                    tab === t ? 'bg-brand-100 text-brand-700' : 'bg-gray-100 text-gray-500',
                  )}>
                    {t === 'members' ? members.length : groupRoles.length}
                  </span>
                </button>
              ))}
            </div>

            {/* Members tab */}
            {tab === 'members' && (
              <Card>
                <div className="flex items-center justify-between px-5 py-3 border-b border-gray-50">
                  <p className="text-sm font-medium text-gray-700">Members</p>
                  <Button size="sm" variant="secondary" onClick={() => setShowAddMember(true)}>
                    <UserPlus className="h-4 w-4" />
                    Add member
                  </Button>
                </div>
                {members.length === 0 ? (
                  <div className="py-8 text-center text-sm text-gray-400">No members yet</div>
                ) : (
                  <div className="divide-y divide-gray-50">
                    {members.map((u) => (
                      <div key={u.id} className="flex items-center gap-3 px-5 py-3">
                        <div className="h-8 w-8 rounded-full bg-brand-100 flex items-center justify-center flex-shrink-0">
                          <span className="text-xs font-semibold text-brand-700">{u.email[0].toUpperCase()}</span>
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-gray-900 truncate">{userDisplayName(u)}</p>
                          <p className="text-xs text-gray-400 truncate">{u.email}</p>
                        </div>
                        <button
                          onClick={() => removeMember.mutate(u.id)}
                          className="text-gray-300 hover:text-red-500 transition-colors p-1 rounded"
                          title="Remove from group"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            )}

            {/* Roles tab */}
            {tab === 'roles' && (
              <Card>
                <div className="flex items-center justify-between px-5 py-3 border-b border-gray-50">
                  <p className="text-sm font-medium text-gray-700">Assigned roles</p>
                  <Button size="sm" variant="secondary" onClick={() => setShowAddRole(true)}>
                    <Shield className="h-4 w-4" />
                    Assign role
                  </Button>
                </div>
                {groupRoles.length === 0 ? (
                  <div className="py-8 text-center text-sm text-gray-400">No roles assigned</div>
                ) : (
                  <div className="divide-y divide-gray-50">
                    {groupRoles.map((r) => (
                      <div key={r.id} className="flex items-center gap-3 px-5 py-3">
                        <div className="h-8 w-8 rounded-lg bg-violet-50 flex items-center justify-center flex-shrink-0">
                          <Shield className="h-4 w-4 text-violet-600" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-gray-900">{r.name}</p>
                          {r.description && <p className="text-xs text-gray-400">{r.description}</p>}
                        </div>
                        {r.is_system && <Badge variant="purple">system</Badge>}
                        {!r.is_system && (
                          <button
                            onClick={() => removeRole.mutate(r.id)}
                            className="text-gray-300 hover:text-red-500 transition-colors p-1 rounded"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            )}
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center py-20 text-gray-400">
            <div className="text-center">
              <Users className="h-8 w-8 mx-auto mb-2 text-gray-200" />
              <p className="text-sm">Select a group to manage its members and roles</p>
            </div>
          </div>
        )}
      </div>

      {/* Create group modal */}
      <Modal open={showCreate} title="Create group" onClose={() => setShowCreate(false)}>
        <form onSubmit={(e) => { e.preventDefault(); createGroup.mutate() }} className="space-y-4">
          <Input
            label="Group name"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="engineering"
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
            <Button type="submit" disabled={createGroup.isPending}>
              {createGroup.isPending ? 'Creating…' : 'Create group'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Add member modal */}
      <Modal open={showAddMember} title="Add member" onClose={() => setShowAddMember(false)}>
        <div className="space-y-2">
          <p className="text-sm text-gray-500 mb-3">Select a user to add to <strong>{selected?.name}</strong>.</p>
          {allUsers.filter((u) => !memberIds.has(u.id)).length === 0 ? (
            <p className="text-sm text-gray-400 py-4 text-center">All users are already members.</p>
          ) : (
            allUsers
              .filter((u) => !memberIds.has(u.id))
              .map((u) => (
                <button
                  key={u.id}
                  onClick={() => addMember.mutate(u.id)}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-brand-50 hover:border-brand-200 border border-gray-100 transition-all text-left"
                >
                  <div className="h-8 w-8 rounded-full bg-brand-100 flex items-center justify-center flex-shrink-0">
                    <span className="text-xs font-semibold text-brand-700">{u.email[0].toUpperCase()}</span>
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">{userDisplayName(u)}</p>
                    <p className="text-xs text-gray-400 truncate">{u.email}</p>
                  </div>
                </button>
              ))
          )}
        </div>
      </Modal>

      {/* Assign role modal */}
      <Modal open={showAddRole} title="Assign role" onClose={() => setShowAddRole(false)}>
        <div className="space-y-2">
          <p className="text-sm text-gray-500 mb-3">Select a role to assign to <strong>{selected?.name}</strong>.</p>
          {allRoles.filter((r) => !assignedRoleIds.has(r.id)).length === 0 ? (
            <p className="text-sm text-gray-400 py-4 text-center">All roles are already assigned.</p>
          ) : (
            allRoles
              .filter((r) => !assignedRoleIds.has(r.id))
              .map((r) => (
                <button
                  key={r.id}
                  onClick={() => assignRole.mutate(r.id)}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-brand-50 hover:border-brand-200 border border-gray-100 transition-all text-left"
                >
                  <div className="h-8 w-8 rounded-lg bg-violet-50 flex items-center justify-center flex-shrink-0">
                    <Shield className="h-4 w-4 text-violet-600" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-gray-900">{r.name}</p>
                    {r.description && <p className="text-xs text-gray-400 truncate">{r.description}</p>}
                  </div>
                  {r.is_system && <Badge variant="purple">system</Badge>}
                </button>
              ))
          )}
        </div>
      </Modal>
    </div>
  )
}
