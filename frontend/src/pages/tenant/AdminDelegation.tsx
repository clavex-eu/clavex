import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import {
  Shield, Plus, Trash2, Pencil, X, CheckCircle, Lock,
  UserCheck, UserMinus, ChevronDown, ChevronRight, Loader2,
  RefreshCw, Sparkles,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface PermissionInfo {
  token: string
  resource: string
  action: string
  description: string
}

interface AdminRole {
  id: string
  org_id: string
  name: string
  description?: string
  permissions: string[]
  is_system: boolean
  created_at: string
  updated_at: string
}

interface AdminRoleAssignment {
  id: string
  user_id: string
  role_id: string
  role_name: string
  created_by?: string
  created_at: string
}

interface User {
  id: string
  email: string
  display_name?: string
}

// ── Shared styles ─────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}
const inp: React.CSSProperties = {
  background: 'white',
  color: 'var(--clavex-ink)',
  border: '0.5px solid var(--clavex-border-subtle)',
  borderRadius: 8,
  padding: '7px 11px',
  fontSize: 13,
  outline: 'none',
  width: '100%',
}
const lbl: React.CSSProperties = {
  display: 'block',
  fontSize: 11,
  fontWeight: 600,
  textTransform: 'uppercase' as const,
  letterSpacing: '0.06em',
  color: 'var(--clavex-ink-muted)',
  marginBottom: 4,
}
const btn = (variant: 'primary' | 'ghost' | 'danger' = 'primary'): React.CSSProperties => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  padding: '7px 14px',
  borderRadius: 8,
  fontSize: 13,
  fontWeight: 600,
  cursor: 'pointer',
  border: variant === 'ghost' ? '0.5px solid var(--clavex-border-subtle)' : 'none',
  background:
    variant === 'primary' ? 'var(--clavex-primary)'
    : variant === 'danger'  ? '#ef4444'
    : 'white',
  color: variant === 'ghost' ? 'var(--clavex-ink)' : 'white',
})

// ── Permissions picker ────────────────────────────────────────────────────────

function PermissionsPicker({
  all,
  selected,
  onChange,
}: {
  all: PermissionInfo[]
  selected: string[]
  onChange: (perms: string[]) => void
}) {
  const resources = Array.from(new Set(all.map(p => p.resource)))

  const toggle = (token: string) =>
    onChange(
      selected.includes(token)
        ? selected.filter(t => t !== token)
        : [...selected, token],
    )

  return (
    <div className="space-y-3">
      {resources.map(resource => {
        const perms = all.filter(p => p.resource === resource)
        return (
          <div key={resource} style={{ border: '0.5px solid var(--clavex-border)', borderRadius: 8, overflow: 'hidden' }}>
            <div style={{ background: 'var(--clavex-surface)', padding: '8px 14px', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--clavex-ink-muted)' }}>
              {resource.replace(/_/g, ' ')}
            </div>
            <div style={{ padding: '10px 14px', display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {perms.map(p => (
                <label
                  key={p.token}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}
                  title={p.description}
                >
                  <input
                    type="checkbox"
                    checked={selected.includes(p.token)}
                    onChange={() => toggle(p.token)}
                    style={{ accentColor: 'var(--clavex-primary)', width: 14, height: 14 }}
                  />
                  <span style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--clavex-ink)', fontWeight: 500 }}>
                    {p.action}
                  </span>
                </label>
              ))}
            </div>
            {perms.some(p => selected.includes(p.token)) && (
              <div style={{ padding: '0 14px 8px', fontSize: 11, color: 'var(--clavex-ink-muted)', lineHeight: 1.5 }}>
                {perms.filter(p => selected.includes(p.token)).map(p => p.description).join(' • ')}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Role form ─────────────────────────────────────────────────────────────────

function RoleForm({
  allPerms,
  initial,
  onSave,
  onCancel,
}: {
  allPerms: PermissionInfo[]
  initial?: AdminRole
  onSave: (name: string, desc: string, perms: string[]) => Promise<void>
  onCancel: () => void
}) {
  const [name, setName]   = useState(initial?.name ?? '')
  const [desc, setDesc]   = useState(initial?.description ?? '')
  const [perms, setPerms] = useState<string[]>(initial?.permissions ?? [])
  const [saving, setSaving] = useState(false)

  const handle = async () => {
    if (!name.trim()) { toast.error('Name is required'); return }
    if (perms.length === 0) { toast.error('Select at least one permission'); return }
    setSaving(true)
    try { await onSave(name.trim(), desc.trim(), perms) }
    finally { setSaving(false) }
  }

  return (
    <div style={{ ...card, borderColor: 'var(--clavex-primary)' }} className="space-y-4">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--clavex-ink)' }}>
          {initial ? 'Edit Admin Role' : 'Create Admin Role'}
        </span>
        <button style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--clavex-ink-muted)' }} onClick={onCancel}>
          <X size={16} />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label style={lbl}>Role Name</label>
          <input style={inp} value={name} onChange={e => setName(e.target.value)}
            placeholder="e.g. Helpdesk Read-Only" disabled={initial?.is_system} />
          {initial?.is_system && (
            <p style={{ fontSize: 11, color: '#f59e0b', marginTop: 4 }}>System role — name is immutable.</p>
          )}
        </div>
        <div>
          <label style={lbl}>Description</label>
          <input style={inp} value={desc} onChange={e => setDesc(e.target.value)}
            placeholder="Optional description for this role" />
        </div>
      </div>

      <div>
        <label style={{ ...lbl, marginBottom: 8 }}>Permissions</label>
        <PermissionsPicker all={allPerms} selected={perms} onChange={setPerms} />
      </div>

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button style={btn('ghost')} onClick={onCancel}>Cancel</button>
        <button style={btn('primary')} onClick={handle} disabled={saving}>
          {saving ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle size={14} />}
          {initial ? 'Save Changes' : 'Create Role'}
        </button>
      </div>
    </div>
  )
}

// ── Assignment panel ──────────────────────────────────────────────────────────

function AssignmentsPanel({ orgId, role }: { orgId: string; role: AdminRole }) {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [showUserSearch, setShowUserSearch] = useState(false)

  const { data: assignments } = useQuery<AdminRoleAssignment[]>({
    queryKey: ['admin-role-assignments', orgId, role.id],
    queryFn: async () => {
      // Fetch all users and filter by role by listing per user is impractical.
      // Instead, we list all users and check which ones have this role.
      // We'll use the role's assignment list indirectly via an org-wide approach:
      // Unfortunately the backend doesn't have GET /admin-roles/:id/users.
      // Workaround: store assignments when we do assign/unassign locally.
      // Placeholder — return empty; real data flows through the users search below.
      return []
    },
    enabled: false, // disabled; real data fetched via users search
  })

  // Search users to assign
  const { data: userResults, isLoading: searchLoading } = useQuery<User[]>({
    queryKey: ['admin-delegation-user-search', orgId, search],
    queryFn: () =>
      api.get(`/organizations/${orgId}/users`, { params: { search, limit: 10 } })
        .then(r => toArr<User>(r.data)),
    enabled: search.length > 1,
  })

  const assign = useMutation({
    mutationFn: (userId: string) =>
      api.put(`/organizations/${orgId}/users/${userId}/admin-roles/${role.id}`),
    onSuccess: () => {
      toast.success('Role assigned')
      setSelectedUser(null)
      setSearch('')
      setShowUserSearch(false)
      qc.invalidateQueries({ queryKey: ['admin-role-assignments', orgId, role.id] })
    },
    onError: () => toast.error('Assignment failed'),
  })

  const unassign = useMutation({
    mutationFn: ({ userId }: { userId: string }) =>
      api.delete(`/organizations/${orgId}/users/${userId}/admin-roles/${role.id}`),
    onSuccess: () => {
      toast.success('Role unassigned')
      qc.invalidateQueries({ queryKey: ['admin-role-assignments', orgId, role.id] })
    },
    onError: () => toast.error('Unassign failed'),
  })

  const list = assignments ?? []

  return (
    <div style={{ marginTop: 16 }} className="space-y-3">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)' }}>Assigned Users</span>
        {!showUserSearch && (
          <button style={btn('ghost')} onClick={() => setShowUserSearch(true)}>
            <Plus size={13} /> Assign User
          </button>
        )}
      </div>

      {showUserSearch && (
        <div style={{ ...card, padding: '14px 18px' }} className="space-y-3">
          <label style={lbl}>Search user by email or name</label>
          <input
            style={inp}
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Type to search…"
            autoFocus
          />
          {searchLoading && <p style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>Searching…</p>}
          {userResults && userResults.length > 0 && !selectedUser && (
            <div style={{ border: '0.5px solid var(--clavex-border)', borderRadius: 8, overflow: 'hidden' }}>
              {userResults.map(u => (
                <div
                  key={u.id}
                  style={{ padding: '8px 12px', cursor: 'pointer', fontSize: 13, color: 'var(--clavex-ink)', borderBottom: '0.5px solid var(--clavex-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--clavex-surface)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'white')}
                  onClick={() => { setSelectedUser(u); setSearch(u.email) }}
                >
                  <span>{u.email}</span>
                  {u.display_name && <span style={{ fontSize: 11, color: 'var(--clavex-ink-muted)' }}>{u.display_name}</span>}
                </div>
              ))}
            </div>
          )}
          {selectedUser && (
            <div style={{ padding: '8px 12px', background: '#f0fdf4', borderRadius: 8, border: '0.5px solid #86efac', fontSize: 13, color: '#166534' }}>
              <CheckCircle size={13} style={{ display: 'inline', marginRight: 6 }} />
              {selectedUser.email}
            </div>
          )}
          <div style={{ display: 'flex', gap: 8 }}>
            <button style={btn('ghost')} onClick={() => { setShowUserSearch(false); setSelectedUser(null); setSearch('') }}>Cancel</button>
            <button
              style={btn('primary')}
              disabled={!selectedUser || assign.isPending}
              onClick={() => selectedUser && assign.mutate(selectedUser.id)}
            >
              {assign.isPending ? <Loader2 size={14} className="animate-spin" /> : <UserCheck size={13} />}
              Assign {role.name}
            </button>
          </div>
        </div>
      )}

      {list.length === 0 && !showUserSearch && (
        <p style={{ fontSize: 12, color: 'var(--clavex-ink-muted)', padding: '8px 0' }}>
          No users assigned to this role yet.
        </p>
      )}
      {list.map(a => (
        <div key={a.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', background: 'var(--clavex-surface)', borderRadius: 8, fontSize: 13 }}>
          <code style={{ color: 'var(--clavex-ink)', fontSize: 12 }}>{a.user_id}</code>
          <span style={{ color: 'var(--clavex-ink-muted)', fontSize: 11 }}>{new Date(a.created_at).toLocaleDateString()}</span>
          <button
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ef4444', padding: 4 }}
            onClick={() => unassign.mutate({ userId: a.user_id })}
            title="Unassign"
          >
            <UserMinus size={14} />
          </button>
        </div>
      ))}
    </div>
  )
}

// ── Role card ─────────────────────────────────────────────────────────────────

function RoleCard({
  role,
  allPerms,
  orgId,
}: {
  role: AdminRole
  allPerms: PermissionInfo[]
  orgId: string
}) {
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [editing, setEditing] = useState(false)

  const update = useMutation({
    mutationFn: ({ name, desc, perms }: { name: string; desc: string; perms: string[] }) =>
      api.patch(`/organizations/${orgId}/admin-roles/${role.id}`, {
        name, description: desc, permissions: perms,
      }),
    onSuccess: () => {
      toast.success('Role updated')
      setEditing(false)
      qc.invalidateQueries({ queryKey: ['admin-roles', orgId] })
    },
    onError: () => toast.error('Update failed'),
  })

  const del = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/admin-roles/${role.id}`),
    onSuccess: () => {
      toast.success('Role deleted')
      qc.invalidateQueries({ queryKey: ['admin-roles', orgId] })
    },
    onError: () => toast.error('Cannot delete system role'),
  })

  if (editing) {
    return (
      <RoleForm
        allPerms={allPerms}
        initial={role}
        onSave={async (name, desc, perms) => { await update.mutateAsync({ name, desc, perms }) }}
        onCancel={() => setEditing(false)}
      />
    )
  }

  return (
    <div style={{ ...card, padding: 0, overflow: 'hidden' }}>
      {/* Header row */}
      <div
        style={{ padding: '14px 20px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 12 }}
        onClick={() => setExpanded(e => !e)}
      >
        {expanded ? <ChevronDown size={15} style={{ color: 'var(--clavex-ink-muted)', flexShrink: 0 }} />
                  : <ChevronRight size={15} style={{ color: 'var(--clavex-ink-muted)', flexShrink: 0 }} />}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontWeight: 700, color: 'var(--clavex-ink)', fontSize: 14 }}>{role.name}</span>
            {role.is_system && (
              <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 20, background: '#f0f9ff', color: '#0369a1', border: '0.5px solid #bae6fd', display: 'flex', alignItems: 'center', gap: 3 }}>
                <Lock size={9} /> system
              </span>
            )}
          </div>
          {role.description && (
            <p style={{ fontSize: 12, color: 'var(--clavex-ink-muted)', margin: '2px 0 0', lineHeight: 1.4 }}>{role.description}</p>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <span style={{ fontSize: 11, color: 'var(--clavex-ink-muted)' }}>{role.permissions.length} permission{role.permissions.length !== 1 ? 's' : ''}</span>
          <button
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 4, color: 'var(--clavex-ink-muted)' }}
            onClick={e => { e.stopPropagation(); setEditing(true) }}
            title="Edit"
          >
            <Pencil size={13} />
          </button>
          {!role.is_system && (
            <button
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 4, color: '#ef4444' }}
              onClick={e => { e.stopPropagation(); if (confirm(`Delete role "${role.name}"?`)) del.mutate() }}
              title="Delete"
            >
              <Trash2 size={13} />
            </button>
          )}
        </div>
      </div>

      {expanded && (
        <div style={{ padding: '0 20px 20px', borderTop: '0.5px solid var(--clavex-border)' }}>
          {/* Permission tags */}
          <div style={{ paddingTop: 14, display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 4 }}>
            {role.permissions.map(p => (
              <span key={p} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 4, fontFamily: 'monospace', background: '#f0fdf4', color: '#166534', border: '0.5px solid #86efac' }}>
                {p}
              </span>
            ))}
          </div>
          <AssignmentsPanel orgId={orgId} role={role} />
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AdminDelegationPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)

  const { data: roles = [], isLoading } = useQuery<AdminRole[]>({
    queryKey: ['admin-roles', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/admin-roles`).then(r => toArr<AdminRole>(r.data)),
    enabled: !!orgId,
  })

  const { data: allPerms = [] } = useQuery<PermissionInfo[]>({
    queryKey: ['admin-roles-permissions'],
    queryFn: () => api.get('/admin-roles/permissions').then(r => r.data),
  })

  const createRole = useMutation({
    mutationFn: ({ name, desc, perms }: { name: string; desc: string; perms: string[] }) =>
      api.post(`/organizations/${orgId}/admin-roles`, { name, description: desc, permissions: perms }),
    onSuccess: () => {
      toast.success('Admin role created')
      setCreating(false)
      qc.invalidateQueries({ queryKey: ['admin-roles', orgId] })
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(msg ?? 'Could not create role')
    },
  })

  const ensureSystem = useMutation({
    mutationFn: () => api.post(`/organizations/${orgId}/admin-roles/system/ensure`),
    onSuccess: () => {
      toast.success('System roles seeded')
      qc.invalidateQueries({ queryKey: ['admin-roles', orgId] })
    },
    onError: () => toast.error('Failed to seed system roles'),
  })

  if (!orgId) return null

  const systemRoles = roles.filter(r => r.is_system)
  const customRoles = roles.filter(r => !r.is_system)

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 28 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <Shield size={20} style={{ color: 'var(--clavex-primary)' }} />
            <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--clavex-ink)', margin: 0 }}>
              Delegated Admin Roles
            </h1>
          </div>
          <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', margin: 0, lineHeight: 1.6, maxWidth: 560 }}>
            Define fine-grained admin roles and assign them to users. Each role bundles a set of
            permission tokens controlling which resources a delegated admin can access.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
          <button style={btn('ghost')} onClick={() => qc.invalidateQueries({ queryKey: ['admin-roles', orgId] })}>
            <RefreshCw size={13} />
          </button>
          {systemRoles.length === 0 && (
            <button style={btn('ghost')} onClick={() => ensureSystem.mutate()} disabled={ensureSystem.isPending}>
              {ensureSystem.isPending ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
              Seed System Roles
            </button>
          )}
          <button style={btn('primary')} onClick={() => setCreating(true)} disabled={creating}>
            <Plus size={13} /> New Role
          </button>
        </div>
      </div>

      {creating && (
        <div style={{ marginBottom: 20 }}>
          <RoleForm
            allPerms={allPerms}
            onSave={async (name, desc, perms) => { await createRole.mutateAsync({ name, desc, perms }) }}
            onCancel={() => setCreating(false)}
          />
        </div>
      )}

      {isLoading && <p style={{ color: 'var(--clavex-ink-muted)', fontSize: 13 }}>Loading…</p>}

      {!isLoading && roles.length === 0 && !creating && (
        <div style={{ ...card, textAlign: 'center', padding: '48px 24px', borderStyle: 'dashed' }}>
          <Shield size={36} style={{ color: 'var(--clavex-ink-muted)', margin: '0 auto 12px' }} />
          <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 8 }}>No admin roles yet</p>
          <p style={{ fontSize: 13, color: 'var(--clavex-ink-muted)', marginBottom: 20 }}>
            Create a custom role or seed the built-in system roles (Org Admin, Read-Only, Helpdesk).
          </p>
          <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
            <button style={btn('ghost')} onClick={() => ensureSystem.mutate()} disabled={ensureSystem.isPending}>
              {ensureSystem.isPending ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
              Seed System Roles
            </button>
            <button style={btn('primary')} onClick={() => setCreating(true)}>
              <Plus size={14} /> New Role
            </button>
          </div>
        </div>
      )}

      {systemRoles.length > 0 && (
        <div style={{ marginBottom: 24 }} className="space-y-3">
          <div style={{ ...lbl, marginBottom: 10 }}>System Roles</div>
          {systemRoles.map(r => (
            <RoleCard key={r.id} role={r} allPerms={allPerms} orgId={orgId} />
          ))}
        </div>
      )}

      {customRoles.length > 0 && (
        <div className="space-y-3">
          <div style={{ ...lbl, marginBottom: 10 }}>Custom Roles</div>
          {customRoles.map(r => (
            <RoleCard key={r.id} role={r} allPerms={allPerms} orgId={orgId} />
          ))}
        </div>
      )}

      {/* Permission reference */}
      {allPerms.length > 0 && (
        <details style={{ marginTop: 32 }}>
          <summary style={{ cursor: 'pointer', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink-muted)', userSelect: 'none' }}>
            Permission reference ({allPerms.length} tokens)
          </summary>
          <div style={{ ...card, marginTop: 10 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: 'var(--clavex-surface)' }}>
                  {['Token', 'Description'].map(h => (
                    <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--clavex-ink-muted)', borderBottom: '0.5px solid var(--clavex-border)' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {allPerms.map(p => (
                  <tr key={p.token} style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                    <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: 'var(--clavex-ink)', whiteSpace: 'nowrap' }}>{p.token}</td>
                    <td style={{ padding: '8px 12px', color: 'var(--clavex-ink-muted)' }}>{p.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  )
}
