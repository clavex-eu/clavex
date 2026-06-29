import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, UserCheck, Users, Search, ShieldAlert, Tag, Upload, Download, CheckCircle2, XCircle, Laptop, MailCheck } from 'lucide-react'
import toast from 'react-hot-toast'
import api, { toArr } from '@/lib/api'
import { Badge, Button, Modal, Input, Select, PageHeader, EmptyState, Spinner } from '@/components/ui'

interface TrustedDevice {
  id: string
  display_name?: string
  last_seen_at: string
  created_at: string
}

interface User {
  id: string
  email: string
  first_name?: string
  last_name?: string
  is_active: boolean
  is_email_verified: boolean
  required_actions: string[]
  metadata?: Record<string, unknown>
  created_at: string
}
interface Role { id: string; name: string }
interface ImportError { row: number; email: string; reason: string }
interface ImportReport { total: number; created: number; skipped: number; errors: ImportError[] }
interface Props { orgId: string; breadcrumb?: React.ReactNode }

function UserAvatar({ email, firstName }: { email: string; firstName?: string }) {
  const letter = (firstName || email)[0].toUpperCase()
  const colors = ['#0F6E56', '#534AB7', '#185FA5', '#BA7517', '#D85A30']
  const idx = email.charCodeAt(0) % colors.length
  return (
    <div style={{
      width: 32, height: 32, borderRadius: '50%', flexShrink: 0,
      background: colors[idx] + '20',
      border: `0.5px solid ${colors[idx]}40`,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <span style={{ fontSize: 12, fontWeight: 700, color: colors[idx] }}>{letter}</span>
    </div>
  )
}

export default function UsersPage({ orgId, breadcrumb }: Props) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [showAssignRole, setShowAssignRole] = useState<User | null>(null)
  const [showRequiredActions, setShowRequiredActions] = useState<User | null>(null)
  const [showAttributes, setShowAttributes] = useState<User | null>(null)
  const [showDevices, setShowDevices] = useState<User | null>(null)
  const [attrPairs, setAttrPairs] = useState<{ key: string; value: string }[]>([])
  const [selectedActions, setSelectedActions] = useState<string[]>([])
  const [search, setSearch] = useState('')
  const [form, setForm] = useState({ email: '', first_name: '', last_name: '', password: '' })
  const [selectedRole, setSelectedRole] = useState('')
  const [showImport, setShowImport] = useState(false)
  const [importReport, setImportReport] = useState<ImportReport | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const openAttributes = (user: User) => {
    const pairs = Object.entries(user.metadata ?? {}).map(([key, value]) => ({
      key,
      value: String(value),
    }))
    setAttrPairs(pairs)
    setShowAttributes(user)
  }

  const addAttrPair = () => setAttrPairs((p) => [...p, { key: '', value: '' }])
  const removeAttrPair = (i: number) => setAttrPairs((p) => p.filter((_, idx) => idx !== i))
  const updateAttrPair = (i: number, field: 'key' | 'value', val: string) =>
    setAttrPairs((p) => p.map((pair, idx) => (idx === i ? { ...pair, [field]: val } : pair)))

  const { data: users = [], isLoading } = useQuery<User[]>({
    queryKey: ['users', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/users`).then((r) => toArr(r.data)),
    enabled: !!orgId,
  })
  const { data: roles = [] } = useQuery<Role[]>({
    queryKey: ['roles', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/roles`).then((r) => toArr(r.data)),
    enabled: !!orgId,
  })

  const createUser = useMutation({
    mutationFn: (body: typeof form) => api.post(`/organizations/${orgId}/users`, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['users', orgId] }); toast.success('User created'); setShowCreate(false); setForm({ email: '', first_name: '', last_name: '', password: '' }) },
    onError: () => toast.error('Failed to create user'),
  })
  const deleteUser = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/users/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['users', orgId] }); toast.success('User deleted') },
    onError: () => toast.error('Failed to delete user'),
  })
  const verifyEmail = useMutation({
    mutationFn: (id: string) => api.patch(`/organizations/${orgId}/users/${id}`, { is_email_verified: true }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['users', orgId] }); toast.success('Email marked as verified') },
    onError: () => toast.error('Failed to verify email'),
  })
  const importUsers = useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData()
      fd.append('file', file)
      return api.post(`/organizations/${orgId}/users/import`, fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['users', orgId] })
      setImportReport(res.data)
    },
    onError: () => toast.error('Import failed'),
  })
  const assignRole = useMutation({
    mutationFn: ({ userId, roleId }: { userId: string; roleId: string }) => api.put(`/organizations/${orgId}/roles/${roleId}/users/${userId}`),
    onSuccess: () => { toast.success('Role assigned'); setShowAssignRole(null); setSelectedRole('') },
    onError: () => toast.error('Failed to assign role'),
  })
  const setRequiredActions = useMutation({
    mutationFn: ({ userId, actions }: { userId: string; actions: string[] }) =>
      api.put(`/organizations/${orgId}/users/${userId}/required-actions`, { actions }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users', orgId] })
      toast.success('Required actions updated')
      setShowRequiredActions(null)
    },
    onError: () => toast.error('Failed to update required actions'),
  })

  const saveAttributes = useMutation({
    mutationFn: ({ userId, attrs }: { userId: string; attrs: Record<string, string> }) =>
      api.put(`/organizations/${orgId}/users/${userId}/attributes`, attrs),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users', orgId] })
      toast.success('Attributes saved')
      setShowAttributes(null)
    },
    onError: () => toast.error('Failed to save attributes'),
  })

  const openRequiredActions = (user: User) => {
    setSelectedActions(user.required_actions ?? [])
    setShowRequiredActions(user)
  }

  const toggleAction = (action: string) => {
    setSelectedActions((prev) =>
      prev.includes(action) ? prev.filter((a) => a !== action) : [...prev, action]
    )
  }

  const ALL_ACTIONS = [
    { value: 'VERIFY_EMAIL',    label: 'Verify email' },
    { value: 'UPDATE_PASSWORD', label: 'Update password' },
    { value: 'CONFIGURE_TOTP',  label: 'Configure MFA (TOTP)' },
  ]

  const { data: trustedDevices = [] } = useQuery<TrustedDevice[]>({
    queryKey: ['trusted-devices', orgId, showDevices?.id],
    queryFn: () => api.get(`/organizations/${orgId}/users/${showDevices!.id}/trusted-devices`).then(r => toArr<TrustedDevice>(r.data)),
    enabled: !!showDevices,
  })

  const revokeDevice = useMutation({
    mutationFn: (deviceId: string) =>
      api.delete(`/organizations/${orgId}/users/${showDevices!.id}/trusted-devices/${deviceId}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['trusted-devices', orgId, showDevices?.id] }); toast.success('Device revoked') },
    onError: () => toast.error('Failed to revoke device'),
  })

  const revokeAllDevices = useMutation({
    mutationFn: () =>
      api.delete(`/organizations/${orgId}/users/${showDevices!.id}/trusted-devices`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['trusted-devices', orgId, showDevices?.id] }); toast.success('All devices revoked') },
    onError: () => toast.error('Failed to revoke devices'),
  })

  const filtered = users.filter((u) => !search || u.email.toLowerCase().includes(search.toLowerCase()) || `${u.first_name ?? ''} ${u.last_name ?? ''}`.toLowerCase().includes(search.toLowerCase()))

  return (
    <div>
      {breadcrumb}
      <PageHeader
        title="Users"
        subtitle={`${users.length} member${users.length !== 1 ? 's' : ''}`}
        action={
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => setShowImport(true)}>
              <Upload className="h-4 w-4" /> Import
            </Button>
            <Button onClick={() => setShowCreate(true)}>
              <Plus className="h-4 w-4" /> New user
            </Button>
          </div>
        }
      />

      {users.length > 0 && (
        <div className="mb-4">
          <Input icon={<Search className="h-4 w-4" />} placeholder="Search by name or email…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      )}

      {isLoading ? <Spinner /> : filtered.length === 0 ? (
        <div style={{ background: 'white', border: '0.5px solid var(--clavex-border)', borderRadius: 'var(--clavex-radius-lg)' }}>
          <EmptyState icon={Users} title={users.length === 0 ? 'No users yet' : 'No results'} message={users.length === 0 ? 'Add the first user to this organization' : 'Try a different search'} />
        </div>
      ) : (
        <div style={{ background: 'white', border: '0.5px solid var(--clavex-border)', borderRadius: 'var(--clavex-radius-lg)', overflow: 'hidden' }}>
          {/* Table header */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 140px 80px 160px',
            padding: '8px 20px',
            borderBottom: '0.5px solid var(--clavex-surface)',
          }}>
            {['User', 'Required Actions', 'Status', ''].map((h) => (
              <span key={h} style={{ fontSize: 10, fontWeight: 700, letterSpacing: '1.5px', color: 'var(--clavex-neutral)', textTransform: 'uppercase' }}>{h}</span>
            ))}
          </div>

          {filtered.map((user, i) => {
            const displayName = [user.first_name, user.last_name].filter(Boolean).join(' ') || null
            const pendingActions = user.required_actions ?? []
            return (
              <div
                key={user.id}
                style={{
                  display: 'grid', gridTemplateColumns: '1fr 140px 80px 160px',
                  padding: '12px 20px',
                  borderBottom: i < filtered.length - 1 ? '0.5px solid var(--clavex-surface)' : 'none',
                  transition: 'background 100ms',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--clavex-surface)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
              >
                {/* User col */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                  <UserAvatar email={user.email} firstName={user.first_name} />
                  <div style={{ minWidth: 0 }}>
                    {displayName && <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', fontSize: 13, lineHeight: 1.2 }}>{displayName}</p>}
                    <div className="flex items-center gap-1.5">
                      <p style={{ fontSize: displayName ? 11 : 13, color: displayName ? 'var(--clavex-neutral)' : 'var(--clavex-ink)', fontWeight: displayName ? 400 : 600 }} className="truncate">{user.email}</p>
                      {user.is_email_verified
                        ? <CheckCircle2 style={{ width: 11, height: 11, flexShrink: 0, color: 'var(--clavex-primary)' }} />
                        : <XCircle style={{ width: 11, height: 11, flexShrink: 0, color: 'var(--clavex-neutral)' }} />}
                    </div>
                  </div>
                </div>

                {/* Required actions col */}
                <div>
                  {pendingActions.length === 0 ? (
                    <span style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>—</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {pendingActions.map((a) => (
                        <Badge key={a} variant="yellow" className="text-xs">
                          {a === 'VERIFY_EMAIL' ? 'Email' : a === 'UPDATE_PASSWORD' ? 'Reset pw' : 'TOTP'}
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>

                {/* Status col */}
                <Badge variant={user.is_active ? 'green' : 'gray'}>
                  {user.is_active ? 'Active' : 'Inactive'}
                </Badge>

                {/* Actions col */}
                <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                  <Button variant="ghost" size="xs" onClick={() => openAttributes(user)} title="User attributes">
                    <Tag className="h-4 w-4" style={{ color: 'var(--clavex-700)' }} />
                  </Button>
                  {!user.is_email_verified && (
                    <Button
                      variant="ghost" size="xs"
                      onClick={() => { if (confirm(`Mark ${user.email} email as verified?`)) verifyEmail.mutate(user.id) }}
                      title="Mark email as verified"
                    >
                      <MailCheck className="h-4 w-4" style={{ color: 'var(--clavex-700)' }} />
                    </Button>
                  )}
                  <Button variant="ghost" size="xs" onClick={() => openRequiredActions(user)} title="Required actions">
                    <ShieldAlert className="h-4 w-4" style={{ color: pendingActions.length > 0 ? 'var(--clavex-warning)' : 'var(--clavex-700)' }} />
                  </Button>
                  <Button variant="ghost" size="xs" onClick={() => setShowAssignRole(user)} title="Assign role">
                    <UserCheck className="h-4 w-4" style={{ color: 'var(--clavex-700)' }} />
                  </Button>
                  <Button variant="ghost" size="xs" onClick={() => setShowDevices(user)} title="Trusted devices">
                    <Laptop className="h-4 w-4" style={{ color: 'var(--clavex-700)' }} />
                  </Button>
                  <Button variant="ghost" size="xs" onClick={() => { if (confirm(`Delete ${user.email}?`)) deleteUser.mutate(user.id) }} title="Delete">
                    <Trash2 className="h-4 w-4" style={{ color: 'var(--clavex-danger)' }} />
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      <Modal open={showCreate} title="Create user" description="Add a new user to this organization" onClose={() => setShowCreate(false)}>
        <form onSubmit={(e) => { e.preventDefault(); createUser.mutate(form) }} className="space-y-4">
          <Input label="Email address" type="email" value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} required autoFocus />
          <div className="grid grid-cols-2 gap-3">
            <Input label="First name" value={form.first_name} onChange={(e) => setForm((f) => ({ ...f, first_name: e.target.value }))} />
            <Input label="Last name" value={form.last_name} onChange={(e) => setForm((f) => ({ ...f, last_name: e.target.value }))} />
          </div>
          <Input label="Initial password" type="password" value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} required hint="User can change this after first login" />
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="secondary" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button type="submit" loading={createUser.isPending}>Create user</Button>
          </div>
        </form>
      </Modal>

      <Modal open={!!showAssignRole} title="Assign role" description={`Assign a role to ${showAssignRole?.email}`} onClose={() => setShowAssignRole(null)}>
        <div className="space-y-4">
          <Select label="Role" value={selectedRole} onChange={(e) => setSelectedRole(e.target.value)}>
            <option value="">Select a role…</option>
            {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </Select>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setShowAssignRole(null)}>Cancel</Button>
            <Button disabled={!selectedRole} loading={assignRole.isPending} onClick={() => assignRole.mutate({ userId: showAssignRole!.id, roleId: selectedRole })}>
              Assign
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        open={!!showRequiredActions}
        title="Required Actions"
        description={`Actions the user must complete at next login — ${showRequiredActions?.email}`}
        onClose={() => setShowRequiredActions(null)}
      >
        <div className="space-y-3">
          {ALL_ACTIONS.map(({ value, label }) => (
            <label
              key={value}
              className="flex items-center gap-3 cursor-pointer rounded-lg px-3 py-2.5 transition-colors"
              style={{
                border: '0.5px solid var(--clavex-border)',
                background: selectedActions.includes(value) ? 'rgba(29,158,117,0.06)' : 'var(--clavex-surface)',
                borderColor: selectedActions.includes(value) ? 'var(--clavex-primary)' : 'var(--clavex-border)',
              }}
            >
              <input
                type="checkbox"
                checked={selectedActions.includes(value)}
                onChange={() => toggleAction(value)}
                style={{ accentColor: 'var(--clavex-primary)' }}
              />
              <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--clavex-ink)' }}>{label}</span>
            </label>
          ))}
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="secondary" onClick={() => setShowRequiredActions(null)}>Cancel</Button>
            <Button
              loading={setRequiredActions.isPending}
              onClick={() => setRequiredActions.mutate({ userId: showRequiredActions!.id, actions: selectedActions })}
            >
              Save
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        open={!!showAttributes}
        title="User Attributes"
        description={`Custom key-value metadata for ${showAttributes?.email}`}
        onClose={() => setShowAttributes(null)}
        size="md"
      >
        <div className="space-y-3">
          {attrPairs.map((pair, i) => (
            <div key={i} className="flex items-center gap-2">
              <input
                placeholder="key"
                value={pair.key}
                onChange={(e) => updateAttrPair(i, 'key', e.target.value)}
                className="flex-1 rounded-lg border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
              />
              <input
                placeholder="value"
                value={pair.value}
                onChange={(e) => updateAttrPair(i, 'value', e.target.value)}
                className="flex-1 rounded-lg border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
              />
              <button
                onClick={() => removeAttrPair(i)}
                className="p-1.5 rounded hover:bg-red-50 text-gray-400 hover:text-red-500 transition-colors"
              >
                ×
              </button>
            </div>
          ))}
          <button
            onClick={addAttrPair}
            className="text-xs text-[var(--clavex-primary)] hover:underline flex items-center gap-1"
          >
            <Plus className="h-3 w-3" /> Add attribute
          </button>
          <div className="flex justify-end gap-2 pt-2 border-t border-gray-100">
            <Button variant="secondary" onClick={() => setShowAttributes(null)}>Cancel</Button>
            <Button
              loading={saveAttributes.isPending}
              onClick={() => {
                const attrs: Record<string, string> = {}
                attrPairs.filter((p) => p.key.trim()).forEach((p) => { attrs[p.key.trim()] = p.value })
                saveAttributes.mutate({ userId: showAttributes!.id, attrs })
              }}
            >
              Save attributes
            </Button>
          </div>
        </div>
      </Modal>

      {/* ── Bulk import modal ── */}
      <Modal
        open={showImport}
        title={importReport ? 'Import complete' : 'Import users'}
        description={importReport ? `${importReport.created} created, ${importReport.skipped} skipped` : 'Upload a CSV or JSON file to bulk-create users.'}
        onClose={() => { setShowImport(false); setImportReport(null) }}
        size="md"
      >
        {importReport ? (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'Total', value: importReport.total, color: 'var(--clavex-ink)' },
                { label: 'Created', value: importReport.created, color: '#0F6E56' },
                { label: 'Skipped', value: importReport.skipped, color: 'var(--clavex-neutral)' },
              ].map(({ label, value, color }) => (
                <div key={label} style={{ background: 'var(--clavex-surface)', borderRadius: 8, padding: '12px 16px', textAlign: 'center' }}>
                  <p style={{ fontSize: 22, fontWeight: 700, color }}>{value}</p>
                  <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '1px' }}>{label}</p>
                </div>
              ))}
            </div>

            {importReport.errors.length > 0 && (
              <div>
                <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-neutral)', marginBottom: 6 }}>
                  {importReport.errors.length} issue{importReport.errors.length !== 1 ? 's' : ''}
                </p>
                <div style={{ maxHeight: 180, overflowY: 'auto', borderRadius: 8, border: '0.5px solid var(--clavex-border)' }}>
                  {importReport.errors.map((e, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '8px 12px', borderBottom: i < importReport.errors.length - 1 ? '0.5px solid var(--clavex-surface)' : 'none' }}>
                      {e.reason === 'user already exists' ? (
                        <CheckCircle2 className="h-3.5 w-3.5 mt-0.5 shrink-0" style={{ color: 'var(--clavex-neutral)' }} />
                      ) : (
                        <XCircle className="h-3.5 w-3.5 mt-0.5 shrink-0" style={{ color: 'var(--clavex-danger)' }} />
                      )}
                      <div style={{ minWidth: 0, flex: 1, fontSize: 12 }}>
                        <span style={{ fontWeight: 600 }}>{e.email || `Row ${e.row}`}</span>
                        <span style={{ color: 'var(--clavex-neutral)' }}> — {e.reason}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex justify-end">
              <Button onClick={() => { setShowImport(false); setImportReport(null) }}>Done</Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>
              CSV columns: <code style={{ background: 'var(--clavex-surface)', padding: '0 4px', borderRadius: 4 }}>email</code>, <code style={{ background: 'var(--clavex-surface)', padding: '0 4px', borderRadius: 4 }}>first_name</code>, <code style={{ background: 'var(--clavex-surface)', padding: '0 4px', borderRadius: 4 }}>last_name</code>, <code style={{ background: 'var(--clavex-surface)', padding: '0 4px', borderRadius: 4 }}>password</code>, <code style={{ background: 'var(--clavex-surface)', padding: '0 4px', borderRadius: 4 }}>roles</code> (comma-separated)
            </p>

            <button
              onClick={() => {
                const csv = 'email,first_name,last_name,password,roles\nalice@example.com,Alice,Smith,secret123,member\nbob@example.com,Bob,Jones,,admin'
                const blob = new Blob([csv], { type: 'text/csv' })
                const a = document.createElement('a')
                a.href = URL.createObjectURL(blob)
                a.download = 'import-template.csv'
                a.click()
              }}
              className="flex items-center gap-1.5 text-xs text-[var(--clavex-primary)] hover:underline"
            >
              <Download className="h-3 w-3" /> Download template
            </button>

            <div
              onClick={() => fileInputRef.current?.click()}
              style={{
                border: '2px dashed var(--clavex-border)',
                borderRadius: 12,
                padding: '32px 24px',
                textAlign: 'center',
                cursor: 'pointer',
                background: 'var(--clavex-surface)',
                transition: 'border-color 150ms',
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--clavex-primary)' }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--clavex-border)' }}
            >
              {importUsers.isPending ? (
                <Spinner />
              ) : (
                <>
                  <Upload className="h-6 w-6 mx-auto mb-2" style={{ color: 'var(--clavex-neutral)' }} />
                  <p style={{ fontSize: 13, color: 'var(--clavex-ink)', fontWeight: 600 }}>Click to upload</p>
                  <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 2 }}>CSV or JSON · max 10 MB</p>
                </>
              )}
            </div>

            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,.json"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) importUsers.mutate(f)
                e.target.value = ''
              }}
            />

            <div className="flex justify-end">
              <Button variant="secondary" onClick={() => setShowImport(false)}>Cancel</Button>
            </div>
          </div>
        )}
      </Modal>

      {/* ── Trusted devices modal ── */}
      <Modal
        open={!!showDevices}
        title="Trusted Devices"
        description={`Devices trusted by ${showDevices?.email}`}
        onClose={() => setShowDevices(null)}
        size="md"
      >
        {trustedDevices.length === 0 ? (
          <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', textAlign: 'center', padding: '24px 0' }}>
            No trusted devices registered.
          </p>
        ) : (
          <div className="space-y-2 mb-4">
            {trustedDevices.map(d => (
              <div key={d.id} className="flex items-center gap-3 rounded-lg border border-gray-200 px-4 py-3">
                <Laptop className="h-4 w-4 text-gray-400 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-800 truncate">{d.display_name ?? 'Unknown device'}</p>
                  <p className="text-xs text-gray-400">
                    Last seen {new Date(d.last_seen_at).toLocaleString()} · Added {new Date(d.created_at).toLocaleDateString()}
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="xs"
                  onClick={() => revokeDevice.mutate(d.id)}
                  title="Revoke device"
                >
                  <Trash2 className="h-4 w-4" style={{ color: 'var(--clavex-danger)' }} />
                </Button>
              </div>
            ))}
          </div>
        )}
        <div className="flex justify-between">
          <Button
            variant="secondary"
            size="sm"
            disabled={trustedDevices.length === 0 || revokeAllDevices.isPending}
            onClick={() => { if (confirm('Revoke ALL trusted devices for this user?')) revokeAllDevices.mutate() }}
          >
            Revoke all
          </Button>
          <Button variant="secondary" onClick={() => setShowDevices(null)}>Close</Button>
        </div>
      </Modal>
    </div>
  )
}

