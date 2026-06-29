import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Copy, RefreshCw, Settings, KeyRound, GitMerge } from 'lucide-react'
import toast from 'react-hot-toast'
import api, { toArr } from '@/lib/api'
import { Badge, Button, Modal, Input, PageHeader, EmptyState, Spinner } from '@/components/ui'

interface OIDCClient {
  client_id: string
  name: string
  token_endpoint_auth_method: string
  grant_types: string[]
  redirect_uris: string[]
  post_logout_redirect_uris: string[]
  is_active: boolean
  mfa_required: boolean
  keycloak_compat: boolean
  enabled_login_providers: string[]
  created_at: string
}

interface ProtocolMapper {
  id: string
  client_id: string
  name: string
  mapper_type: 'user_property' | 'user_attribute' | 'hardcoded' | 'role_list' | 'group_membership'
  claim_name: string
  claim_value?: string
  attribute_name?: string
  add_to_access_token: boolean
  add_to_id_token: boolean
  add_to_userinfo: boolean
}

interface ClientBranding {
  client_id: string
  company_name?: string
  logo_url?: string
  primary_color?: string
  background_color?: string
}

interface Props {
  orgId: string
  breadcrumb?: React.ReactNode
}

function ClientBrandingTab({ orgId, clientId }: { orgId: string; clientId: string }) {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery<ClientBranding | null>({
    queryKey: ['client-branding', orgId, clientId],
    queryFn: () =>
      api.get(`/organizations/${orgId}/clients/${clientId}/branding`)
        .then(r => r.data)
        .catch(e => e?.response?.status === 404 ? null : Promise.reject(e)),
  })
  const [form, setForm] = useState({ company_name: '', logo_url: '', primary_color: '', background_color: '' })
  const [initialized, setInitialized] = useState(false)

  if (!initialized && !isLoading) {
    setForm({
      company_name: data?.company_name ?? '',
      logo_url: data?.logo_url ?? '',
      primary_color: data?.primary_color ?? '',
      background_color: data?.background_color ?? '',
    })
    setInitialized(true)
  }

  const save = useMutation({
    mutationFn: () => api.put(`/organizations/${orgId}/clients/${clientId}/branding`, form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['client-branding', orgId, clientId] }); toast.success('Branding saved') },
    onError: () => toast.error('Failed to save branding'),
  })

  const remove = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/clients/${clientId}/branding`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['client-branding', orgId, clientId] })
      setForm({ company_name: '', logo_url: '', primary_color: '', background_color: '' })
      setInitialized(false)
      toast.success('Branding reset to org defaults')
    },
    onError: () => toast.error('Failed to reset branding'),
  })

  if (isLoading) return <p className="text-sm text-gray-400 py-4">Loading…</p>

  const set = (k: keyof typeof form, v: string) => setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="space-y-4">
      <p className="text-xs text-gray-400 mb-2">
        Override branding for this client's login page. Leave empty to inherit from org defaults.
      </p>
      {([
        ['company_name', 'Company name', 'text', 'Acme Corp'],
        ['logo_url',     'Logo URL',     'url',  'https://…/logo.png'],
        ['primary_color',    'Primary colour',    'text', '#5DCAA5'],
        ['background_color', 'Background colour', 'text', '#0D1B2A'],
      ] as const).map(([key, label, type, placeholder]) => (
        <div key={key}>
          <label className="block text-xs font-medium text-gray-600 mb-1">{label}</label>
          <div className="flex items-center gap-2">
            {(key === 'primary_color' || key === 'background_color') && form[key] && (
              <span
                className="inline-block h-5 w-5 rounded border border-gray-300 shrink-0"
                style={{ background: form[key] }}
              />
            )}
            <input
              type={type}
              className="flex-1 border rounded-lg px-3 py-1.5 text-sm"
              placeholder={placeholder}
              value={form[key]}
              onChange={e => set(key, e.target.value)}
            />
          </div>
        </div>
      ))}
      <div className="flex justify-between pt-2">
        <Button
          variant="secondary"
          size="sm"
          disabled={!data || remove.isPending}
          onClick={() => { if (confirm('Reset to org branding defaults?')) remove.mutate() }}
        >
          Reset to defaults
        </Button>
        <Button size="sm" loading={save.isPending} onClick={() => save.mutate()}>
          Save branding
        </Button>
      </div>
    </div>
  )
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', gap: 12 }}>
      <span style={{ fontSize: 13, color: 'var(--clavex-ink)', fontWeight: 500 }}>{label}</span>
      <button
        type="button"
        onClick={() => onChange(!checked)}
        style={{
          width: 36, height: 20, borderRadius: 10, flexShrink: 0, border: 'none', cursor: 'pointer',
          background: checked ? 'var(--clavex-primary)' : 'var(--clavex-border-subtle)',
          position: 'relative', transition: 'background 150ms ease',
        }}
      >
        <span style={{
          position: 'absolute', top: 3, left: checked ? 19 : 3,
          width: 14, height: 14, borderRadius: '50%', background: 'white',
          transition: 'left 150ms ease',
          boxShadow: '0 1px 3px rgba(0,0,0,0.15)',
        }} />
      </button>
    </label>
  )
}

const MAPPER_TYPE_LABELS: Record<string, string> = {
  user_property:    'User property',
  user_attribute:   'User attribute',
  hardcoded:        'Hardcoded claim',
  role_list:        'Role list',
  group_membership: 'Group membership',
}

function MappersTab({ orgId, clientId }: { orgId: string; clientId: string }) {
  const qc = useQueryClient()
  const [showAdd, setShowAdd] = useState(false)
  const [mapperForm, setMapperForm] = useState({
    name: '', mapper_type: 'user_property', claim_name: '', claim_value: '', attribute_name: '',
    add_to_access_token: true, add_to_id_token: true, add_to_userinfo: true,
  })

  const { data: mappers = [], isLoading } = useQuery<ProtocolMapper[]>({
    queryKey: ['mappers', clientId],
    queryFn: () => api.get(`/organizations/${orgId}/clients/${clientId}/mappers`).then((r) => r.data),
  })

  const createMapper = useMutation({
    mutationFn: (body: typeof mapperForm) =>
      api.post(`/organizations/${orgId}/clients/${clientId}/mappers`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['mappers', clientId] })
      toast.success('Mapper added')
      setShowAdd(false)
      setMapperForm({ name: '', mapper_type: 'user_property', claim_name: '', claim_value: '', attribute_name: '', add_to_access_token: true, add_to_id_token: true, add_to_userinfo: true })
    },
    onError: () => toast.error('Failed to add mapper'),
  })

  const deleteMapper = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/clients/${clientId}/mappers/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['mappers', clientId] }); toast.success('Mapper deleted') },
    onError: () => toast.error('Failed to delete mapper'),
  })

  const needsAttributeName = mapperForm.mapper_type === 'user_property' || mapperForm.mapper_type === 'user_attribute'
  const needsClaimValue = mapperForm.mapper_type === 'hardcoded'

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>
          Map user attributes and properties into token claims.
        </p>
        <Button size="sm" onClick={() => setShowAdd(true)}>
          <Plus className="h-3.5 w-3.5 mr-1" /> Add mapper
        </Button>
      </div>

      {isLoading ? (
        <Spinner />
      ) : mappers.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--clavex-ink-muted)', fontSize: 13 }}>
          <GitMerge className="h-6 w-6 mx-auto mb-2 opacity-30" />
          No protocol mappers configured.
        </div>
      ) : (
        <div className="space-y-1.5">
          {mappers.map((m) => (
            <div
              key={m.id}
              className="flex items-center justify-between rounded-lg px-3 py-2.5"
              style={{ background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)' }}
            >
              <div>
                <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)' }}>{m.name}</p>
                <p style={{ fontSize: 11, color: 'var(--clavex-ink-muted)' }}>
                  {MAPPER_TYPE_LABELS[m.mapper_type]} → <code style={{ fontFamily: 'monospace' }}>{m.claim_name}</code>
                  {m.attribute_name && <> · <em>{m.attribute_name}</em></>}
                  {m.claim_value && <> · "{m.claim_value}"</>}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex gap-1">
                  {m.add_to_access_token && <Badge variant="purple" className="text-xs">AT</Badge>}
                  {m.add_to_id_token && <Badge variant="blue" className="text-xs">ID</Badge>}
                  {m.add_to_userinfo && <Badge variant="green" className="text-xs">UI</Badge>}
                </div>
                <Button
                  variant="ghost" size="xs"
                  onClick={() => { if (confirm(`Delete mapper ${m.name}?`)) deleteMapper.mutate(m.id) }}
                >
                  <Trash2 className="h-3.5 w-3.5" style={{ color: 'var(--clavex-danger)' }} />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={showAdd} title="Add protocol mapper" onClose={() => setShowAdd(false)}>
        <form
          onSubmit={(e) => { e.preventDefault(); createMapper.mutate(mapperForm) }}
          className="space-y-4"
        >
          <Input label="Mapper name" value={mapperForm.name} onChange={(e) => setMapperForm((f) => ({ ...f, name: e.target.value }))} required autoFocus />
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 4 }}>Mapper type</label>
            <select
              className="input-base"
              value={mapperForm.mapper_type}
              onChange={(e) => setMapperForm((f) => ({ ...f, mapper_type: e.target.value }))}
            >
              {Object.entries(MAPPER_TYPE_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          <Input
            label="Claim name (in token)"
            value={mapperForm.claim_name}
            onChange={(e) => setMapperForm((f) => ({ ...f, claim_name: e.target.value }))}
            required
            hint='E.g. "department" or "custom_role"'
          />
          {needsAttributeName && (
            <Input
              label={mapperForm.mapper_type === 'user_property' ? 'Property' : 'Metadata key'}
              value={mapperForm.attribute_name}
              onChange={(e) => setMapperForm((f) => ({ ...f, attribute_name: e.target.value }))}
              hint={mapperForm.mapper_type === 'user_property' ? 'email · first_name · last_name · sub' : 'Key in user metadata JSON'}
            />
          )}
          {needsClaimValue && (
            <Input
              label="Hardcoded value"
              value={mapperForm.claim_value}
              onChange={(e) => setMapperForm((f) => ({ ...f, claim_value: e.target.value }))}
            />
          )}
          <div style={{ background: 'var(--clavex-surface)', borderRadius: 'var(--clavex-radius-md)', padding: '12px 14px' }}>
            <p style={{ fontSize: 11, fontWeight: 700, color: 'var(--clavex-ink-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 8 }}>Include in</p>
            <div className="space-y-2">
              {([
                ['add_to_access_token', 'Access Token'],
                ['add_to_id_token', 'ID Token'],
                ['add_to_userinfo', 'UserInfo endpoint'],
              ] as const).map(([key, label]) => (
                <label key={key} className="flex items-center gap-2 cursor-pointer text-sm" style={{ color: 'var(--clavex-ink-muted)' }}>
                  <input
                    type="checkbox"
                    checked={mapperForm[key]}
                    onChange={(e) => setMapperForm((f) => ({ ...f, [key]: e.target.checked }))}
                    style={{ accentColor: 'var(--clavex-primary)' }}
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" type="button" onClick={() => setShowAdd(false)}>Cancel</Button>
            <Button type="submit" loading={createMapper.isPending}>Add mapper</Button>
          </div>
        </form>
      </Modal>
    </div>
  )
}

export default function ClientsPage({ orgId, breadcrumb }: Props) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editClient, setEditClient] = useState<OIDCClient | null>(null)
  const [editTab, setEditTab] = useState<'policies' | 'uris' | 'mappers' | 'branding'>('policies')
  const [newSecret, setNewSecret] = useState<{ clientId: string; secret: string } | null>(null)
  const [form, setForm] = useState({ client_id: '', name: '', is_public: true, redirect_uris: '' })
  const [editForm, setEditForm] = useState({ mfa_required: false, keycloak_compat: false, is_active: true, enabled_login_providers: [] as string[] })
  const [uriForm, setUriForm] = useState({ redirect_uris: '', post_logout_redirect_uris: '' })

  const { data: clients = [], isLoading } = useQuery<OIDCClient[]>({
    queryKey: ['clients', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/clients`).then((r) => toArr(r.data)),
    enabled: !!orgId,
  })

  const createClient = useMutation({
    mutationFn: (body: { client_id?: string; name: string; is_public: boolean; redirect_uris: string[] }) =>
      api.post(`/organizations/${orgId}/clients`, body),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['clients', orgId] })
      if (res.data.client_secret) {
        setNewSecret({ clientId: res.data.client.client_id, secret: res.data.client_secret })
      } else {
        toast.success('Client created'); setShowCreate(false); resetForm()
      }
    },
    onError: () => toast.error('Failed to create client'),
  })

  const updateClient = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      api.patch(`/organizations/${orgId}/clients/${id}`, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['clients', orgId] }); toast.success('Client updated'); setEditClient(null) },
    onError: () => toast.error('Failed to update client'),
  })

  const deleteClient = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/clients/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['clients', orgId] }); toast.success('Client deleted') },
    onError: () => toast.error('Failed to delete client'),
  })

  const rotateSecret = useMutation({
    mutationFn: (id: string) => api.post(`/organizations/${orgId}/clients/${id}/secret`),
    onSuccess: (res, id) => setNewSecret({ clientId: id, secret: res.data.client_secret }),
    onError: () => toast.error('Failed to rotate secret'),
  })

  function resetForm() { setForm({ client_id: '', name: '', is_public: true, redirect_uris: '' }) }

  function openEdit(c: OIDCClient) {
    setEditClient(c)
    setEditTab('policies')
    setEditForm({ mfa_required: c.mfa_required, keycloak_compat: c.keycloak_compat, is_active: c.is_active, enabled_login_providers: c.enabled_login_providers ?? [] })
    setUriForm({
      redirect_uris: (c.redirect_uris ?? []).join('\n'),
      post_logout_redirect_uris: (c.post_logout_redirect_uris ?? []).join('\n'),
    })
  }

  const isPublic = (c: OIDCClient) => c.token_endpoint_auth_method === 'none'

  return (
    <div>
      {breadcrumb}
      <PageHeader
        title="OIDC Clients"
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" /> New client
          </Button>
        }
      />

      {isLoading ? <Spinner /> : clients.length === 0 ? (
        <div style={{ background: 'white', border: '0.5px solid var(--clavex-border)', borderRadius: 'var(--clavex-radius-lg)' }}>
          <EmptyState icon={KeyRound} title="No clients yet" message="Register an OIDC client to start issuing tokens" />
        </div>
      ) : (
        <div style={{ background: 'white', border: '0.5px solid var(--clavex-border)', borderRadius: 'var(--clavex-radius-lg)', overflow: 'hidden' }}>
          {/* Table header */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 80px 80px 80px 100px',
            padding: '10px 20px',
            borderBottom: '0.5px solid var(--clavex-surface)',
            background: 'var(--clavex-surface)',
          }}>
            {['Client', 'Type', 'MFA', 'Keycloak', ''].map((h) => (
              <span key={h} style={{ fontSize: 10, fontWeight: 700, letterSpacing: '1.5px', color: 'var(--clavex-neutral)', textTransform: 'uppercase' }}>{h}</span>
            ))}
          </div>

          {clients.map((c, i) => (
            <div
              key={c.client_id}
              style={{
                display: 'grid', gridTemplateColumns: '1fr 80px 80px 80px 100px',
                alignItems: 'center',
                padding: '12px 20px',
                borderBottom: i < clients.length - 1 ? '0.5px solid var(--clavex-surface)' : 'none',
                transition: 'background 100ms',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--clavex-surface)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
            >
              {/* Client col */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                <div style={{
                  width: 32, height: 32, borderRadius: 8, flexShrink: 0,
                  background: 'var(--clavex-50)', border: '0.5px solid var(--clavex-border)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <KeyRound style={{ width: 14, height: 14, color: 'var(--clavex-700)' }} />
                </div>
                <div style={{ minWidth: 0 }}>
                  <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', fontSize: 13, lineHeight: 1.2 }}>{c.name}</p>
                  <p style={{ fontSize: 10, color: 'var(--clavex-neutral)', fontFamily: 'monospace', marginTop: 1 }} className="truncate">{c.client_id}</p>
                </div>
              </div>

              {/* Type col */}
              <Badge variant={isPublic(c) ? 'blue' : 'yellow'}>
                {isPublic(c) ? 'Public' : 'Confidential'}
              </Badge>

              {/* MFA col */}
              <Badge variant={c.mfa_required ? 'purple' : 'gray'}>
                {c.mfa_required ? 'Required' : 'Optional'}
              </Badge>

              {/* Keycloak compat col */}
              <Badge variant={c.keycloak_compat ? 'green' : 'gray'}>
                {c.keycloak_compat ? 'On' : 'Off'}
              </Badge>

              {/* Actions col */}
              <div style={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
                <Button variant="ghost" size="xs" onClick={() => openEdit(c)} title="Settings">
                  <Settings style={{ width: 14, height: 14, color: 'var(--clavex-700)' }} />
                </Button>
                {!isPublic(c) && (
                  <Button variant="ghost" size="xs" onClick={() => rotateSecret.mutate(c.client_id)} title="Rotate secret">
                    <RefreshCw style={{ width: 14, height: 14, color: 'var(--clavex-neutral)' }} />
                  </Button>
                )}
                <Button variant="ghost" size="xs" onClick={() => { if (confirm(`Delete client ${c.name}?`)) deleteClient.mutate(c.client_id) }}>
                  <Trash2 style={{ width: 14, height: 14, color: 'var(--clavex-danger)' }} />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create client modal */}
      <Modal open={showCreate} title="Register OIDC client" onClose={() => { setShowCreate(false); resetForm() }}>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            createClient.mutate({
              client_id: form.client_id.trim() || undefined,
              name: form.name,
              is_public: form.is_public,
              redirect_uris: form.redirect_uris.split('\n').map((u) => u.trim()).filter(Boolean),
            })
          }}
          className="space-y-4"
        >
          <Input label="Client name" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} required autoFocus />
          <Input
            label="Client ID"
            value={form.client_id}
            onChange={(e) => setForm((f) => ({ ...f, client_id: e.target.value }))}
            placeholder="auto-generated if left empty"
            style={{ fontFamily: 'monospace' }}
          />
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 8 }}>Type</label>
            <div className="flex gap-4">
              {[
                { value: true, label: 'Public (SPA / mobile — PKCE)' },
                { value: false, label: 'Confidential (server / M2M)' },
              ].map(({ value, label }) => (
                <label key={String(value)} className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--clavex-ink-muted)' }}>
                  <input
                    type="radio"
                    name="client_type"
                    checked={form.is_public === value}
                    onChange={() => setForm((f) => ({ ...f, is_public: value }))}
                    style={{ accentColor: 'var(--clavex-primary)' }}
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 4 }}>
              Redirect URIs <span style={{ fontWeight: 400, color: 'var(--clavex-neutral)' }}>(one per line)</span>
            </label>
            <textarea
              value={form.redirect_uris}
              onChange={(e) => setForm((f) => ({ ...f, redirect_uris: e.target.value }))}
              rows={3}
              className="input-base"
              style={{ fontFamily: 'monospace', resize: 'none' }}
              placeholder="https://app.example.com/callback"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" type="button" onClick={() => { setShowCreate(false); resetForm() }}>Cancel</Button>
            <Button type="submit" loading={createClient.isPending}>Create</Button>
          </div>
        </form>
      </Modal>

      {/* Edit client modal (settings / policies / mappers) */}
      <Modal open={!!editClient} title={`Settings — ${editClient?.name}`} onClose={() => setEditClient(null)} size="xl">
        {/* Tabs */}
        <div style={{ display: 'flex', gap: 2, marginBottom: 16, borderBottom: '0.5px solid var(--clavex-border)', paddingBottom: 0 }}>
          {(['policies', 'uris', 'mappers', 'branding'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setEditTab(tab)}
              style={{
                padding: '6px 14px',
                fontSize: 13,
                fontWeight: editTab === tab ? 600 : 400,
                color: editTab === tab ? 'var(--clavex-primary)' : 'var(--clavex-ink-muted)',
                background: 'none',
                border: 'none',
                borderBottom: editTab === tab ? '2px solid var(--clavex-primary)' : '2px solid transparent',
                cursor: 'pointer',
                marginBottom: -1,
              }}
            >
              {tab === 'mappers' ? 'Protocol Mappers' : tab === 'branding' ? 'Branding' : tab === 'uris' ? 'Redirect URIs' : 'Policies'}
            </button>
          ))}
        </div>

        {editTab === 'policies' && (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              updateClient.mutate({ id: editClient!.client_id, body: editForm })
            }}
            className="space-y-5"
          >
            <div style={{ background: 'var(--clavex-surface)', borderRadius: 'var(--clavex-radius-md)', padding: '14px 16px' }}>
              <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '1.5px', color: 'var(--clavex-neutral)', textTransform: 'uppercase', marginBottom: 12 }}>Authentication policies</p>
              <div className="space-y-3">
                <Toggle
                  checked={editForm.mfa_required}
                  onChange={(v) => setEditForm((f) => ({ ...f, mfa_required: v }))}
                  label="Require MFA for this client"
                />
                <Toggle
                  checked={editForm.is_active}
                  onChange={(v) => setEditForm((f) => ({ ...f, is_active: v }))}
                  label="Client enabled"
                />
              </div>
            </div>

            <div style={{ background: 'var(--clavex-surface)', borderRadius: 'var(--clavex-radius-md)', padding: '14px 16px' }}>
              <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '1.5px', color: 'var(--clavex-neutral)', textTransform: 'uppercase', marginBottom: 4 }}>National eID login providers</p>
              <p style={{ fontSize: 12, color: 'var(--clavex-ink-subtle)', marginBottom: 12 }}>
                Select which national identity providers appear on the login page for this client.
                Leave all unchecked to show every active provider (default).
              </p>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { value: 'spid',          label: '🇮🇹 SPID' },
                  { value: 'cie',           label: '🇮🇹 CIE 3.0' },
                  { value: 'franceconnect', label: '🇫🇷 FranceConnect' },
                  { value: 'itsme',         label: '🇧🇪 itsme' },
                  { value: 'bundid',        label: '🇩🇪 BundID' },
                  { value: 'bundidsaml',    label: '🇩🇪 BundID SAML' },
                  { value: 'digid',         label: '🇳🇱 DigiD' },
                  { value: 'clave',         label: '🇪🇸 Cl@ve' },
                  { value: 'eidas',         label: '🇪🇺 eIDAS' },
                ].map(({ value, label }) => {
                  const checked = editForm.enabled_login_providers.includes(value)
                  return (
                    <label key={value} className="flex items-center gap-2 cursor-pointer select-none"
                      style={{ fontSize: 13, color: 'var(--clavex-ink)' }}>
                      <input type="checkbox" checked={checked}
                        onChange={(e) => setEditForm((f) => ({
                          ...f,
                          enabled_login_providers: e.target.checked
                            ? [...f.enabled_login_providers, value]
                            : f.enabled_login_providers.filter((p) => p !== value),
                        }))} />
                      {label}
                    </label>
                  )
                })}
              </div>
            </div>

            <div style={{ background: 'var(--clavex-surface)', borderRadius: 'var(--clavex-radius-md)', padding: '14px 16px' }}>
              <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '1.5px', color: 'var(--clavex-neutral)', textTransform: 'uppercase', marginBottom: 4 }}>Keycloak compatibility</p>
              <p style={{ fontSize: 12, color: 'var(--clavex-ink-subtle)', marginBottom: 12 }}>
                Adds <code style={{ background: '#F0FAF6', padding: '1px 5px', borderRadius: 4, fontSize: 11 }}>realm_access</code> and <code style={{ background: '#F0FAF6', padding: '1px 5px', borderRadius: 4, fontSize: 11 }}>resource_access</code> claims to access tokens. Enable for apps built against Keycloak.
              </p>
              <Toggle
                checked={editForm.keycloak_compat}
                onChange={(v) => setEditForm((f) => ({ ...f, keycloak_compat: v }))}
                label="Keycloak-compatible token claims"
              />
            </div>

            <div className="flex justify-end gap-2 pt-1">
              <Button variant="secondary" type="button" onClick={() => setEditClient(null)}>Cancel</Button>
              <Button type="submit" loading={updateClient.isPending}>Save changes</Button>
            </div>
          </form>
        )}

        {editTab === 'uris' && editClient && (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              updateClient.mutate({
                id: editClient.client_id,
                body: {
                  redirect_uris: uriForm.redirect_uris.split('\n').map((u) => u.trim()).filter(Boolean),
                  post_logout_redirect_uris: uriForm.post_logout_redirect_uris.split('\n').map((u) => u.trim()).filter(Boolean),
                },
              })
            }}
            className="space-y-4"
          >
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 4 }}>
                Redirect URIs <span style={{ fontWeight: 400, color: 'var(--clavex-neutral)' }}>(one per line)</span>
              </label>
              <textarea
                value={uriForm.redirect_uris}
                onChange={(e) => setUriForm((f) => ({ ...f, redirect_uris: e.target.value }))}
                rows={5}
                className="input-base"
                style={{ fontFamily: 'monospace', fontSize: 12, resize: 'vertical' }}
                placeholder="https://app.example.com/callback"
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 4 }}>
                Post-logout redirect URIs <span style={{ fontWeight: 400, color: 'var(--clavex-neutral)' }}>(one per line)</span>
              </label>
              <textarea
                value={uriForm.post_logout_redirect_uris}
                onChange={(e) => setUriForm((f) => ({ ...f, post_logout_redirect_uris: e.target.value }))}
                rows={3}
                className="input-base"
                style={{ fontFamily: 'monospace', fontSize: 12, resize: 'vertical' }}
                placeholder="https://app.example.com/logged-out"
              />
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <Button variant="secondary" type="button" onClick={() => setEditClient(null)}>Cancel</Button>
              <Button type="submit" loading={updateClient.isPending}>Save URIs</Button>
            </div>
          </form>
        )}
        {editTab === 'mappers' && editClient && (
          <MappersTab orgId={orgId} clientId={editClient.client_id} />
        )}
        {editTab === 'branding' && editClient && (
          <ClientBrandingTab orgId={orgId} clientId={editClient.client_id} />
        )}
      </Modal>

      {/* New secret reveal modal */}
      <Modal
        open={!!newSecret}
        title="Client secret — save this now"
        onClose={() => { setNewSecret(null); setShowCreate(false); resetForm(); qc.invalidateQueries({ queryKey: ['clients', orgId] }) }}
      >
        <div className="space-y-4">
          <div style={{ background: '#FAEEDA', border: '0.5px solid #BA7517', borderRadius: 'var(--clavex-radius-md)', padding: '10px 14px', fontSize: 13, color: '#854F0B' }}>
            This secret will <strong>not</strong> be shown again. Copy it now.
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--clavex-neutral)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '1px' }}>Client ID</label>
            <code style={{ display: 'block', background: 'var(--clavex-surface)', borderRadius: 'var(--clavex-radius-md)', padding: '10px 12px', fontSize: 12, fontFamily: 'monospace', wordBreak: 'break-all' }}>{newSecret?.clientId}</code>
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--clavex-neutral)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '1px' }}>Client Secret</label>
            <div className="flex items-center gap-2">
              <code style={{ flex: 1, display: 'block', background: 'var(--clavex-surface)', borderRadius: 'var(--clavex-radius-md)', padding: '10px 12px', fontSize: 12, fontFamily: 'monospace', wordBreak: 'break-all' }}>{newSecret?.secret}</code>
              <Button variant="secondary" size="sm" onClick={() => { navigator.clipboard.writeText(newSecret?.secret ?? ''); toast.success('Copied!') }}>
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
          <div className="flex justify-end">
            <Button onClick={() => { setNewSecret(null); setShowCreate(false); resetForm(); qc.invalidateQueries({ queryKey: ['clients', orgId] }) }}>
              Done, I've saved it
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
