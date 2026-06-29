import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, RefreshCw, CheckCircle2, XCircle, Network } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuthStore } from '@/stores/auth'
import { Button, Card, Modal, Input, PageHeader, Badge, Spinner } from '@/components/ui'
import { cn } from '@/lib/cn'
import api, { toArr } from '@/lib/api'

// ── Provider catalogue ────────────────────────────────────────────────────────

interface Provider {
  id: string
  name: string
  vendor?: string
  description: string
  icon: string // emoji / short text used as avatar
  defaults: Partial<LDAPForm>
}

const PROVIDERS: Provider[] = [
  {
    id: 'active-directory',
    name: 'Active Directory',
    vendor: 'Microsoft',
    description: 'On-premises Windows Server AD — the most common enterprise directory.',
    icon: '🪟',
    defaults: {
      port: 389,
      use_tls: false,
      user_filter: '(objectClass=user)',
      bind_dn: 'CN=svc-clavex,CN=Users,DC=corp,DC=example,DC=com',
      base_dn: 'DC=corp,DC=example,DC=com',
    },
  },
  {
    id: 'openldap',
    name: 'OpenLDAP',
    vendor: 'Open Source',
    description: 'High-performance open source LDAP v3 server.',
    icon: '🐧',
    defaults: {
      port: 389,
      use_tls: false,
      user_filter: '(objectClass=inetOrgPerson)',
      bind_dn: 'cn=admin,dc=example,dc=com',
      base_dn: 'dc=example,dc=com',
    },
  },
  {
    id: 'freeipa',
    name: 'FreeIPA / Red Hat IdM',
    vendor: 'Red Hat',
    description: 'Linux-centric enterprise identity: users, groups, Kerberos, DNS.',
    icon: '🎩',
    defaults: {
      port: 389,
      use_tls: false,
      user_filter: '(objectClass=person)',
      bind_dn: 'uid=admin,cn=users,cn=accounts,dc=ipa,dc=example,dc=com',
      base_dn: 'cn=users,cn=accounts,dc=ipa,dc=example,dc=com',
    },
  },
  {
    id: 'jumpcloud',
    name: 'JumpCloud',
    vendor: 'JumpCloud',
    description: 'Cloud LDAP-as-a-service. Host and TLS are fixed.',
    icon: '☁️',
    defaults: {
      host: 'ldap.jumpcloud.com',
      port: 636,
      use_tls: true,
      user_filter: '(objectClass=inetOrgPerson)',
      bind_dn: 'uid=<service-user>,ou=Users,o=<org-id>,dc=jumpcloud,dc=com',
      base_dn: 'ou=Users,o=<org-id>,dc=jumpcloud,dc=com',
    },
  },
  {
    id: 'azure-ad-ds',
    name: 'Azure AD Domain Services',
    vendor: 'Microsoft',
    description: 'Managed LDAP in Azure. Requires LDAPS (port 636).',
    icon: '🔷',
    defaults: {
      port: 636,
      use_tls: true,
      user_filter: '(objectClass=user)',
      bind_dn: 'CN=svc-clavex,OU=AADDC Users,DC=aadds,DC=example,DC=com',
      base_dn: 'OU=AADDC Users,DC=aadds,DC=example,DC=com',
    },
  },
  {
    id: 'entra-id',
    name: 'Microsoft Entra ID',
    vendor: 'Microsoft',
    description: 'Entra ID (Azure AD) via LDAP needs Azure AD DS or an LDAP proxy. For cloud-only tenants prefer OIDC/SCIM.',
    icon: '🔵',
    defaults: {
      port: 636,
      use_tls: true,
      user_filter: '(objectClass=user)',
      bind_dn: 'CN=svc-clavex,OU=AADDC Users,DC=contoso,DC=onmicrosoft,DC=com',
      base_dn: 'OU=AADDC Users,DC=contoso,DC=onmicrosoft,DC=com',
    },
  },
  {
    id: 'generic',
    name: 'Generic LDAP',
    description: 'Any LDAPv3-compatible directory not listed above.',
    icon: '📂',
    defaults: {
      port: 389,
      use_tls: false,
      user_filter: '(objectClass=person)',
    },
  },
]

// ── Types ─────────────────────────────────────────────────────────────────────

interface LDAPForm {
  name: string
  host: string
  port: number
  use_tls: boolean
  bind_dn: string
  bind_password: string
  base_dn: string
  user_filter: string
}

interface LDAPConnection {
  id: string
  name: string
  host: string
  port: number
  use_tls: boolean
  bind_dn?: string
  base_dn: string
  user_filter: string
  is_active: boolean
  last_sync_at?: string
  created_at: string
}

const DEFAULT_FORM: LDAPForm = {
  name: '',
  host: '',
  port: 389,
  use_tls: false,
  bind_dn: '',
  bind_password: '',
  base_dn: '',
  user_filter: '(objectClass=person)',
}

// ── Sub-components ────────────────────────────────────────────────────────────

function ProviderCard({
  provider,
  selected,
  onSelect,
}: {
  provider: Provider
  selected: boolean
  onSelect: () => void
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'w-full text-left flex items-center gap-4 px-4 py-3 rounded-xl border transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500',
        selected
          ? 'border-brand-500 bg-brand-50'
          : 'border-gray-100 bg-white hover:border-gray-200 hover:bg-gray-50',
      )}
    >
      {/* Selector circle */}
      <div className={cn(
        'flex-shrink-0 h-4 w-4 rounded-full border-2 transition-colors',
        selected ? 'border-brand-500 bg-brand-500' : 'border-gray-300',
      )}>
        {selected && <div className="h-full w-full rounded-full scale-[0.4] bg-white" />}
      </div>

      {/* Icon */}
      <span className="text-xl leading-none flex-shrink-0">{provider.icon}</span>

      {/* Text */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className="font-medium text-sm text-gray-900">{provider.name}</p>
          {provider.vendor && (
            <span className="text-[10px] font-medium text-gray-400 bg-gray-100 px-1.5 py-0.5 rounded-full">
              {provider.vendor}
            </span>
          )}
        </div>
        <p className="text-xs text-gray-500 truncate">{provider.description}</p>
      </div>
    </button>
  )
}

// ── Wizard modal ──────────────────────────────────────────────────────────────

function AddConnectionModal({
  open,
  orgId,
  onClose,
}: {
  open: boolean
  orgId: string
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [step, setStep] = useState<'pick' | 'configure'>('pick')
  const [selectedProvider, setSelectedProvider] = useState<Provider | null>(null)
  const [form, setForm] = useState<LDAPForm>(DEFAULT_FORM)

  function handlePickProvider(p: Provider) {
    setSelectedProvider(p)
    setForm({ ...DEFAULT_FORM, ...p.defaults, name: p.name })
  }

  function handleNext() {
    if (!selectedProvider) return
    setStep('configure')
  }

  function handleBack() {
    setStep('pick')
  }

  function handleClose() {
    setStep('pick')
    setSelectedProvider(null)
    setForm(DEFAULT_FORM)
    onClose()
  }

  const set = (key: keyof LDAPForm, value: string | number | boolean) =>
    setForm((f) => ({ ...f, [key]: value }))

  const create = useMutation({
    mutationFn: () =>
      api.post(`/organizations/${orgId}/ldap`, {
        name: form.name,
        host: form.host,
        port: Number(form.port),
        use_tls: form.use_tls,
        bind_dn: form.bind_dn || undefined,
        bind_password: form.bind_password || undefined,
        base_dn: form.base_dn,
        user_filter: form.user_filter,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ldap', orgId] })
      toast.success('LDAP connection added')
      handleClose()
    },
    onError: () => toast.error('Failed to create LDAP connection'),
  })

  return (
    <Modal
      open={open}
      title={step === 'pick' ? 'Choose a directory provider' : `Configure ${selectedProvider?.name}`}
      onClose={handleClose}
      size="lg"
    >
      {step === 'pick' ? (
        <div className="space-y-4">
          <p className="text-sm text-gray-500">
            Select your directory type — defaults will be pre-filled for you.
          </p>
          <div className="flex flex-col gap-1.5">
            {PROVIDERS.map((p) => (
              <ProviderCard
                key={p.id}
                provider={p}
                selected={selectedProvider?.id === p.id}
                onSelect={() => handlePickProvider(p)}
              />
            ))}
          </div>
          <div className="flex justify-end gap-2 pt-2 border-t border-gray-100">
            <Button variant="secondary" type="button" onClick={handleClose}>
              Cancel
            </Button>
            <Button disabled={!selectedProvider} onClick={handleNext}>
              Continue →
            </Button>
          </div>
        </div>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            create.mutate()
          }}
          className="space-y-4"
        >
          <div className="flex items-center gap-2 p-3 rounded-xl bg-brand-50 border border-brand-100">
            <span className="text-lg">{selectedProvider?.icon}</span>
            <div>
              <p className="text-sm font-medium text-brand-800">{selectedProvider?.name}</p>
              <p className="text-xs text-brand-600">{selectedProvider?.description}</p>
            </div>
          </div>

          <Input
            label="Connection name"
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
            placeholder="Production AD"
            required
            autoFocus
          />

          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <Input
                label="Host"
                value={form.host}
                onChange={(e) => set('host', e.target.value)}
                placeholder="ldap.example.com"
                required
              />
            </div>
            <Input
              label="Port"
              type="number"
              value={String(form.port)}
              onChange={(e) => set('port', Number(e.target.value))}
              min={1}
              max={65535}
              required
            />
          </div>

          <label className="flex items-center gap-2.5 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={form.use_tls}
              onChange={(e) => set('use_tls', e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
            />
            <span className="text-sm font-medium text-gray-700">Use TLS / LDAPS</span>
          </label>

          <div className="border-t border-gray-100 pt-4 space-y-4">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Bind credentials</p>
            <Input
              label="Bind DN"
              value={form.bind_dn}
              onChange={(e) => set('bind_dn', e.target.value)}
              placeholder="CN=svc-clavex,CN=Users,DC=corp,DC=com"
              hint="Service account used to search the directory"
            />
            <Input
              label="Bind password"
              type="password"
              value={form.bind_password}
              onChange={(e) => set('bind_password', e.target.value)}
              hint="Stored encrypted at rest"
            />
          </div>

          <div className="border-t border-gray-100 pt-4 space-y-4">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Search settings</p>
            <Input
              label="Base DN"
              value={form.base_dn}
              onChange={(e) => set('base_dn', e.target.value)}
              placeholder="DC=corp,DC=example,DC=com"
              required
            />
            <Input
              label="User filter"
              value={form.user_filter}
              onChange={(e) => set('user_filter', e.target.value)}
              placeholder="(objectClass=person)"
              hint="LDAP filter to identify user objects"
              required
            />
          </div>

          <div className="flex justify-between gap-2 pt-2 border-t border-gray-100">
            <Button variant="ghost" type="button" onClick={handleBack}>
              ← Back
            </Button>
            <div className="flex gap-2">
              <Button variant="secondary" type="button" onClick={handleClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={create.isPending}>
                {create.isPending ? 'Saving…' : 'Add connection'}
              </Button>
            </div>
          </div>
        </form>
      )}
    </Modal>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function LdapPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [showAdd, setShowAdd] = useState(false)

  const { data: connections = [], isLoading } = useQuery<LDAPConnection[]>({
    queryKey: ['ldap', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/ldap`).then((r) => toArr<LDAPConnection>(r.data)),
    enabled: !!orgId,
  })

  const deleteConn = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/ldap/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ldap', orgId] })
      toast.success('Connection removed')
    },
    onError: () => toast.error('Failed to remove connection'),
  })

  const syncConn = useMutation({
    mutationFn: (id: string) => api.post(`/organizations/${orgId}/ldap/${id}/sync`),
    onSuccess: () => toast.success('Sync triggered'),
    onError: () => toast.error('Sync not implemented yet'),
  })

  return (
    <div>
      <PageHeader
        title="Directory Connections"
        subtitle="Federate users from your LDAP / Active Directory into Clavex."
        action={
          <Button onClick={() => setShowAdd(true)}>
            <Plus className="h-4 w-4" />
            Add connection
          </Button>
        }
      />

      {isLoading ? (
        <Spinner />
      ) : connections.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-14 px-6 text-center">
          <div className="h-12 w-12 rounded-xl bg-gray-100 flex items-center justify-center mb-3">
            <Network className="h-6 w-6 text-gray-400" />
          </div>
          <p className="font-medium text-gray-700 mb-1">No directory connections yet</p>
          <p className="text-sm text-gray-400 mb-4">Connect your LDAP or Active Directory to sync users automatically.</p>
          <Button onClick={() => setShowAdd(true)}>
            <Plus className="h-4 w-4" />
            Add connection
          </Button>
        </div>
      ) : (
        <Card>
          <div className="divide-y divide-gray-100">
            {connections.map((conn) => (
              <div key={conn.id} className="flex items-center gap-4 px-6 py-4">
                {/* Status icon */}
                <div className="flex-shrink-0">
                  {conn.is_active ? (
                    <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                  ) : (
                    <XCircle className="h-5 w-5 text-gray-300" />
                  )}
                </div>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm text-gray-900">{conn.name}</p>
                  <p className="text-xs text-gray-400 font-mono mt-0.5">
                    {conn.use_tls ? 'ldaps' : 'ldap'}://{conn.host}:{conn.port}
                  </p>
                  <p className="text-xs text-gray-400 mt-0.5 truncate">{conn.base_dn}</p>
                </div>

                {/* Badges */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <Badge variant={conn.is_active ? 'green' : 'gray'}>
                    {conn.is_active ? 'Active' : 'Inactive'}
                  </Badge>
                  {conn.use_tls && <Badge variant="blue">TLS</Badge>}
                  {conn.last_sync_at && (
                    <span className="text-xs text-gray-400 hidden sm:inline">
                      Synced {new Date(conn.last_sync_at).toLocaleDateString()}
                    </span>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-1 flex-shrink-0">
                  <Button
                    variant="ghost"
                    size="sm"
                    title="Trigger sync"
                    onClick={() => syncConn.mutate(conn.id)}
                  >
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    title="Remove connection"
                    onClick={() => {
                      if (confirm(`Remove connection "${conn.name}"?`)) {
                        deleteConn.mutate(conn.id)
                      }
                    }}
                  >
                    <Trash2 className="h-4 w-4 text-red-500" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <AddConnectionModal
        open={showAdd}
        orgId={orgId ?? ''}
        onClose={() => setShowAdd(false)}
      />
    </div>
  )
}
