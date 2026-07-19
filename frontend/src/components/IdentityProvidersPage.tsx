import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Globe, X } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Button, Card, PageHeader, Spinner, Modal, ManagedBadge } from '@/components/ui'

// ── Types ──────────────────────────────────────────────────────────────────────

interface IDP {
  id: string
  org_id: string
  name: string
  provider_type: string
  client_id: string
  authorization_url: string
  token_url: string
  userinfo_url: string | null
  scopes: string
  email_claim: string
  first_name_claim: string
  last_name_claim: string
  is_active: boolean
  allow_jit: boolean
  roles_claim: string | null
  role_claim_mappings: Record<string, string>
  apple_team_id?: string | null
  apple_key_id?: string | null
  managed_by?: string | null
  managed_ref?: string | null
}

interface IDPForm {
  name: string
  provider_type: string
  client_id: string
  client_secret: string
  authorization_url: string
  token_url: string
  userinfo_url: string
  scopes: string
  email_claim: string
  first_name_claim: string
  last_name_claim: string
  is_active: boolean
  allow_jit: boolean
  roles_claim: string
  role_claim_mappings: Record<string, string>
  // Apple Sign In With Apple credentials
  apple_team_id: string
  apple_key_id: string
  apple_private_key: string
}

interface Props {
  orgId: string
}

// ── Provider icons ─────────────────────────────────────────────────────────────

function ProviderIcon({ type, className = 'h-4 w-4' }: { type: string; className?: string }) {
  switch (type) {
    case 'google':
      return (
        <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
          <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
          <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
          <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"/>
          <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
        </svg>
      )
    case 'github':
      return (
        <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
        </svg>
      )
    case 'gitlab':
      return (
        <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
          <path fill="#E24329" d="M23.955 13.587l-1.342-4.135-2.664-8.189a.455.455 0 00-.867 0L16.418 9.45H7.582L4.918 1.263a.455.455 0 00-.867 0L1.387 9.45.045 13.587a.924.924 0 00.331 1.023L12 23.054l11.624-8.444a.923.923 0 00.331-1.023"/>
        </svg>
      )
    case 'microsoft':
      return (
        <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
          <path fill="#F25022" d="M1 1h10v10H1z"/>
          <path fill="#00A4EF" d="M13 1h10v10H13z"/>
          <path fill="#7FBA00" d="M1 13h10v10H1z"/>
          <path fill="#FFB900" d="M13 13h10v10H13z"/>
        </svg>
      )
    case 'apple':
      return (
        <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.7 9.05 7.4c1.36.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 3.99zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z"/>
        </svg>
      )
    case 'linkedin':
      return (
        <svg className={className} viewBox="0 0 24 24" fill="#0A66C2" aria-hidden="true">
          <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
        </svg>
      )
    default:
      return <Globe className={className} />
  }
}

const PROVIDER_LABELS: Record<string, string> = {
  oidc: 'OIDC',
  google: 'Google',
  github: 'GitHub',
  microsoft: 'Microsoft',
  gitlab: 'GitLab',
  apple: 'Apple',
  linkedin: 'LinkedIn',
}

// ── Presets for known providers ────────────────────────────────────────────────

const PRESETS: Record<string, Partial<IDPForm>> = {
  oidc: {},
  google: {
    authorization_url: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_url:         'https://oauth2.googleapis.com/token',
    userinfo_url:      'https://openidconnect.googleapis.com/v1/userinfo',
    scopes:            'openid email profile',
    email_claim:       'email',
    first_name_claim:  'given_name',
    last_name_claim:   'family_name',
  },
  github: {
    authorization_url: 'https://github.com/login/oauth/authorize',
    token_url:         'https://github.com/login/oauth/access_token',
    userinfo_url:      'https://api.github.com/user',
    scopes:            'read:user user:email',
    email_claim:       'email',
    first_name_claim:  'name',
    last_name_claim:   '',
  },
  microsoft: {
    authorization_url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    token_url:         'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userinfo_url:      'https://graph.microsoft.com/oidc/userinfo',
    scopes:            'openid email profile',
    email_claim:       'email',
    first_name_claim:  'given_name',
    last_name_claim:   'family_name',
  },
  gitlab: {
    authorization_url: 'https://gitlab.com/oauth/authorize',
    token_url:         'https://gitlab.com/oauth/token',
    userinfo_url:      'https://gitlab.com/oauth/userinfo',
    scopes:            'openid email profile',
    email_claim:       'email',
    first_name_claim:  'given_name',
    last_name_claim:   'family_name',
  },
  apple: {
    authorization_url: 'https://appleid.apple.com/auth/authorize',
    token_url:         'https://appleid.apple.com/auth/token',
    userinfo_url:      'https://appleid.apple.com/auth/userinfo',
    scopes:            'name email',
    email_claim:       'email',
    first_name_claim:  'given_name',
    last_name_claim:   'family_name',
  },
  linkedin: {
    authorization_url: 'https://www.linkedin.com/oauth/v2/authorization',
    token_url:         'https://www.linkedin.com/oauth/v2/accessToken',
    userinfo_url:      'https://api.linkedin.com/v2/userinfo',
    scopes:            'openid profile email',
    email_claim:       'email',
    first_name_claim:  'given_name',
    last_name_claim:   'family_name',
  },
}

const BLANK_FORM: IDPForm = {
  name:              '',
  provider_type:     'oidc',
  client_id:         '',
  client_secret:     '',
  authorization_url: '',
  token_url:         '',
  userinfo_url:      '',
  scopes:            'openid email profile',
  email_claim:       'email',
  first_name_claim:  'given_name',
  last_name_claim:   'family_name',
  is_active:         true,
  allow_jit:         true,
  roles_claim:       '',
  role_claim_mappings: {},
  apple_team_id:     '',
  apple_key_id:      '',
  apple_private_key: '',
}

// ── Form modal ─────────────────────────────────────────────────────────────────

function IDPFormModal({
  orgId,
  editing,
  onClose,
}: {
  orgId: string
  editing: IDP | null
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [form, setForm] = useState<IDPForm>(
    editing
      ? {
          name:              editing.name,
          provider_type:     editing.provider_type,
          client_id:         editing.client_id,
          client_secret:     '',
          authorization_url: editing.authorization_url,
          token_url:         editing.token_url,
          userinfo_url:      editing.userinfo_url ?? '',
          scopes:            editing.scopes,
          email_claim:       editing.email_claim,
          first_name_claim:  editing.first_name_claim,
          last_name_claim:   editing.last_name_claim,
          is_active:         editing.is_active,
          allow_jit:         editing.allow_jit,
          roles_claim:       editing.roles_claim ?? '',
          role_claim_mappings: editing.role_claim_mappings ?? {},
          apple_team_id:     editing.apple_team_id ?? '',
          apple_key_id:      editing.apple_key_id ?? '',
          apple_private_key: '',
        }
      : { ...BLANK_FORM },
  )

  const set = <K extends keyof IDPForm>(key: K, val: IDPForm[K]) =>
    setForm((prev) => ({ ...prev, [key]: val }))

  const applyPreset = (type: string) => {
    const preset = PRESETS[type] ?? {}
    setForm((prev) => ({
      ...prev,
      provider_type: type,
      ...preset,
      // Reset Apple fields when switching away
      ...(type !== 'apple' ? { apple_team_id: '', apple_key_id: '', apple_private_key: '' } : {}),
    }))
  }

  const save = useMutation({
    mutationFn: (body: IDPForm) =>
      editing
        ? api.patch(`/organizations/${orgId}/identity-providers/${editing.id}`, body)
        : api.post(`/organizations/${orgId}/identity-providers`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['idps', orgId] })
      toast.success(editing ? 'Provider updated' : 'Provider created')
      onClose()
    },
    onError: () => toast.error('Failed to save identity provider'),
  })

  const textField = (
    label: string,
    field: keyof IDPForm,
    opts?: { type?: string; placeholder?: string; required?: boolean },
  ) => (
    <div>
      <label className="block text-xs font-medium text-gray-600 mb-1">{label}</label>
      <input
        type={opts?.type ?? 'text'}
        required={opts?.required}
        placeholder={opts?.placeholder}
        value={String(form[field])}
        onChange={(e) => set(field, e.target.value as IDPForm[typeof field])}
        className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
      />
    </div>
  )

  const isApple = form.provider_type === 'apple'

  return (
    <Modal
      open
      title={editing ? 'Edit Identity Provider' : 'Add Identity Provider'}
      onClose={onClose}
      size="lg"
    >
      <div className="space-y-4">
        {/* Preset picker */}
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-2">Provider type</label>
          <div className="flex flex-wrap gap-2">
            {(['oidc', 'google', 'github', 'microsoft', 'gitlab', 'apple', 'linkedin'] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => applyPreset(t)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                  form.provider_type === t
                    ? 'bg-[var(--clavex-primary)] text-white border-[var(--clavex-primary)]'
                    : 'border-gray-300 text-gray-600 hover:border-[var(--clavex-primary)]'
                }`}
              >
                <ProviderIcon type={t} className="h-3.5 w-3.5" />
                {PROVIDER_LABELS[t]}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {textField('Display name', 'name', { required: true, placeholder: 'e.g. Company SSO' })}
          {textField('Client ID', 'client_id', { required: true })}
          {!isApple && textField(editing ? 'Client secret (leave blank to keep)' : 'Client secret', 'client_secret', {
            type: 'password',
            required: !editing,
          })}
          {textField('Scopes', 'scopes')}
        </div>

        {/* Apple-specific JWT credentials */}
        {isApple && (
          <div className="rounded-xl border border-amber-200 bg-amber-50/60 p-4 space-y-3">
            <div>
              <p className="text-xs font-semibold text-amber-800 uppercase tracking-wide">Sign in with Apple credentials</p>
              <p className="text-xs text-amber-700 mt-0.5">
                Clavex generates the ES256 JWT client secret automatically. Provide your Team ID, Key ID, and the .p8 private key from Apple Developer portal.
              </p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {textField('Team ID', 'apple_team_id', { required: true, placeholder: 'XXXXXXXXXX' })}
              {textField('Key ID', 'apple_key_id', { required: true, placeholder: 'XXXXXXXXXX' })}
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                {editing ? 'Private key (.p8 content — leave blank to keep)' : 'Private key (.p8 content)'}
              </label>
              <textarea
                rows={5}
                placeholder={'-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----'}
                value={form.apple_private_key}
                onChange={(e) => set('apple_private_key', e.target.value)}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
              />
            </div>
          </div>
        )}

        <div className="space-y-3">
          {textField('Authorization URL', 'authorization_url', { required: true, placeholder: 'https://…/authorize' })}
          {textField('Token URL', 'token_url', { required: true, placeholder: 'https://…/token' })}
          {textField('UserInfo URL', 'userinfo_url', { placeholder: 'https://…/userinfo' })}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {textField('Email claim', 'email_claim')}
          {textField('First name claim', 'first_name_claim')}
          {textField('Last name claim', 'last_name_claim')}
        </div>

        <label className="flex items-center gap-3 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={form.is_active}
            onChange={(e) => set('is_active', e.target.checked)}
            className="h-4 w-4 rounded border-gray-300 text-[var(--clavex-primary)]"
          />
          <span className="text-sm text-gray-700">Active (show on login page)</span>
        </label>

        {/* JIT provisioning */}
        <div className="border border-gray-100 rounded-xl p-4 space-y-4 bg-gray-50/60">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-sm font-medium text-gray-800">JIT provisioning</p>
              <p className="text-xs text-gray-500 mt-0.5">
                Automatically create user accounts on first login via this provider.
              </p>
            </div>
            <button
              type="button"
              onClick={() => set('allow_jit', !form.allow_jit)}
              className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors
                ${form.allow_jit ? 'bg-[var(--clavex-primary)]' : 'bg-gray-300'}`}
            >
              <span
                className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow ring-0 transition-transform
                  ${form.allow_jit ? 'translate-x-4' : 'translate-x-0'}`}
              />
            </button>
          </div>

          {/* Role claim mappings */}
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Roles / groups claim name
            </label>
            <input
              type="text"
              placeholder="e.g. groups, roles"
              value={form.roles_claim}
              onChange={(e) => set('roles_claim', e.target.value)}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
            />
            <p className="mt-1 text-xs text-gray-400">
              Claim in the userinfo response that contains group/role values.
            </p>
          </div>

          {form.roles_claim.trim() !== '' && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-medium text-gray-600">Claim → role mappings</label>
                <button
                  type="button"
                  onClick={() => set('role_claim_mappings', { ...form.role_claim_mappings, '': '' })}
                  className="text-xs text-[var(--clavex-primary)] hover:underline"
                >
                  + Add mapping
                </button>
              </div>
              {Object.entries(form.role_claim_mappings).length === 0 ? (
                <p className="text-xs text-gray-400 italic">No mappings — add one above.</p>
              ) : (
                <div className="space-y-2">
                  {Object.entries(form.role_claim_mappings).map(([claimVal, localRole], idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <input
                        type="text"
                        placeholder="Claim value (e.g. admins)"
                        value={claimVal}
                        onChange={(e) => {
                          const entries = Object.entries(form.role_claim_mappings)
                          entries[idx][0] = e.target.value
                          set('role_claim_mappings', Object.fromEntries(entries))
                        }}
                        className="flex-1 rounded-lg border border-gray-300 px-2.5 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
                      />
                      <span className="text-gray-400 text-xs">→</span>
                      <input
                        type="text"
                        placeholder="Local role name"
                        value={localRole}
                        onChange={(e) => {
                          const entries = Object.entries(form.role_claim_mappings)
                          entries[idx][1] = e.target.value
                          set('role_claim_mappings', Object.fromEntries(entries))
                        }}
                        className="flex-1 rounded-lg border border-gray-300 px-2.5 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
                      />
                      <button
                        type="button"
                        onClick={() => {
                          const entries = Object.entries(form.role_claim_mappings)
                          entries.splice(idx, 1)
                          set('role_claim_mappings', Object.fromEntries(entries))
                        }}
                        className="p-1 rounded hover:bg-red-50 text-gray-400 hover:text-red-500 transition-colors"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 pt-2 border-t border-gray-100">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => save.mutate(form)} disabled={save.isPending}>
            {save.isPending ? 'Saving…' : editing ? 'Update' : 'Create'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}

// ── Main export ────────────────────────────────────────────────────────────────

export default function IdentityProvidersPage({ orgId }: Props) {
  const qc = useQueryClient()
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<IDP | null>(null)

  const { data: providers, isLoading } = useQuery<IDP[]>({
    queryKey: ['idps', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/identity-providers`).then((r) => r.data),
  })

  const remove = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/organizations/${orgId}/identity-providers/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['idps', orgId] })
      toast.success('Provider removed')
    },
    onError: () => toast.error('Failed to remove provider'),
  })

  const openCreate = () => { setEditing(null); setModalOpen(true) }
  const openEdit = (idp: IDP) => { setEditing(idp); setModalOpen(true) }

  return (
    <div>
      <PageHeader
        title="EuroID"
        action={
          <Button onClick={openCreate}>
            <Plus className="h-4 w-4" />
            Add provider
          </Button>
        }
      />

      {isLoading ? (
        <Spinner />
      ) : !providers?.length ? (
        <Card className="p-12 text-center">
          <Globe className="h-10 w-10 mx-auto mb-3 text-gray-300" />
          <p className="text-sm text-gray-500 font-medium">No identity providers configured</p>
          <p className="text-xs text-gray-400 mt-1">
            Connect Google, GitHub, Apple, LinkedIn or any OIDC-compatible provider.
          </p>
          <div className="mt-4">
            <Button onClick={openCreate}>
              <Plus className="h-4 w-4" />
              Add your first provider
            </Button>
          </div>
        </Card>
      ) : (
        <Card>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100">
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Name</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Type</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Client ID</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Status</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {providers.map((idp) => (
                <tr key={idp.id} className="border-b border-gray-50 hover:bg-gray-50/50 transition-colors">
                  <td className="px-4 py-3 font-medium text-gray-900">
                    <div className="flex items-center gap-1.5">
                      <span>{idp.name}</span>
                      <ManagedBadge managedBy={idp.managed_by} managedRef={idp.managed_ref} />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-blue-50 text-blue-700">
                      <ProviderIcon type={idp.provider_type} className="h-3 w-3" />
                      {PROVIDER_LABELS[idp.provider_type] ?? idp.provider_type}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-500 font-mono text-xs truncate max-w-[200px]">
                    {idp.client_id}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                        idp.is_active
                          ? 'bg-green-50 text-green-700'
                          : 'bg-gray-100 text-gray-500'
                      }`}
                    >
                      {idp.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1 justify-end">
                      <button
                        onClick={() => openEdit(idp)}
                        className="p-1.5 rounded hover:bg-gray-100 text-gray-500 transition-colors"
                        title="Edit"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => {
                          if (confirm(`Remove "${idp.name}"?`)) remove.mutate(idp.id)
                        }}
                        className="p-1.5 rounded hover:bg-red-50 text-gray-500 hover:text-red-600 transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {modalOpen && (
        <IDPFormModal orgId={orgId} editing={editing} onClose={() => setModalOpen(false)} />
      )}
    </div>
  )
}

