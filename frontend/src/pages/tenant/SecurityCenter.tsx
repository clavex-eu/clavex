import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import { useParams, useNavigate } from 'react-router-dom'
import api, { toArr } from '@/lib/api'
import toast from 'react-hot-toast'
import {
  ShieldCheck, Flag, Mail, ToggleLeft, ToggleRight,
  Plus, Trash2, Pencil, X, Check, Users, User, ChevronDown, ChevronRight,
} from 'lucide-react'
import {
  Badge, Button, Input, Modal, PageHeader, EmptyState, Spinner, Card, AlertBanner,
} from '@/components/ui'

// ── Types ─────────────────────────────────────────────────────────────────────

interface EmailPolicy {
  email_blocklist: string[]
  email_allowlist: string[]
}

interface FeatureFlag {
  id: string
  org_id: string
  key: string
  description: string
  value: boolean
  created_at: string
  updated_at: string
}

interface FlagOverride {
  id: string
  flag_id: string
  target_type: 'user' | 'role'
  target_id: string
  value: boolean
}

// ── Email Policy Panel ────────────────────────────────────────────────────────

function EmailPolicyPanel({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [newBlockEntry, setNewBlockEntry] = useState('')
  const [newAllowEntry, setNewAllowEntry] = useState('')

  const { data: policy, isLoading } = useQuery<EmailPolicy>({
    queryKey: ['email-policy', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/email-policy`).then((r) => r.data),
    enabled: !!orgId,
  })

  const save = useMutation({
    mutationFn: (body: EmailPolicy) =>
      api.put(`/organizations/${orgId}/email-policy`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['email-policy', orgId] })
      toast.success('Email policy saved')
    },
    onError: () => toast.error('Failed to save email policy'),
  })

  function addBlocklist() {
    const entry = newBlockEntry.trim().toLowerCase()
    if (!entry) return
    const current = policy?.email_blocklist ?? []
    if (current.includes(entry)) { toast.error('Already in blocklist'); return }
    save.mutate({ email_blocklist: [...current, entry], email_allowlist: policy?.email_allowlist ?? [] })
    setNewBlockEntry('')
  }

  function removeBlocklist(domain: string) {
    const blocklist = (policy?.email_blocklist ?? []).filter((d) => d !== domain)
    save.mutate({ email_blocklist: blocklist, email_allowlist: policy?.email_allowlist ?? [] })
  }

  function addAllowlist() {
    const entry = newAllowEntry.trim().toLowerCase()
    if (!entry) return
    const current = policy?.email_allowlist ?? []
    if (current.includes(entry)) { toast.error('Already in allowlist'); return }
    save.mutate({ email_blocklist: policy?.email_blocklist ?? [], email_allowlist: [...current, entry] })
    setNewAllowEntry('')
  }

  function removeAllowlist(domain: string) {
    const allowlist = (policy?.email_allowlist ?? []).filter((d) => d !== domain)
    save.mutate({ email_blocklist: policy?.email_blocklist ?? [], email_allowlist: allowlist })
  }

  if (isLoading) return <Spinner />

  const blocklist = policy?.email_blocklist ?? []
  const allowlist = policy?.email_allowlist ?? []

  return (
    <div className="space-y-6">
      <AlertBanner variant="info">
        {allowlist.length > 0
          ? 'Allowlist is active — only the listed domains can register users in this org.'
          : blocklist.length > 0
          ? 'Blocklist is active — the listed domains are rejected at registration.'
          : 'No email policy configured. All domains are allowed.'}
      </AlertBanner>

      {/* Allowlist */}
      <div>
        <h3 className="text-sm font-semibold text-[#1A2332] mb-1">
          Allowlist <span className="text-[#5F5E5A] font-normal">(only these domains may register)</span>
        </h3>
        <p className="text-xs text-[#5F5E5A] mb-3">
          When non-empty, overrides the blocklist. Supports wildcards: <code className="bg-[#F5F4F0] px-1 rounded">*.example.com</code>
        </p>
        <div className="flex gap-2 mb-2">
          <Input
            placeholder="acme.com or *.acme.com"
            value={newAllowEntry}
            onChange={(e) => setNewAllowEntry(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addAllowlist()}
            className="flex-1"
          />
          <Button size="sm" onClick={addAllowlist} loading={save.isPending}>
            <Plus size={14} /> Add
          </Button>
        </div>
        {allowlist.length === 0
          ? <p className="text-xs text-[#5F5E5A] italic">No allowlist entries.</p>
          : (
            <div className="flex flex-wrap gap-2">
              {allowlist.map((d) => (
                <span key={d} className="inline-flex items-center gap-1 rounded-full px-3 py-1 bg-[#E1F5EE] text-[#0F6E56] text-xs font-medium">
                  <Check size={11} />
                  {d}
                  <button
                    onClick={() => removeAllowlist(d)}
                    className="ml-1 hover:text-[#0F6E56]/60 transition-colors"
                    aria-label={`Remove ${d} from allowlist`}
                  >
                    <X size={11} />
                  </button>
                </span>
              ))}
            </div>
          )}
      </div>

      {/* Blocklist */}
      <div>
        <h3 className="text-sm font-semibold text-[#1A2332] mb-1">
          Blocklist <span className="text-[#5F5E5A] font-normal">(these domains are refused at registration)</span>
        </h3>
        <p className="text-xs text-[#5F5E5A] mb-3">
          Ignored when the allowlist is non-empty. Supports wildcards: <code className="bg-[#F5F4F0] px-1 rounded">*.tempmail.com</code>
        </p>
        <div className="flex gap-2 mb-2">
          <Input
            placeholder="tempmail.com or *.disposable.org"
            value={newBlockEntry}
            onChange={(e) => setNewBlockEntry(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addBlocklist()}
            className="flex-1"
          />
          <Button size="sm" variant="danger" onClick={addBlocklist} loading={save.isPending}>
            <Plus size={14} /> Block
          </Button>
        </div>
        {blocklist.length === 0
          ? <p className="text-xs text-[#5F5E5A] italic">No blocklist entries.</p>
          : (
            <div className="flex flex-wrap gap-2">
              {blocklist.map((d) => (
                <span key={d} className="inline-flex items-center gap-1 rounded-full px-3 py-1 bg-[#FCEBEB] text-[#A32D2D] text-xs font-medium">
                  <X size={11} />
                  {d}
                  <button
                    onClick={() => removeBlocklist(d)}
                    className="ml-1 hover:text-[#A32D2D]/60 transition-colors"
                    aria-label={`Remove ${d} from blocklist`}
                  >
                    <Trash2 size={11} />
                  </button>
                </span>
              ))}
            </div>
          )}
      </div>
    </div>
  )
}

// ── Feature Flags Panel ───────────────────────────────────────────────────────

interface FlagRowProps {
  flag: FeatureFlag
  orgId: string
  onDelete: () => void
  onToggle: () => void
}

function FlagRow({ flag, orgId, onDelete, onToggle }: FlagRowProps) {
  const [expanded, setExpanded] = useState(false)
  const [editMode, setEditMode] = useState(false)
  const [desc, setDesc] = useState(flag.description)
  const qc = useQueryClient()

  const upsert = useMutation({
    mutationFn: (body: { key: string; description: string; value: boolean }) =>
      api.post(`/organizations/${orgId}/feature-flags`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['feature-flags', orgId] })
      toast.success('Flag updated')
      setEditMode(false)
    },
    onError: () => toast.error('Failed to update flag'),
  })

  const { data: overrides = [], isLoading: loadingOverrides } = useQuery<FlagOverride[]>({
    queryKey: ['flag-overrides', orgId, flag.key],
    queryFn: () =>
      api.get(`/organizations/${orgId}/feature-flags/${flag.key}/overrides`)
        .then((r) => toArr<FlagOverride>(r.data)),
    enabled: expanded,
  })

  const deleteOverride = useMutation({
    mutationFn: (body: { target_type: string; target_id: string }) =>
      api.delete(`/organizations/${orgId}/feature-flags/${flag.key}/overrides`, { data: body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['flag-overrides', orgId, flag.key] }),
    onError: () => toast.error('Failed to remove override'),
  })

  return (
    <div className="border border-[#E8E7E3] rounded-lg overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 bg-white">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="text-[#5F5E5A] hover:text-[#1A2332] transition-colors"
        >
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>

        <code className="text-sm font-mono font-semibold text-[#185FA5] flex-1">
          {flag.key}
        </code>

        {editMode ? (
          <input
            value={desc}
            onChange={(e) => setDesc(e.target.value)}
            className="text-xs border border-[#E8E7E3] rounded px-2 py-1 flex-1 mr-2"
            placeholder="Description"
          />
        ) : (
          <span className="text-xs text-[#5F5E5A] flex-1 truncate">{flag.description || '—'}</span>
        )}

        {/* Toggle */}
        <button
          onClick={() => {
            if (editMode) {
              upsert.mutate({ key: flag.key, description: desc, value: flag.value })
            } else {
              onToggle()
            }
          }}
          className="transition-colors"
          aria-label={flag.value ? 'Disable flag' : 'Enable flag'}
        >
          {flag.value
            ? <ToggleRight size={22} className="text-[#0F6E56]" />
            : <ToggleLeft size={22} className="text-[#9E9E9B]" />}
        </button>

        <Badge variant={flag.value ? 'green' : 'gray'}>{flag.value ? 'on' : 'off'}</Badge>

        {editMode ? (
          <>
            <Button size="xs" loading={upsert.isPending} onClick={() => upsert.mutate({ key: flag.key, description: desc, value: flag.value })}>
              <Check size={12} /> Save
            </Button>
            <Button size="xs" variant="ghost" onClick={() => { setEditMode(false); setDesc(flag.description) }}>
              Cancel
            </Button>
          </>
        ) : (
          <button onClick={() => setEditMode(true)} className="text-[#5F5E5A] hover:text-[#1A2332] p-1" aria-label="Edit">
            <Pencil size={13} />
          </button>
        )}

        <button onClick={onDelete} className="text-[#5F5E5A] hover:text-[#A32D2D] p-1 transition-colors" aria-label="Delete flag">
          <Trash2 size={13} />
        </button>
      </div>

      {expanded && (
        <div className="bg-[#FAFAF8] border-t border-[#E8E7E3] px-4 py-3">
          <p className="text-xs font-semibold text-[#1A2332] mb-2">
            Overrides
            <span className="text-[#5F5E5A] font-normal ml-1">— per-user or per-role values that override the default</span>
          </p>
          {loadingOverrides
            ? <Spinner />
            : overrides.length === 0
            ? <p className="text-xs text-[#5F5E5A] italic">No overrides.</p>
            : (
              <div className="space-y-1">
                {overrides.map((ov) => (
                  <div key={ov.id} className="flex items-center gap-2 text-xs">
                    {ov.target_type === 'user' ? <User size={12} className="text-[#534AB7]" /> : <Users size={12} className="text-[#185FA5]" />}
                    <span className="font-mono text-[#1A2332]">{ov.target_id}</span>
                    <Badge variant={ov.value ? 'green' : 'gray'}>{ov.value ? 'on' : 'off'}</Badge>
                    <button
                      onClick={() => deleteOverride.mutate({ target_type: ov.target_type, target_id: ov.target_id })}
                      className="text-[#5F5E5A] hover:text-[#A32D2D]"
                      aria-label="Remove override"
                    >
                      <X size={11} />
                    </button>
                  </div>
                ))}
              </div>
            )}
        </div>
      )}
    </div>
  )
}

function FeatureFlagsPanel({ orgId }: { orgId: string }) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [newKey, setNewKey] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newVal, setNewVal] = useState(false)

  const { data: flags = [], isLoading } = useQuery<FeatureFlag[]>({
    queryKey: ['feature-flags', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/feature-flags`).then((r) => toArr<FeatureFlag>(r.data)),
    enabled: !!orgId,
  })

  const create = useMutation({
    mutationFn: (body: { key: string; description: string; value: boolean }) =>
      api.post(`/organizations/${orgId}/feature-flags`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['feature-flags', orgId] })
      toast.success('Feature flag created')
      setShowCreate(false)
      setNewKey(''); setNewDesc(''); setNewVal(false)
    },
    onError: () => toast.error('Failed to create flag'),
  })

  const toggleFlag = useMutation({
    mutationFn: (flag: FeatureFlag) =>
      api.post(`/organizations/${orgId}/feature-flags`, { key: flag.key, description: flag.description, value: !flag.value }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['feature-flags', orgId] }),
    onError: () => toast.error('Failed to update flag'),
  })

  const deleteFlag = useMutation({
    mutationFn: (key: string) =>
      api.delete(`/organizations/${orgId}/feature-flags/${key}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['feature-flags', orgId] })
      toast.success('Flag deleted')
    },
    onError: () => toast.error('Failed to delete flag'),
  })

  if (isLoading) return <Spinner />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-[#5F5E5A]">
          Flags are resolved at token issuance and injected as the <code className="bg-[#F5F4F0] px-1 rounded">flags</code> claim in every JWT.
        </p>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus size={14} /> New flag
        </Button>
      </div>

      {flags.length === 0 ? (
        <EmptyState
          icon={Flag}
          title="No feature flags"
          message="Create flags to control feature rollout per-user or per-role."
        />
      ) : (
        <div className="space-y-2">
          {flags.map((f) => (
            <FlagRow
              key={f.key}
              flag={f}
              orgId={orgId}
              onDelete={() => deleteFlag.mutate(f.key)}
              onToggle={() => toggleFlag.mutate(f)}
            />
          ))}
        </div>
      )}

      <Modal
        open={showCreate}
        title="New Feature Flag"
        description="Flags are boolean values resolved per-user at token issuance."
        onClose={() => setShowCreate(false)}
        size="sm"
      >
        <div className="space-y-4">
          <Input
            label="Key"
            placeholder="my_new_feature"
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
          />
          <Input
            label="Description (optional)"
            placeholder="Enables the new checkout flow"
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
          />
          <label className="flex items-center gap-3 text-sm">
            <span className="text-[#1A2332]">Default value</span>
            <button
              onClick={() => setNewVal((v) => !v)}
              className="transition-colors"
              aria-label="Toggle default value"
            >
              {newVal
                ? <ToggleRight size={22} className="text-[#0F6E56]" />
                : <ToggleLeft size={22} className="text-[#9E9E9B]" />}
            </button>
            <Badge variant={newVal ? 'green' : 'gray'}>{newVal ? 'on' : 'off'}</Badge>
          </label>
          <div className="flex gap-2 justify-end pt-2">
            <Button variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button
              loading={create.isPending}
              onClick={() => create.mutate({ key: newKey.trim(), description: newDesc.trim(), value: newVal })}
              disabled={!newKey.trim()}
            >
              Create
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

type Tab = 'email-policy' | 'feature-flags'

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: 'email-policy',   label: 'Email Policy',   icon: Mail  },
  { id: 'feature-flags',  label: 'Feature Flags',  icon: Flag  },
]

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SecurityCenterPage() {
  const { orgId } = useAuthStore()
  const { orgSlug } = useParams<{ orgSlug: string }>()
  const navigate = useNavigate()
  const [tab, setTab] = useState<Tab>('email-policy')

  if (!orgId) return null

  const base = `/admin/${orgSlug}`

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Center"
        subtitle="Manage email domain policy, feature flag rollout, and org-level security controls."
      />

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-[#E8E7E3]">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={[
              'inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px',
              tab === id
                ? 'border-[#0F6E56] text-[#0F6E56]'
                : 'border-transparent text-[#5F5E5A] hover:text-[#1A2332]',
            ].join(' ')}
          >
            <Icon size={15} />
            {label}
          </button>
        ))}
      </div>

      <Card>
        <div className="p-6">
          {tab === 'email-policy' && <EmailPolicyPanel orgId={orgId} />}
          {tab === 'feature-flags' && <FeatureFlagsPanel orgId={orgId} />}
        </div>
      </Card>

      {/* Quick links to related security pages */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
        {[
          { href: `${base}/shield-dashboard`,              icon: ShieldCheck, label: 'Threat Intelligence',  desc: 'Shield threat-intel signals'     },
          { href: `${base}/security/breached-passwords`,   icon: ShieldCheck, label: 'Breached Passwords',   desc: 'Haveibeenpwned breach detection'  },
          { href: `${base}/lockout-admin`,                 icon: ShieldCheck, label: 'Guard Unlock',         desc: 'Adaptive lockout management'     },
        ].map(({ href, icon: Icon, label, desc }) => (
          <a
            key={href}
            href={href}
            onClick={(e) => { e.preventDefault(); navigate(href) }}
            className="flex items-start gap-3 rounded-xl border border-[#E8E7E3] bg-white px-4 py-3 hover:border-[#0F6E56]/40 hover:bg-[#F0FAF6] transition-colors group"
          >
            <div className="mt-0.5 rounded-lg p-2 bg-[#E1F5EE] text-[#0F6E56]">
              <Icon size={16} />
            </div>
            <div>
              <p className="text-sm font-semibold text-[#1A2332] group-hover:text-[#0F6E56] transition-colors">{label}</p>
              <p className="text-xs text-[#5F5E5A]">{desc}</p>
            </div>
          </a>
        ))}
      </div>
    </div>
  )
}
